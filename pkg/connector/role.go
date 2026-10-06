package connector

import (
	"context"
	"fmt"
	"slices"
	"strconv"

	"github.com/conductorone/baton-jamf/pkg/jamf"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	"github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type roleResourceType struct {
	resourceType *v2.ResourceType
	client       *jamf.Client
}

func (o *roleResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

// privilegeSets are the built-in sets; privilegeSetCustom is deliberately
// excluded — a Custom account's access is described by its individual
// privileges, not by "Custom" being a role someone holds.
var privilegeSets = []string{privilegeSetAdministrator, privilegeSetAuditor, privilegeSetEnrollmentOnly}

// privilegeReadLicenseInformation is the one privilege Jamf always keeps on
// every Custom privilege set and never lets a client remove — see Revoke's
// individual-privilege path.
const privilegeReadLicenseInformation = "Read License Information"

// Create a new connector resource for a Jamf role.
func roleResource(ctx context.Context, role string, parentResourceID *v2.ResourceId) (*v2.Resource, error) {
	profile := map[string]interface{}{
		"role_name": role,
		"role_id":   role,
	}

	ret, err := resource.NewRoleResource(
		role,
		resourceTypeRole,
		role,
		nil,
		resource.WithParentResourceID(parentResourceID),
		resource.WithResourceProfile(profile),
	)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func (o *roleResourceType) List(ctx context.Context, parentId *v2.ResourceId, attrs resource.SyncOpAttrs) ([]*v2.Resource, *resource.SyncOpResults, error) {
	var rv []*v2.Resource
	for _, privilegeSet := range privilegeSets {
		rr, err := roleResource(ctx, privilegeSet, parentId)
		if err != nil {
			return nil, nil, err
		}
		rv = append(rv, rr)
	}

	res, err := o.client.GetPrivileges(ctx)
	if err != nil {
		return nil, nil, err
	}

	for _, privilege := range res.Privileges {
		rr, err := roleResource(ctx, privilege, parentId)
		if err != nil {
			return nil, nil, err
		}
		rv = append(rv, rr)
	}

	return rv, nil, nil
}

// Entitlements declares every Role resource — the three built-in privilege
// sets and every individual privilege — as grantable to both userAccount and
// group principals. Grant/Revoke (below) are the source of truth for the
// actual rules (a privilege set is always grantable; an individual privilege
// is only meaningfully grantable while the principal's privilege_set is
// Custom) — this declaration is deliberately permissive so the platform can
// always attempt a grant and get back a precise, actionable error instead of
// never offering the option at all. Custom itself is not a Role resource —
// see List — so it is never declared grantable here either.
func (o *roleResourceType) Entitlements(_ context.Context, resource *v2.Resource, _ resource.SyncOpAttrs) ([]*v2.Entitlement, *resource.SyncOpResults, error) {
	description := fmt.Sprintf("Individual privilege %q — only grantable while the principal's privilege set is %q", resource.DisplayName, privilegeSetCustom)
	if slices.Contains(privilegeSets, resource.Id.Resource) {
		description = fmt.Sprintf(
			"Privilege set of %s — granting this overwrites the principal's current privilege set; revoking moves the principal to %q with only the %q privilege",
			resource.DisplayName, privilegeSetCustom, privilegeReadLicenseInformation,
		)
	}

	privilegesEn := ent.NewPermissionEntitlement(resource, memberEntitlement,
		ent.WithDisplayName(fmt.Sprintf("%s privilege set %s", resource.DisplayName, memberEntitlement)),
		ent.WithDescription(description),
		ent.WithGrantableTo(resourceTypeUserAccount, resourceTypeGroup),
	)

	return []*v2.Entitlement{privilegesEn}, nil, nil
}

// matchesIndividualPrivilege reports whether an account/group holding
// privilegeSet and privileges should be granted the given individual
// privilege role. Privileges is only meaningful for a Custom privilege_set
// (see jamf.AccountPrivilegesUpdateBody.Privileges) — a built-in set's
// Privileges data, if Jamf ever returns any, must not be treated as an
// access grant.
func matchesIndividualPrivilege(privilegeSet string, privileges *jamf.Privileges, privilege string) bool {
	return privilegeSet == privilegeSetCustom && privileges.Contains(privilege)
}

func (o *roleResourceType) Grants(ctx context.Context, resource *v2.Resource, attrs resource.SyncOpAttrs) ([]*v2.Grant, *resource.SyncOpResults, error) {
	var rv []*v2.Grant
	isCustomPrivilege := !slices.Contains(privilegeSets, resource.Id.Resource)
	userAccounts, groups, err := o.client.GetAccounts(ctx)
	if err != nil {
		return nil, nil, err
	}

	for _, group := range groups {
		groupCopy := group
		gr, err := groupResource(groupCopy, resource.Id)
		if err != nil {
			return nil, nil, err
		}

		if isCustomPrivilege && matchesIndividualPrivilege(group.PrivilegeSet, &group.Privileges, resource.Id.Resource) {
			privilegeGrant := grant.NewGrant(resource, memberEntitlement, gr.Id)
			rv = append(rv, privilegeGrant)
			continue
		}
		if group.PrivilegeSet == resource.Id.Resource {
			privilegeGrant := grant.NewGrant(resource, memberEntitlement, gr.Id)
			rv = append(rv, privilegeGrant)
		}
	}

	for _, userAccount := range userAccounts {
		userAccountCopy := userAccount
		gr, err := userAccountResource(userAccountCopy, resource.Id)
		if err != nil {
			return nil, nil, err
		}

		if isCustomPrivilege && matchesIndividualPrivilege(userAccount.PrivilegeSet, &userAccount.Privileges, resource.Id.Resource) {
			privilegeGrant := grant.NewGrant(resource, memberEntitlement, gr.Id)
			rv = append(rv, privilegeGrant)
			continue
		}
		if userAccount.PrivilegeSet == resource.Id.Resource {
			privilegeGrant := grant.NewGrant(resource, memberEntitlement, gr.Id)
			rv = append(rv, privilegeGrant)
		}
	}
	return rv, nil, nil
}

// roleOps abstracts the account/group-specific GET and minimal privilege-only
// PUT that Role Grant/Revoke otherwise share entirely. fetch always re-reads
// (ctx is wrapped with jamf.WithFreshReads by both Grant and Revoke), so a
// write immediately followed by another fetch observes the write.
type roleOps interface {
	// fetch returns the principal's current privilege_set, privileges, and
	// (for a userAccount; always "" for a group) access_level.
	fetch(ctx context.Context) (privilegeSet string, privileges jamf.Privileges, accessLevel string, err error)
	// write sends the minimal privilege-only PUT. A nil privileges omits the
	// <privileges> element entirely; a non-nil pointer — even to an
	// all-empty Privileges — forces an explicit element.
	write(ctx context.Context, privilegeSet string, privileges *jamf.Privileges) error
	// name is the principal's display name, populated by the most recent
	// fetch call.
	name() string
}

type userAccountRoleOps struct {
	client      *jamf.Client
	id          int
	accountName string
}

func (u *userAccountRoleOps) fetch(ctx context.Context) (string, jamf.Privileges, string, error) {
	account, err := u.client.GetUserAccountDetails(ctx, u.id)
	if err != nil {
		return "", jamf.Privileges{}, "", err
	}
	u.accountName = account.Name
	return account.PrivilegeSet, account.Privileges, account.AccessLevel, nil
}

func (u *userAccountRoleOps) write(ctx context.Context, privilegeSet string, privileges *jamf.Privileges) error {
	return u.client.UpdateAccountPrivileges(ctx, u.id, u.accountName, privilegeSet, privileges)
}

func (u *userAccountRoleOps) name() string { return u.accountName }

type groupRoleOps struct {
	client    *jamf.Client
	id        int
	groupName string
}

func (g *groupRoleOps) fetch(ctx context.Context) (string, jamf.Privileges, string, error) {
	group, err := g.client.GetGroupDetails(ctx, g.id)
	if err != nil {
		return "", jamf.Privileges{}, "", err
	}
	g.groupName = group.Name
	return group.PrivilegeSet, group.Privileges, "", nil
}

func (g *groupRoleOps) write(ctx context.Context, privilegeSet string, privileges *jamf.Privileges) error {
	return g.client.UpdateGroupPrivileges(ctx, g.id, g.groupName, privilegeSet, privileges)
}

func (g *groupRoleOps) name() string { return g.groupName }

// roleOpsFor builds the account/group-specific roleOps for resourceID,
// rejecting any other principal/entitlement resource type with
// InvalidArgument — shared by Grant and Revoke.
func (o *roleResourceType) roleOpsFor(resourceID *v2.ResourceId) (roleOps, error) {
	switch resourceID.ResourceType {
	case resourceTypeUserAccount.Id:
		id, err := strconv.Atoi(resourceID.Resource)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "jamf-connector: invalid user account id %q: %s", resourceID.Resource, err)
		}
		return &userAccountRoleOps{client: o.client, id: id}, nil
	case resourceTypeGroup.Id:
		id, err := strconv.Atoi(resourceID.Resource)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "jamf-connector: invalid group id %q: %s", resourceID.Resource, err)
		}
		return &groupRoleOps{client: o.client, id: id}, nil
	default:
		return nil, status.Errorf(codes.InvalidArgument, "jamf-connector: role can only be granted/revoked for a user account or group, got resource type %q", resourceID.ResourceType)
	}
}

// Grant sets principal (a userAccount or group) to hold the Role resource
// backing entitlement — either one of the three built-in privilege sets
// (Administrator, Auditor, Enrollment Only) or an individual privilege. See
// grantPrivilegeSet and grantIndividualPrivilege for the respective rules.
func (o *roleResourceType) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) ([]*v2.Grant, annotations.Annotations, error) {
	ctx = jamf.WithFreshReads(ctx)

	ops, err := o.roleOpsFor(principal.Id)
	if err != nil {
		return nil, nil, err
	}

	currentPrivilegeSet, currentPrivileges, accessLevel, err := ops.fetch(ctx)
	if err != nil {
		if jamf.IsNotFoundError(err) {
			return nil, nil, status.Errorf(codes.NotFound, "jamf-connector: grant role: %s %q not found", principal.Id.ResourceType, principal.Id.Resource)
		}
		return nil, nil, fmt.Errorf("jamf-connector: grant role: %w", err)
	}

	if principal.Id.ResourceType == resourceTypeUserAccount.Id && accessLevel == accessLevelGroupAccess {
		return nil, nil, status.Errorf(codes.FailedPrecondition,
			"jamf-connector: account %q has Group Access, so its rights come from its groups; assign the role to the group instead.", ops.name())
	}

	newGrant := grant.NewGrant(entitlement.Resource, memberEntitlement, principal.Id)
	target := entitlement.Resource.Id.Resource

	if slices.Contains(privilegeSets, target) {
		return o.grantPrivilegeSet(ctx, ops, currentPrivilegeSet, target, principal, entitlement, newGrant)
	}
	return o.grantIndividualPrivilege(ctx, ops, currentPrivilegeSet, currentPrivileges, target, newGrant)
}

// grantPrivilegeSet handles Grant of a built-in privilege set. Single-valued
// and never gated on the principal's current privilege_set: granting
// displaces whatever privilege_set (including Custom) the principal
// previously held.
func (o *roleResourceType) grantPrivilegeSet(
	ctx context.Context,
	ops roleOps,
	currentPrivilegeSet, target string,
	principal *v2.Resource,
	entitlement *v2.Entitlement,
	newGrant *v2.Grant,
) ([]*v2.Grant, annotations.Annotations, error) {
	if currentPrivilegeSet == target {
		// Already holds this exact privilege set — nothing would be
		// displaced, and re-sending the same PUT would only churn Jamf's
		// audit log.
		return []*v2.Grant{newGrant}, annotations.New(&v2.GrantAlreadyExists{}), nil
	}

	if currentPrivilegeSet == privilegeSetCustom {
		ctxzap.Extract(ctx).Debug("jamf-connector: grant role: displacing a Custom privilege set discards its individual privileges",
			zap.String("principal", ops.name()))
	}

	if err := ops.write(ctx, target, nil); err != nil {
		return nil, nil, fmt.Errorf("jamf-connector: grant role: %w", err)
	}

	newPrivilegeSet, _, _, err := ops.fetch(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("jamf-connector: grant role: verify: %w", err)
	}
	if newPrivilegeSet != target {
		return nil, nil, status.Errorf(codes.FailedPrecondition, "jamf-connector: Jamf did not apply privilege set %q to %q", target, ops.name())
	}

	annos, err := o.replacedPrivilegeSetAnnotation(ctx, currentPrivilegeSet, target, principal, entitlement)
	if err != nil {
		return nil, nil, fmt.Errorf("jamf-connector: grant role: %w", err)
	}
	return []*v2.Grant{newGrant}, annos, nil
}

// grantIndividualPrivilege handles Grant of a single named privilege. Only
// allowed while the principal's privilege_set is already Custom: Grant never
// transitions a principal into Custom on the caller's behalf, since arriving
// at Custom that way would (per Jamf's own escalation trap — see
// jamf.AccountPrivilegesUpdateBody) copy the principal's previous set's
// entire expanded privilege list rather than starting from nothing. The
// intended flow is: Revoke the current privilege set first (which moves the
// principal to Custom with an explicit empty block — see revokePrivilegeSet),
// then Grant individual privileges.
func (o *roleResourceType) grantIndividualPrivilege(
	ctx context.Context,
	ops roleOps,
	currentPrivilegeSet string,
	currentPrivileges jamf.Privileges,
	target string,
	newGrant *v2.Grant,
) ([]*v2.Grant, annotations.Annotations, error) {
	if currentPrivilegeSet != privilegeSetCustom {
		return nil, nil, status.Errorf(codes.FailedPrecondition,
			"jamf-connector: %q does not have a Custom privilege set, so individual privileges cannot be granted; "+
				"revoke its current privilege set first (this moves it to Custom) and then grant the privileges.", ops.name())
	}

	if currentPrivileges.Contains(target) {
		return []*v2.Grant{newGrant}, annotations.New(&v2.GrantAlreadyExists{}), nil
	}

	updated := addPrivilege(currentPrivileges, target)
	if err := ops.write(ctx, privilegeSetCustom, &updated); err != nil {
		return nil, nil, fmt.Errorf("jamf-connector: grant role: %w", err)
	}

	_, verifyPrivileges, _, err := ops.fetch(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("jamf-connector: grant role: verify: %w", err)
	}
	if !verifyPrivileges.Contains(target) {
		// Jamf silently drops privilege names it doesn't recognize (201,
		// same as a successful write), so the PUT response alone can't be
		// trusted.
		return nil, nil, status.Errorf(codes.FailedPrecondition, "jamf-connector: Jamf did not apply privilege %q to %q", target, ops.name())
	}

	return []*v2.Grant{newGrant}, nil, nil
}

// addPrivilege returns a deduped copy of current with target added under the
// JSSObjects category — Jamf files every privilege name under its correct
// category regardless of which category element it was sent under, so where
// a newly granted privilege is placed in the request body doesn't affect
// which category it ends up stored in.
func addPrivilege(current jamf.Privileges, target string) jamf.Privileges {
	updated := dedupePrivileges(current)
	if !slices.Contains(updated.JSSObjects, target) {
		updated.JSSObjects = append(updated.JSSObjects, target)
	}
	return updated
}

// removePrivilege returns a deduped copy of current with target removed from
// whichever category(ies) it appears in.
func removePrivilege(current jamf.Privileges, target string) jamf.Privileges {
	updated := dedupePrivileges(current)
	updated.JSSObjects = removeString(updated.JSSObjects, target)
	updated.JSSSettings = removeString(updated.JSSSettings, target)
	updated.JSSActions = removeString(updated.JSSActions, target)
	updated.Recon = removeString(updated.Recon, target)
	updated.CasperAdmin = removeString(updated.CasperAdmin, target)
	updated.CasperRemote = removeString(updated.CasperRemote, target)
	updated.CasperImaging = removeString(updated.CasperImaging, target)
	return updated
}

// dedupePrivileges returns a copy of p with each category's duplicate
// entries removed — Jamf's GET response can contain duplicates within a
// category, and re-sending them verbatim would only grow the list on every
// write.
func dedupePrivileges(p jamf.Privileges) jamf.Privileges {
	return jamf.Privileges{
		JSSObjects:    dedupeStrings(p.JSSObjects),
		JSSSettings:   dedupeStrings(p.JSSSettings),
		JSSActions:    dedupeStrings(p.JSSActions),
		Recon:         dedupeStrings(p.Recon),
		CasperAdmin:   dedupeStrings(p.CasperAdmin),
		CasperRemote:  dedupeStrings(p.CasperRemote),
		CasperImaging: dedupeStrings(p.CasperImaging),
	}
}

func dedupeStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func removeString(in []string, target string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == target {
			continue
		}
		out = append(out, s)
	}
	return out
}

// replacedPrivilegeSetAnnotation reports a GrantReplaced annotation naming the
// grant that Grant's write just displaced. previousPrivilegeSet is the
// principal's privilege_set as read BEFORE the write. There is nothing to
// report — and the annotation is skipped — when previousPrivilegeSet is
// empty/unset, Custom (individual privileges have no single Role-resource
// grant to name as displaced; grantPrivilegeSet logs that case separately),
// or already the target set (nothing was displaced).
func (o *roleResourceType) replacedPrivilegeSetAnnotation(
	ctx context.Context,
	previousPrivilegeSet, targetPrivilegeSet string,
	principal *v2.Resource,
	entitlement *v2.Entitlement,
) (annotations.Annotations, error) {
	if previousPrivilegeSet == targetPrivilegeSet || !slices.Contains(privilegeSets, previousPrivilegeSet) {
		return nil, nil
	}

	oldRoleResource, err := roleResource(ctx, previousPrivilegeSet, entitlement.Resource.ParentResourceId)
	if err != nil {
		return nil, fmt.Errorf("build previous privilege set resource: %w", err)
	}
	oldEntitlement := ent.NewPermissionEntitlement(oldRoleResource, memberEntitlement)
	replacedGrantID := grant.NewGrantID(principal.Id, oldEntitlement)

	return annotations.New(&v2.GrantReplaced{ReplacedGrantId: replacedGrantID}), nil
}

// Revoke revokes gr's Role grant (either a built-in privilege set or an
// individual privilege) from gr's principal (a userAccount or group). See
// revokePrivilegeSet and revokeIndividualPrivilege for the respective rules.
// If the account/group backing the grant has itself been deleted,
// GetUserAccountDetails/GetGroupDetails 404s, which is mapped to
// GrantAlreadyRevoked — a deleted principal trivially has nothing left to
// revoke.
func (o *roleResourceType) Revoke(ctx context.Context, gr *v2.Grant) (annotations.Annotations, error) {
	ctx = jamf.WithFreshReads(ctx)

	ops, err := o.roleOpsFor(gr.Principal.Id)
	if err != nil {
		return nil, err
	}

	currentPrivilegeSet, currentPrivileges, accessLevel, err := ops.fetch(ctx)
	if err != nil {
		if jamf.IsNotFoundError(err) {
			return annotations.New(&v2.GrantAlreadyRevoked{}), nil
		}
		return nil, fmt.Errorf("jamf-connector: revoke role: %w", err)
	}

	if gr.Principal.Id.ResourceType == resourceTypeUserAccount.Id && accessLevel == accessLevelGroupAccess {
		return nil, status.Errorf(codes.FailedPrecondition,
			"jamf-connector: account %q has Group Access, so its rights come from its groups; assign the role to the group instead.", ops.name())
	}

	target := gr.Entitlement.Resource.Id.Resource
	if slices.Contains(privilegeSets, target) {
		return o.revokePrivilegeSet(ctx, ops, currentPrivilegeSet, target)
	}
	return o.revokeIndividualPrivilege(ctx, ops, currentPrivilegeSet, currentPrivileges, target)
}

// revokePrivilegeSet handles Revoke of a built-in privilege set. There is no
// neutral/no-access privilege_set in Jamf's enum, so revoking a set moves the
// principal to Custom with an explicit empty <privileges> block — the lowest
// access Jamf allows (it always re-adds "Read License Information" and never
// lets a client remove it). Revoke only does this if the principal STILL
// holds the specific set gr's entitlement names: a Grant for a different set
// may have displaced this grant's privilege_set already (see Grant's
// GrantReplaced annotation), and downgrading here would then wipe out
// whatever the principal currently, legitimately holds.
func (o *roleResourceType) revokePrivilegeSet(ctx context.Context, ops roleOps, currentPrivilegeSet, target string) (annotations.Annotations, error) {
	if currentPrivilegeSet != target {
		return annotations.New(&v2.GrantAlreadyRevoked{}), nil
	}

	empty := jamf.Privileges{}
	if err := ops.write(ctx, privilegeSetCustom, &empty); err != nil {
		return nil, fmt.Errorf("jamf-connector: revoke role: %w", err)
	}

	newPrivilegeSet, _, _, err := ops.fetch(ctx)
	if err != nil {
		return nil, fmt.Errorf("jamf-connector: revoke role: verify: %w", err)
	}
	if newPrivilegeSet != privilegeSetCustom {
		return nil, status.Errorf(codes.FailedPrecondition, "jamf-connector: Jamf did not move %q to %q", ops.name(), privilegeSetCustom)
	}

	return nil, nil
}

// revokeIndividualPrivilege handles Revoke of a single named privilege.
// "Read License Information" is rejected outright — Jamf requires it on
// every Custom privilege set and silently keeps it even if asked to remove
// it, so reporting success here would be a lie.
func (o *roleResourceType) revokeIndividualPrivilege(ctx context.Context, ops roleOps, currentPrivilegeSet string, currentPrivileges jamf.Privileges, target string) (annotations.Annotations, error) {
	if currentPrivilegeSet != privilegeSetCustom || !currentPrivileges.Contains(target) {
		return annotations.New(&v2.GrantAlreadyRevoked{}), nil
	}

	if target == privilegeReadLicenseInformation {
		return nil, status.Errorf(codes.FailedPrecondition, "jamf-connector: cannot revoke privilege %q from %q: Jamf requires it on every Custom privilege set", target, ops.name())
	}

	updated := removePrivilege(currentPrivileges, target)
	if err := ops.write(ctx, privilegeSetCustom, &updated); err != nil {
		return nil, fmt.Errorf("jamf-connector: revoke role: %w", err)
	}

	_, verifyPrivileges, _, err := ops.fetch(ctx)
	if err != nil {
		return nil, fmt.Errorf("jamf-connector: revoke role: verify: %w", err)
	}
	if verifyPrivileges.Contains(target) {
		return nil, status.Errorf(codes.FailedPrecondition, "jamf-connector: Jamf did not remove privilege %q from %q", target, ops.name())
	}

	return nil, nil
}

func roleBuilder(client *jamf.Client) *roleResourceType {
	return &roleResourceType{
		resourceType: resourceTypeRole,
		client:       client,
	}
}
