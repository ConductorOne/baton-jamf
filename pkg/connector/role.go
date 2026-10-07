package connector

import (
	"context"
	"fmt"
	"slices"

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

// roleResource creates a new connector resource for a Jamf role.
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

// rolePrincipal is the account or group whose role is being changed, as last
// read from Jamf. Both Grant and Revoke wrap ctx with jamf.WithFreshReads, so a
// write immediately followed by another getRolePrincipal observes the write.
type rolePrincipal struct {
	resourceType string // resourceTypeUserAccount.Id or resourceTypeGroup.Id
	id           int
	name         string
	privilegeSet string
	privileges   jamf.Privileges
	accessLevel  string // empty for groups
}

// rolePrincipalID parses rid's numeric id, rejecting any principal resource
// type other than userAccount/group with InvalidArgument — shared by
// getRolePrincipal.
func rolePrincipalID(rid *v2.ResourceId) (int, error) {
	switch rid.ResourceType {
	case resourceTypeUserAccount.Id:
		return parseResourceID(rid.Resource, "jamf-connector: invalid user account id")
	case resourceTypeGroup.Id:
		return parseResourceID(rid.Resource, "jamf-connector: invalid group id")
	default:
		return 0, status.Errorf(codes.InvalidArgument, "jamf-connector: role can only be granted/revoked for a user account or group, got resource type %q", rid.ResourceType)
	}
}

// requireDirectPrivileges reports a FailedPrecondition error unless p holds
// its own privilege_set directly — i.e. p is not a Group Access account,
// whose rights come from its groups instead. verb names the caller's
// corrective action (e.g. "assign the role to the group instead" for Grant).
func (p *rolePrincipal) requireDirectPrivileges(verb string) error {
	if p.resourceType == resourceTypeUserAccount.Id && p.accessLevel == accessLevelGroupAccess {
		return status.Errorf(codes.FailedPrecondition,
			"jamf-connector: account %q has Group Access, so its rights come from its groups; %s.", p.name, verb)
	}
	return nil
}

// getRolePrincipal reads the account/group backing rid. Client errors are
// returned unwrapped so callers can check jamf.IsNotFoundError.
func (o *roleResourceType) getRolePrincipal(ctx context.Context, rid *v2.ResourceId) (*rolePrincipal, error) {
	id, err := rolePrincipalID(rid)
	if err != nil {
		return nil, err
	}

	if rid.ResourceType == resourceTypeUserAccount.Id {
		account, err := o.client.GetUserAccountDetails(ctx, id)
		if err != nil {
			return nil, err
		}
		return &rolePrincipal{
			resourceType: rid.ResourceType,
			id:           id,
			name:         account.Name,
			privilegeSet: account.PrivilegeSet,
			privileges:   account.Privileges,
			accessLevel:  account.AccessLevel,
		}, nil
	}

	group, err := o.client.GetGroupDetails(ctx, id)
	if err != nil {
		return nil, err
	}
	return &rolePrincipal{
		resourceType: rid.ResourceType,
		id:           id,
		name:         group.Name,
		privilegeSet: group.PrivilegeSet,
		privileges:   group.Privileges,
	}, nil
}

// updateRolePrincipal sends the minimal privilege-only PUT for p. A nil
// privileges omits the <privileges> element entirely; a non-nil pointer — even
// to an all-empty Privileges — forces an explicit element.
func (o *roleResourceType) updateRolePrincipal(ctx context.Context, p *rolePrincipal, privilegeSet string, privileges *jamf.Privileges) error {
	if p.resourceType == resourceTypeUserAccount.Id {
		return o.client.UpdateAccountPrivileges(ctx, p.id, p.name, privilegeSet, privileges)
	}
	return o.client.UpdateGroupPrivileges(ctx, p.id, p.name, privilegeSet, privileges)
}

// Grant sets principal (a userAccount or group) to hold the Role resource
// backing entitlement — either one of the three built-in privilege sets
// (Administrator, Auditor, Enrollment Only) or an individual privilege. See
// grantPrivilegeSet and grantIndividualPrivilege for the respective rules.
func (o *roleResourceType) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) ([]*v2.Grant, annotations.Annotations, error) {
	ctx = jamf.WithFreshReads(ctx)

	p, err := o.getRolePrincipal(ctx, principal.Id)
	if err != nil {
		if status.Code(err) == codes.InvalidArgument {
			return nil, nil, err
		}
		if jamf.IsNotFoundError(err) {
			return nil, nil, status.Errorf(codes.NotFound, "jamf-connector: grant role: %s %q not found", principal.Id.ResourceType, principal.Id.Resource)
		}
		return nil, nil, fmt.Errorf("jamf-connector: grant role: %w", err)
	}

	if err := p.requireDirectPrivileges("assign the role to the group instead"); err != nil {
		return nil, nil, err
	}

	target := entitlement.Resource.Id.Resource

	if slices.Contains(privilegeSets, target) {
		return o.grantPrivilegeSet(ctx, p, target, principal.Id, entitlement)
	}
	return o.grantIndividualPrivilege(ctx, p, target, principal.Id, entitlement)
}

// grantPrivilegeSet handles Grant of a built-in privilege set. Single-valued
// and never gated on the principal's current privilege_set: granting
// displaces whatever privilege_set (including Custom) the principal
// previously held.
func (o *roleResourceType) grantPrivilegeSet(
	ctx context.Context,
	p *rolePrincipal,
	target string,
	principalID *v2.ResourceId,
	entitlement *v2.Entitlement,
) ([]*v2.Grant, annotations.Annotations, error) {
	if p.privilegeSet == target {
		// Already holds this exact privilege set — nothing would be
		// displaced, and re-sending the same PUT would only churn Jamf's
		// audit log.
		return nil, annotations.New(&v2.GrantAlreadyExists{}), nil
	}

	if p.privilegeSet == privilegeSetCustom {
		ctxzap.Extract(ctx).Debug("jamf-connector: grant role: displacing a Custom privilege set discards its individual privileges",
			zap.String("principal", p.name))
	}

	if err := o.updateRolePrincipal(ctx, p, target, nil); err != nil {
		return nil, nil, fmt.Errorf("jamf-connector: grant role: %w", err)
	}

	newGrant := grant.NewGrant(entitlement.Resource, memberEntitlement, principalID)
	annos := replacedPrivilegeSetAnnotation(ctx, p.privilegeSet, target, principalID, entitlement)
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
	p *rolePrincipal,
	target string,
	principalID *v2.ResourceId,
	entitlement *v2.Entitlement,
) ([]*v2.Grant, annotations.Annotations, error) {
	if p.privilegeSet != privilegeSetCustom {
		return nil, nil, status.Errorf(codes.FailedPrecondition,
			"jamf-connector: %q does not have a Custom privilege set, so individual privileges cannot be granted; "+
				"revoke its current privilege set first (this moves it to Custom) and then grant the privileges.", p.name)
	}

	if p.privileges.Contains(target) {
		return nil, annotations.New(&v2.GrantAlreadyExists{}), nil
	}

	updated := addPrivilege(p.privileges, target)
	if err := o.updateRolePrincipal(ctx, p, privilegeSetCustom, &updated); err != nil {
		return nil, nil, fmt.Errorf("jamf-connector: grant role: %w", err)
	}

	newGrant := grant.NewGrant(entitlement.Resource, memberEntitlement, principalID)
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
	return dedupePrivileges(current).Map(func(s []string) []string { return removeString(s, target) })
}

// dedupePrivileges returns a copy of p with each category's duplicate
// entries removed — Jamf's GET response can contain duplicates within a
// category, and re-sending them verbatim would only grow the list on every
// write.
func dedupePrivileges(p jamf.Privileges) jamf.Privileges {
	return p.Map(dedupeStrings)
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
	return slices.DeleteFunc(slices.Clone(in), func(s string) bool { return s == target })
}

// replacedPrivilegeSetAnnotation reports a GrantReplaced annotation naming the
// grant that Grant's write just displaced. previousPrivilegeSet is the
// principal's privilege_set as read BEFORE the write. Returns nil — and the
// annotation is skipped — when previousPrivilegeSet is empty/unset, Custom
// (individual privileges have no single Role-resource grant to name as
// displaced; grantPrivilegeSet logs that case separately), already the
// target set (nothing was displaced), or when building the previous
// resource fails: the write already succeeded by this point, so a failure
// here is logged at Debug rather than failing an otherwise-successful Grant.
func replacedPrivilegeSetAnnotation(
	ctx context.Context,
	previousPrivilegeSet, targetPrivilegeSet string,
	principalID *v2.ResourceId,
	entitlement *v2.Entitlement,
) annotations.Annotations {
	if previousPrivilegeSet == targetPrivilegeSet || !slices.Contains(privilegeSets, previousPrivilegeSet) {
		return nil
	}

	oldRoleResource, err := roleResource(ctx, previousPrivilegeSet, entitlement.Resource.ParentResourceId)
	if err != nil {
		ctxzap.Extract(ctx).Debug("jamf-connector: grant role: failed to build previous privilege set resource for GrantReplaced",
			zap.Error(err))
		return nil
	}
	oldEntitlement := ent.NewPermissionEntitlement(oldRoleResource, memberEntitlement)
	replacedGrantID := grant.NewGrantID(principalID, oldEntitlement)

	return annotations.New(&v2.GrantReplaced{ReplacedGrantId: replacedGrantID})
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

	p, err := o.getRolePrincipal(ctx, gr.Principal.Id)
	if err != nil {
		if status.Code(err) == codes.InvalidArgument {
			return nil, err
		}
		if jamf.IsNotFoundError(err) {
			return annotations.New(&v2.GrantAlreadyRevoked{}), nil
		}
		return nil, fmt.Errorf("jamf-connector: revoke role: %w", err)
	}

	if err := p.requireDirectPrivileges("revoke the role from the group instead"); err != nil {
		return nil, err
	}

	target := gr.Entitlement.Resource.Id.Resource
	if slices.Contains(privilegeSets, target) {
		return o.revokePrivilegeSet(ctx, p, target)
	}
	return o.revokeIndividualPrivilege(ctx, p, target)
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
func (o *roleResourceType) revokePrivilegeSet(ctx context.Context, p *rolePrincipal, target string) (annotations.Annotations, error) {
	if p.privilegeSet != target {
		return annotations.New(&v2.GrantAlreadyRevoked{}), nil
	}

	empty := jamf.Privileges{}
	if err := o.updateRolePrincipal(ctx, p, privilegeSetCustom, &empty); err != nil {
		return nil, fmt.Errorf("jamf-connector: revoke role: %w", err)
	}

	return nil, nil
}

// revokeIndividualPrivilege handles Revoke of a single named privilege.
// "Read License Information" is rejected outright — Jamf requires it on
// every Custom privilege set and silently keeps it even if asked to remove
// it, so reporting success here would be a lie.
func (o *roleResourceType) revokeIndividualPrivilege(ctx context.Context, p *rolePrincipal, target string) (annotations.Annotations, error) {
	if p.privilegeSet != privilegeSetCustom || !p.privileges.Contains(target) {
		return annotations.New(&v2.GrantAlreadyRevoked{}), nil
	}

	if target == privilegeReadLicenseInformation {
		return nil, status.Errorf(codes.FailedPrecondition, "jamf-connector: cannot revoke privilege %q from %q: Jamf requires it on every Custom privilege set", target, p.name)
	}

	updated := removePrivilege(p.privileges, target)
	if err := o.updateRolePrincipal(ctx, p, privilegeSetCustom, &updated); err != nil {
		return nil, fmt.Errorf("jamf-connector: revoke role: %w", err)
	}

	return nil, nil
}

func roleBuilder(client *jamf.Client) *roleResourceType {
	return &roleResourceType{
		resourceType: resourceTypeRole,
		client:       client,
	}
}
