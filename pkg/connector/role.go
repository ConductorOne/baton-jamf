package connector

import (
	"context"
	"fmt"
	"slices"
	"strconv"

	"github.com/conductorone/baton-jamf/pkg/jamf"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	"github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/conductorone/baton-sdk/pkg/types/sessions"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type roleResourceType struct {
	resourceType     *v2.ResourceType
	client           *jamf.Client
	syncUserAccounts bool
}

var _ connectorbuilder.TypeScopedGrantsSyncer = (*roleResourceType)(nil)

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

	description := fmt.Sprintf("Individual privilege %q — only grantable while the principal's privilege set is %q", role, privilegeSetCustom)
	if slices.Contains(privilegeSets, role) {
		description = fmt.Sprintf(
			"Privilege set of %s — granting this overwrites the principal's current privilege set; revoking moves the principal to %q with only the %q privilege",
			role, privilegeSetCustom, privilegeReadLicenseInformation,
		)
	}

	ret, err := resource.NewRoleResource(
		role,
		resourceTypeRole,
		role,
		nil,
		resource.WithParentResourceID(parentResourceID),
		resource.WithResourceProfile(profile),
		resource.WithDescription(description),
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

	// Also stores the catalog the grants read, so Jamf is asked once per sync.
	privileges, err := privilegeCatalog(ctx, attrs.Session, o.client)
	if err != nil {
		return nil, nil, fmt.Errorf("jamf-connector: list privileges: %w", err)
	}

	for _, privilege := range privileges {
		rr, err := roleResource(ctx, privilege, parentId)
		if err != nil {
			return nil, nil, err
		}
		rv = append(rv, rr)
	}

	return rv, nil, nil
}

// Entitlements is unused: StaticEntitlements declares the member entitlement.
func (o *roleResourceType) Entitlements(_ context.Context, _ *v2.Resource, _ resource.SyncOpAttrs) ([]*v2.Entitlement, *resource.SyncOpResults, error) {
	return nil, nil, nil
}

// Grantable to both even where Jamf refuses the grant, so Grant answers with an actionable error.
func (o *roleResourceType) StaticEntitlements(_ context.Context, _ resource.SyncOpAttrs) ([]*v2.Entitlement, *resource.SyncOpResults, error) {
	return []*v2.Entitlement{
		ent.NewPermissionEntitlement(nil, memberEntitlement,
			ent.WithDisplayName("Member"),
			ent.WithGrantableTo(resourceTypeUserAccount, resourceTypeGroup),
		),
	}, nil, nil
}

// Grants is unused: GrantsForResourceType emits the accounts' role grants; the group Grants emits the groups'.
func (o *roleResourceType) Grants(_ context.Context, _ *v2.Resource, _ resource.SyncOpAttrs) ([]*v2.Grant, *resource.SyncOpResults, error) {
	return nil, nil, nil
}

// Phases of the type-scoped role grants.
const (
	rolePhasePrivilegeSets  = "privilegeSets"
	rolePhaseCustomAccounts = "customAccounts"
)

// customAccountsPageSize keeps a page of Custom accounts holding every privilege (~528 grants of ~270 bytes each)
// well under gRPC's 4 MiB response limit.
const customAccountsPageSize = 10

// GrantsForResourceType emits the accounts' role grants in two phases: each account's privilege set,
// then the individual privileges of the Custom accounts. Groups' role grants come from the group Grants.
func (o *roleResourceType) GrantsForResourceType(ctx context.Context, _ string, attrs resource.SyncOpAttrs) ([]*v2.Grant, *resource.SyncOpResults, error) {
	// Role grants only name accounts.
	if !o.syncUserAccounts {
		return nil, nil, nil
	}

	bag := &pagination.Bag{}
	if err := bag.Unmarshal(attrs.PageToken.Token); err != nil {
		return nil, nil, fmt.Errorf("jamf-connector: parse role grants page token: %w", err)
	}
	if bag.Current() == nil {
		bag.Push(pagination.PageState{ResourceTypeID: rolePhaseCustomAccounts})
		bag.Push(pagination.PageState{ResourceTypeID: rolePhasePrivilegeSets})
	}

	phase := bag.Current()
	var grants []*v2.Grant
	var nextPage string
	var err error
	switch phase.ResourceTypeID {
	case rolePhasePrivilegeSets:
		grants, nextPage, err = o.privilegeSetGrants(ctx, phase.Token)
	case rolePhaseCustomAccounts:
		grants, nextPage, err = o.customPrivilegeGrants(ctx, attrs.Session, phase.Token)
	default:
		err = fmt.Errorf("unknown phase %q", phase.ResourceTypeID)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("jamf-connector: list role grants (%s): %w", phase.ResourceTypeID, err)
	}

	nextToken, err := bag.NextToken(nextPage)
	if err != nil {
		return nil, nil, fmt.Errorf("jamf-connector: build role grants page token: %w", err)
	}
	return grants, &resource.SyncOpResults{NextPageToken: nextToken}, nil
}

// privilegeSetGrants grants each account on the page its privilege set: Administrator, Auditor or Enrollment Only.
func (o *roleResourceType) privilegeSetGrants(ctx context.Context, page string) ([]*v2.Grant, string, error) {
	accounts, nextPage, err := o.client.GetProAccounts(ctx, "", page, jamf.AccountsPageSize)
	if err != nil {
		return nil, "", err
	}

	var grants []*v2.Grant
	for _, account := range accounts {
		privilegeSet := account.UserAccount().PrivilegeSet
		if slices.Contains(privilegeSets, privilegeSet) {
			grants = append(grants, roleGrant(privilegeSet, account.ID))
		}
	}
	return grants, nextPage, nil
}

// customPrivilegeGrants grants each Custom account on the page the individual privileges it holds.
func (o *roleResourceType) customPrivilegeGrants(ctx context.Context, store sessions.SessionStore, page string) ([]*v2.Grant, string, error) {
	catalog, err := privilegeCatalog(ctx, store, o.client)
	if err != nil {
		return nil, "", err
	}
	accounts, nextPage, err := o.client.GetProAccounts(ctx, "privilegeLevel==CUSTOM", page, customAccountsPageSize)
	if err != nil {
		return nil, "", err
	}

	var grants []*v2.Grant
	for _, account := range accounts {
		// The accounts list has no privileges; only the account detail does.
		detail, err := o.client.GetUserAccountDetails(ctx, account.ID)
		if jamf.IsNotFoundError(err) {
			ctxzap.Extract(ctx).Debug("jamf-connector: account deleted since it was listed; skipping its privileges",
				zap.Int("account_id", account.ID))
			continue
		}
		if err != nil {
			return nil, "", err
		}
		for _, privilege := range customPrivileges(detail.PrivilegeSet, &detail.Privileges, catalog) {
			grants = append(grants, roleGrant(privilege, account.ID))
		}
	}
	return grants, nextPage, nil
}

// customPrivileges returns the catalog privileges held individually; only a Custom privilege set confers them.
func customPrivileges(privilegeSet string, privileges *jamf.Privileges, catalog []string) []string {
	if privilegeSet != privilegeSetCustom {
		return nil
	}
	var held []string
	for _, privilege := range dedupeStrings(privileges.All()) {
		if slices.Contains(catalog, privilege) {
			held = append(held, privilege)
		}
	}
	return held
}

// roleGrant is an account's member grant on a role.
func roleGrant(role string, accountID int) *v2.Grant {
	roleID := &v2.ResourceId{ResourceType: resourceTypeRole.Id, Resource: role}
	account := &v2.ResourceId{ResourceType: resourceTypeUserAccount.Id, Resource: strconv.Itoa(accountID)}
	return grant.NewGrant(&v2.Resource{Id: roleID}, memberEntitlement, account)
}

// rolePrincipal is the account or group whose role is being changed, as last
// read from Jamf.
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

func roleBuilder(client *jamf.Client, syncUserAccounts bool) *roleResourceType {
	return &roleResourceType{
		resourceType:     resourceTypeRole,
		client:           client,
		syncUserAccounts: syncUserAccounts,
	}
}
