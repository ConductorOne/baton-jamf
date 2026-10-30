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
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/conductorone/baton-sdk/pkg/types/sessions"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const memberEntitlement = "member"

type groupResourceType struct {
	resourceType *v2.ResourceType
	client       *jamf.Client
	syncRoles    bool
	syncSites    bool
}

func (g *groupResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return g.resourceType
}

// groupResource creates a new connector resource for a Jamf group.
func groupResource(group *jamf.Group, parentResourceID *v2.ResourceId) (*v2.Resource, error) {
	profile := map[string]interface{}{
		"group_id":   group.ID,
		"group_name": group.Name,
	}

	ret, err := rs.NewGroupResource(
		group.Name,
		resourceTypeGroup,
		group.ID,
		nil,
		rs.WithParentResourceID(parentResourceID),
		rs.WithResourceProfile(profile),
	)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func (g *groupResourceType) List(ctx context.Context, parentId *v2.ResourceId, attrs rs.SyncOpAttrs) ([]*v2.Resource, *rs.SyncOpResults, error) {
	accounts, err := g.client.GetBaseAccounts(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("jamf-connector: failed to list accounts: %w", err)
	}

	var rv []*v2.Resource
	for _, group := range accounts.Groups {
		resource, err := groupResource(&group, parentId)
		if err != nil {
			return nil, nil, err
		}
		rv = append(rv, resource)
	}
	return rv, nil, nil
}

// Entitlements is unused: StaticEntitlements declares the member entitlement.
func (g *groupResourceType) Entitlements(_ context.Context, _ *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	return nil, nil, nil
}

func (g *groupResourceType) StaticEntitlements(_ context.Context, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	return []*v2.Entitlement{
		ent.NewAssignmentEntitlement(nil, memberEntitlement,
			ent.WithDisplayName("Member"),
			ent.WithDescription("Member of the Jamf account group"),
			ent.WithGrantableTo(resourceTypeUserAccount),
		),
	}, nil, nil
}

// Grants emits the group's members, the roles it holds and its site, paged by grant ID.
func (g *groupResourceType) Grants(ctx context.Context, resource *v2.Resource, attrs rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	groupId, err := strconv.Atoi(resource.Id.Resource)
	if err != nil {
		return nil, nil, fmt.Errorf("jamf-connector: invalid group id %q: %w", resource.Id.Resource, err)
	}

	grants, err := g.groupGrants(ctx, attrs.Session, resource, groupId)
	if err != nil {
		return nil, nil, fmt.Errorf("jamf-connector: list group %d grants: %w", groupId, err)
	}

	page, nextCursor, err := pageGrants(grants, attrs.PageToken.Token)
	if err != nil {
		return nil, nil, err
	}
	return page, &rs.SyncOpResults{NextPageToken: nextCursor}, nil
}

// groupGrants lists the grants of one group: its members, then the roles and the site it holds.
func (g *groupResourceType) groupGrants(ctx context.Context, store sessions.SessionStore, resource *v2.Resource, groupId int) ([]*v2.Grant, error) {
	group, err := g.client.GetGroupDetails(ctx, groupId)
	if err != nil {
		return nil, err
	}

	grants := make([]*v2.Grant, 0, len(group.Members))
	for _, member := range group.Members {
		account := &v2.ResourceId{ResourceType: resourceTypeUserAccount.Id, Resource: strconv.Itoa(member.ID)}
		grants = append(grants, grant.NewGrant(resource, memberEntitlement, account))
	}

	if g.syncRoles {
		roles, err := g.heldRoles(ctx, store, group)
		if err != nil {
			return nil, err
		}
		for _, role := range roles {
			roleID := &v2.ResourceId{ResourceType: resourceTypeRole.Id, Resource: role}
			grants = append(grants, grant.NewGrant(&v2.Resource{Id: roleID}, memberEntitlement, resource.Id))
		}
	}

	// Jamf reports a site id of -1 for none.
	if g.syncSites && group.Site.ID > 0 {
		siteID := &v2.ResourceId{ResourceType: resourceTypeSite.Id, Resource: strconv.Itoa(group.Site.ID)}
		grants = append(grants, grant.NewGrant(&v2.Resource{Id: siteID}, memberEntitlement, resource.Id))
	}
	return grants, nil
}

// heldRoles returns the roles a group holds: its privilege set, or the individual privileges of a Custom group.
func (g *groupResourceType) heldRoles(ctx context.Context, store sessions.SessionStore, group *jamf.Group) ([]string, error) {
	if slices.Contains(privilegeSets, group.PrivilegeSet) {
		return []string{group.PrivilegeSet}, nil
	}
	if group.PrivilegeSet != privilegeSetCustom {
		return nil, nil
	}

	catalog, err := privilegeCatalog(ctx, store, g.client)
	if err != nil {
		return nil, err
	}
	return customPrivileges(group.PrivilegeSet, &group.Privileges, catalog), nil
}

// Grant adds principal (a Jamf admin account) to the static admin account
// group backing entitlement's resource.
//
// An empty members read is treated as ambiguous and the write is aborted
// outright (see below) rather than assumed to mean the group is genuinely
// empty: an empty read for a populated group could not be reproduced during
// testing, but it cannot be ruled out, and writing back an empty list would
// silently wipe the group's real membership if it ever occurs.
func (g *groupResourceType) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) ([]*v2.Grant, annotations.Annotations, error) {
	ctx = jamf.WithFreshReads(ctx)

	groupID, userID, err := membershipIDs("grant group member", resourceTypeUserAccount, entitlement.Resource.Id, principal.Id)
	if err != nil {
		return nil, nil, err
	}

	current, err := g.client.GetGroupDetails(ctx, groupID)
	if err != nil {
		if jamf.IsNotFoundError(err) {
			return nil, nil, status.Errorf(codes.NotFound, "jamf-connector: grant group member: group %d not found", groupID)
		}
		return nil, nil, fmt.Errorf("jamf-connector: grant group member: %w", err)
	}

	if len(current.Members) == 0 {
		ctxzap.Extract(ctx).Debug("jamf-connector: group returned no members on Grant; aborting without writing",
			zap.Int("group_id", groupID))
		return nil, nil, status.Errorf(codes.FailedPrecondition,
			"jamf-connector: Jamf did not return any members for group %q, so the change was not applied: "+
				"it is not possible to tell whether the group is really empty or Jamf returned an incomplete response", current.Name)
	}

	if slices.ContainsFunc(current.Members, func(m jamf.BaseType) bool { return m.ID == userID }) {
		return nil, annotations.New(&v2.GrantAlreadyExists{}), nil
	}

	// Membership only grants anything to a Group Access account — a Full or
	// Site Access account's rights come from its own privilege_set, so
	// adding it to a group would silently do nothing. Fetched fresh, right
	// before the write, so this reflects the account's current access level.
	account, err := g.client.GetUserAccountDetails(ctx, userID)
	if err != nil {
		if jamf.IsNotFoundError(err) {
			return nil, nil, status.Errorf(codes.NotFound, "jamf-connector: grant group member: account %d not found", userID)
		}
		return nil, nil, fmt.Errorf("jamf-connector: grant group member: %w", err)
	}
	if account.AccessLevel != accessLevelGroupAccess {
		return nil, nil, status.Errorf(codes.FailedPrecondition,
			"jamf-connector: account %q has Full or Site access, so belonging to a group grants it nothing; change its access to Group Access in Jamf first.", account.Name)
	}

	newMembers := append(append([]jamf.BaseType{}, current.Members...), jamf.BaseType{ID: userID})
	if err := g.client.UpdateGroupMembers(ctx, groupID, current.Name, newMembers); err != nil {
		return nil, nil, fmt.Errorf("jamf-connector: grant group member: %w", err)
	}

	return []*v2.Grant{grant.NewGrant(entitlement.Resource, memberEntitlement, principal.Id)}, nil, nil
}

// Revoke removes gr's principal (a Jamf admin account) from the static
// admin account group backing gr's entitlement resource. An empty members
// read is ambiguous in the same way as Grant (see above): rather than
// reporting a principal that may still be a member as revoked, this returns
// a retryable error so the platform retries instead of recording a false
// success.
func (g *groupResourceType) Revoke(ctx context.Context, gr *v2.Grant) (annotations.Annotations, error) {
	ctx = jamf.WithFreshReads(ctx)

	groupID, userID, err := membershipIDs("revoke group member", resourceTypeUserAccount, gr.Entitlement.Resource.Id, gr.Principal.Id)
	if err != nil {
		return nil, err
	}

	current, err := g.client.GetGroupDetails(ctx, groupID)
	if err != nil {
		if jamf.IsNotFoundError(err) {
			// The group has been deleted — a deleted group trivially has no
			// membership left to revoke.
			return annotations.New(&v2.GrantAlreadyRevoked{}), nil
		}
		return nil, fmt.Errorf("jamf-connector: revoke group member: %w", err)
	}

	if len(current.Members) == 0 {
		// Same ambiguity as Grant: an empty read could be a genuinely empty
		// group, or an unreproduced empty-members response. Reporting this as
		// already-revoked would let a still-present member silently keep its
		// access, so this never writes on this read and instead asks the
		// platform to retry.
		ctxzap.Extract(ctx).Debug("jamf-connector: group returned no members on Revoke; not revoking on an ambiguous read",
			zap.Int("group_id", groupID))
		return nil, status.Errorf(codes.Unavailable,
			"jamf-connector: Jamf returned no members for group %q; not revoking on an ambiguous read", current.Name)
	}

	remaining := make([]jamf.BaseType, 0, len(current.Members))
	found := false
	for _, member := range current.Members {
		if member.ID == userID {
			found = true
			continue
		}
		remaining = append(remaining, member)
	}
	if !found {
		return annotations.New(&v2.GrantAlreadyRevoked{}), nil
	}

	if err := g.client.UpdateGroupMembers(ctx, groupID, current.Name, remaining); err != nil {
		return nil, fmt.Errorf("jamf-connector: revoke group member: %w", err)
	}

	return nil, nil
}

func groupBuilder(client *jamf.Client, syncRoles, syncSites bool) *groupResourceType {
	return &groupResourceType{
		resourceType: resourceTypeGroup,
		client:       client,
		syncRoles:    syncRoles,
		syncSites:    syncSites,
	}
}
