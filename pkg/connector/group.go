package connector

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/conductorone/baton-jamf/pkg/jamf"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const memberEntitlement = "member"

type groupResourceType struct {
	resourceType *v2.ResourceType
	client       *jamf.Client
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
	_, groups, err := g.client.GetAccounts(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("jamf-connector: failed to list accounts: %w", err)
	}

	var rv []*v2.Resource
	for _, group := range groups {
		groupCopy := group
		gr, err := groupResource(groupCopy, parentId)
		if err != nil {
			return nil, nil, err
		}
		rv = append(rv, gr)
	}
	return rv, nil, nil
}

func (g *groupResourceType) Entitlements(_ context.Context, resource *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	var rv []*v2.Entitlement

	assignmentOptions := []ent.EntitlementOption{
		ent.WithGrantableTo(resourceTypeUserAccount),
		ent.WithDescription(fmt.Sprintf("Member of %s Group", resource.DisplayName)),
		ent.WithDisplayName(fmt.Sprintf("%s Group %s", resource.DisplayName, memberEntitlement)),
	}

	en := ent.NewAssignmentEntitlement(resource, memberEntitlement, assignmentOptions...)
	rv = append(rv, en)

	return rv, nil, nil
}

func (g *groupResourceType) Grants(ctx context.Context, resource *v2.Resource, attrs rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	var rv []*v2.Grant

	groupId, err := strconv.Atoi(resource.Id.Resource)
	if err != nil {
		return nil, nil, err
	}

	// HACK: the endpoint to get group details returns a members list, but it comes back empty
	// sometimes when it shouldn't. This is a bug in the Jamf API.
	// This is a workaround to get the members list as of 22/05/2025 and is not 100% reliable.
	// but from what's i've seen, it will return the members list after 2-3 tries. (if there are
	// any members at all in that group)
	// https://developer.jamf.com/jamf-pro/reference/findgroupsbyid
	// if this endpoint becomes reliable again, we can remove this for loop
	var group *jamf.Group
	count := 0
	for count < 5 {
		group, err = g.client.GetGroupDetails(ctx, groupId)
		if err != nil {
			return nil, nil, err
		}
		if len(group.Members) > 0 {
			break
		}
		count++
		time.Sleep(time.Second)
	}

	for _, user := range group.Members {
		userAccountDetails, err := g.client.GetUserAccountDetails(ctx, user.ID)
		if err != nil {
			return nil, nil, err
		}
		ur, err := userAccountResource(userAccountDetails, resource.Id)
		if err != nil {
			return nil, nil, err
		}

		grant := grant.NewGrant(resource, memberEntitlement, ur.Id)
		rv = append(rv, grant)
	}

	return rv, nil, nil
}

// Grant adds principal (a Jamf admin account) to the static admin account
// group backing entitlement's resource.
//
// An empty members read is treated as ambiguous and the write is aborted
// outright (see below) rather than assumed to mean the group is genuinely
// empty: an empty read for a populated group could not be reproduced during
// testing, but it cannot be ruled out, and writing back an empty list would
// silently wipe the group's real membership if it ever occurs. ctx is
// wrapped with jamf.WithFreshReads at the top of this method, so every GET
// below bypasses the HTTP cache.
func (g *groupResourceType) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) ([]*v2.Grant, annotations.Annotations, error) {
	ctx = jamf.WithFreshReads(ctx)

	if err := requirePrincipalType(principal.Id.ResourceType, resourceTypeUserAccount, "group membership", "granted to user accounts"); err != nil {
		return nil, nil, err
	}

	groupID, err := parseResourceID("jamf-connector: grant group member: invalid group id", entitlement.Resource.Id.Resource)
	if err != nil {
		return nil, nil, err
	}
	userID, err := parseResourceID("jamf-connector: grant group member: invalid user account id", principal.Id.Resource)
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

	if containsID(current.Members, userID, func(m jamf.BaseType) int { return m.ID }) {
		return nil, annotations.New(&v2.GrantAlreadyExists{}), nil
	}

	// Membership only grants anything to a Group Access account — a Full or
	// Site Access account's rights come from its own privilege_set, so
	// adding it to a group would silently do nothing. Fetched fresh (ctx is
	// wrapped with jamf.WithFreshReads above), right before the write, so
	// this reflects the account's current access level rather than a cached
	// one.
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

	if err := requirePrincipalType(gr.Principal.Id.ResourceType, resourceTypeUserAccount, "group membership", "revoked for user accounts"); err != nil {
		return nil, err
	}

	groupID, err := parseResourceID("jamf-connector: revoke group member: invalid group id", gr.Entitlement.Resource.Id.Resource)
	if err != nil {
		return nil, err
	}
	userID, err := parseResourceID("jamf-connector: revoke group member: invalid user account id", gr.Principal.Id.Resource)
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

func groupBuilder(client *jamf.Client) *groupResourceType {
	return &groupResourceType{
		resourceType: resourceTypeGroup,
		client:       client,
	}
}
