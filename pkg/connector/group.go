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

// Create a new connector resource for a Jamf group.
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

	assigmentOptions := []ent.EntitlementOption{
		ent.WithGrantableTo(resourceTypeUserAccount),
		ent.WithDescription(fmt.Sprintf("Member of %s Group", resource.DisplayName)),
		ent.WithDisplayName(fmt.Sprintf("%s Group %s", resource.DisplayName, memberEntitlement)),
	}

	en := ent.NewAssignmentEntitlement(resource, memberEntitlement, assigmentOptions...)
	rv = append(rv, en)

	// TODO - access level entitlements & grants

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
// This deliberately uses GetGroupDetails, not GetGroupDetailsReliable's
// retry workaround: role.go's Grant/Revoke need that retry because they
// round-trip Members unmodified through a privilege_set-only PUT, where a
// falsely-empty read would silently wipe the group's membership. Here, an
// empty read is instead treated as ambiguous and the write is aborted
// outright (see below) — retrying first would just delay reaching the same
// safe decision, and a caller that wants the retry behavior can always call
// Grant again. ctx is wrapped with jamf.WithFreshReads at the top of this
// method, so every GET below — including the post-write verification read —
// bypasses the HTTP cache and observes the PUT it just issued, instead of
// replaying a cached pre-write response.
//
// After writing, this re-reads the group and confirms principal is
// actually a member: Jamf silently drops members it doesn't recognize
// (bad id) with the same 201 response as a successful write, so the PUT
// response alone cannot be trusted.
func (g *groupResourceType) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) ([]*v2.Grant, annotations.Annotations, error) {
	ctx = jamf.WithFreshReads(ctx)

	if principal.Id.ResourceType != resourceTypeUserAccount.Id {
		return nil, nil, status.Errorf(codes.InvalidArgument, "jamf-connector: group membership can only be granted to user accounts, got resource type %q", principal.Id.ResourceType)
	}

	groupID, err := strconv.Atoi(entitlement.Resource.Id.Resource)
	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "jamf-connector: grant group member: invalid group id %q: %s", entitlement.Resource.Id.Resource, err)
	}
	userID, err := strconv.Atoi(principal.Id.Resource)
	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "jamf-connector: grant group member: invalid user account id %q: %s", principal.Id.Resource, err)
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

	for _, member := range current.Members {
		if member.ID == userID {
			return nil, annotations.New(&v2.GrantAlreadyExists{}), nil
		}
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

	updated, err := g.client.GetGroupDetails(ctx, groupID)
	if err != nil {
		return nil, nil, fmt.Errorf("jamf-connector: grant group member: verify membership: %w", err)
	}
	for _, member := range updated.Members {
		if member.ID == userID {
			return []*v2.Grant{grant.NewGrant(entitlement.Resource, memberEntitlement, principal.Id)}, nil, nil
		}
	}

	return nil, nil, status.Errorf(codes.FailedPrecondition,
		"jamf-connector: Jamf did not apply membership for user account %d in group %d", userID, groupID)
}

// Revoke removes gr's principal (a Jamf admin account) from the static
// admin account group backing gr's entitlement resource. Unlike Grant, this
// does not re-read after writing to confirm the removal — there is no
// known silent-drop failure mode on the removal path the way there is for
// additions of unrecognized members.
func (g *groupResourceType) Revoke(ctx context.Context, gr *v2.Grant) (annotations.Annotations, error) {
	ctx = jamf.WithFreshReads(ctx)

	if gr.Principal.Id.ResourceType != resourceTypeUserAccount.Id {
		return nil, status.Errorf(codes.InvalidArgument, "jamf-connector: group membership can only be revoked for user accounts, got resource type %q", gr.Principal.Id.ResourceType)
	}

	groupID, err := strconv.Atoi(gr.Entitlement.Resource.Id.Resource)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "jamf-connector: revoke group member: invalid group id %q: %s", gr.Entitlement.Resource.Id.Resource, err)
	}
	userID, err := strconv.Atoi(gr.Principal.Id.Resource)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "jamf-connector: revoke group member: invalid user account id %q: %s", gr.Principal.Id.Resource, err)
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
		// group, or Jamf's known intermittent empty-members response. Either
		// way, the principal is not demonstrably a member, so there is
		// nothing to safely revoke — never write on this read.
		ctxzap.Extract(ctx).Debug("jamf-connector: group returned no members on Revoke; treating as already revoked",
			zap.Int("group_id", groupID))
		return annotations.New(&v2.GrantAlreadyRevoked{}), nil
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
