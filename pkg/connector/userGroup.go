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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type userGroupResourceType struct {
	resourceType *v2.ResourceType
	client       *jamf.Client
}

func (g *userGroupResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return g.resourceType
}

// userGroupResource creates a new connector resource for a Jamf user group.
func userGroupResource(group *jamf.UserGroup, parentResourceID *v2.ResourceId) (*v2.Resource, error) {
	profile := map[string]interface{}{
		"group_id":   group.ID,
		"group_name": group.Name,
	}

	ret, err := rs.NewGroupResource(
		group.Name,
		resourceTypeUserGroup,
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

func (g *userGroupResourceType) List(ctx context.Context, parentId *v2.ResourceId, attrs rs.SyncOpAttrs) ([]*v2.Resource, *rs.SyncOpResults, error) {
	userGroups, err := g.client.GetUserGroups(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("jamf-connector: failed to list user groups: %w", err)
	}

	var rv []*v2.Resource
	for _, userGroup := range userGroups {
		userGroupCopy := userGroup
		ur, err := userGroupResource(userGroupCopy, parentId)
		if err != nil {
			return nil, nil, err
		}
		rv = append(rv, ur)
	}

	return rv, nil, nil
}

func (g *userGroupResourceType) Entitlements(_ context.Context, resource *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	var rv []*v2.Entitlement

	assignmentOptions := []ent.EntitlementOption{
		ent.WithGrantableTo(resourceTypeUser),
		ent.WithDescription(fmt.Sprintf("Member of %s User Group in Jamf", resource.DisplayName)),
		ent.WithDisplayName(fmt.Sprintf("%s User Group %s", resource.DisplayName, memberEntitlement)),
	}

	en := ent.NewAssignmentEntitlement(resource, memberEntitlement, assignmentOptions...)
	rv = append(rv, en)

	return rv, nil, nil
}

func (g *userGroupResourceType) Grants(ctx context.Context, resource *v2.Resource, attrs rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	var rv []*v2.Grant

	userGroupId, err := strconv.Atoi(resource.Id.Resource)
	if err != nil {
		return nil, nil, err
	}

	group, err := g.client.GetUserGroupDetails(ctx, userGroupId)
	if err != nil {
		return nil, nil, err
	}

	for _, user := range group.Users {
		userCopy := user
		ur, err := userResource(&userCopy, resource.Id)
		if err != nil {
			return nil, nil, err
		}

		grant := grant.NewGrant(resource, memberEntitlement, ur.Id)
		rv = append(rv, grant)
	}

	return rv, nil, nil
}

// isUserGroupMember reports whether userID is in users, the membership list
// returned on a Jamf user group's details.
func isUserGroupMember(users []jamf.User, userID int) bool {
	return slices.ContainsFunc(users, func(u jamf.User) bool { return u.ID == userID })
}

// Grant adds principal (a Jamf user) to the static user group backing
// entitlement's resource. Smart groups are rejected — their membership is
// computed from criteria, not assignable.
func (g *userGroupResourceType) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) ([]*v2.Grant, annotations.Annotations, error) {
	ctx = jamf.WithFreshReads(ctx)

	groupID, userID, err := membershipIDs("grant user group member", resourceTypeUser, entitlement.Resource.Id, principal.Id)
	if err != nil {
		return nil, nil, err
	}

	group, err := g.client.GetUserGroupDetails(ctx, groupID)
	if err != nil {
		if jamf.IsNotFoundError(err) {
			return nil, nil, status.Errorf(codes.NotFound, "jamf-connector: grant user group member: group %d not found", groupID)
		}
		return nil, nil, fmt.Errorf("jamf-connector: grant user group member: %w", err)
	}
	if group.IsSmart {
		return nil, nil, status.Errorf(codes.FailedPrecondition, "jamf-connector: cannot grant membership on smart user group %d — membership is computed from criteria, not assignable", groupID)
	}
	if isUserGroupMember(group.Users, userID) {
		return nil, annotations.New(&v2.GrantAlreadyExists{}), nil
	}

	if err := g.client.AddUserGroupMembers(ctx, groupID, []int{userID}); err != nil {
		if jamf.IsNotFoundError(err) {
			return nil, nil, status.Errorf(codes.NotFound, "jamf-connector: grant user group member: group %d not found", groupID)
		}
		return nil, nil, membershipWriteError("grant user group member", "the user or group", err)
	}

	return []*v2.Grant{grant.NewGrant(entitlement.Resource, memberEntitlement, principal.Id)}, nil, nil
}

// Revoke removes gr's principal (a Jamf user) from the static user group
// backing gr's entitlement resource. Smart groups are rejected, same as
// Grant.
func (g *userGroupResourceType) Revoke(ctx context.Context, gr *v2.Grant) (annotations.Annotations, error) {
	ctx = jamf.WithFreshReads(ctx)

	groupID, userID, err := membershipIDs("revoke user group member", resourceTypeUser, gr.Entitlement.Resource.Id, gr.Principal.Id)
	if err != nil {
		return nil, err
	}

	group, err := g.client.GetUserGroupDetails(ctx, groupID)
	if err != nil {
		// A 404 here means the group itself has been deleted. A deleted
		// group trivially has no membership left to revoke.
		if jamf.IsNotFoundError(err) {
			return annotations.New(&v2.GrantAlreadyRevoked{}), nil
		}
		return nil, fmt.Errorf("jamf-connector: revoke user group member: %w", err)
	}
	if group.IsSmart {
		return nil, status.Errorf(codes.FailedPrecondition, "jamf-connector: cannot revoke membership on smart user group %d", groupID)
	}
	if !isUserGroupMember(group.Users, userID) {
		return annotations.New(&v2.GrantAlreadyRevoked{}), nil
	}

	if err := g.client.RemoveUserGroupMembers(ctx, groupID, []int{userID}); err != nil {
		// A 404 here means the group was deleted between the GET and this
		// PUT — same as the GET 404 case above.
		if jamf.IsNotFoundError(err) {
			return annotations.New(&v2.GrantAlreadyRevoked{}), nil
		}
		return nil, membershipWriteError("revoke user group member", "the user or group", err)
	}
	return nil, nil
}

func userGroupBuilder(client *jamf.Client) *userGroupResourceType {
	return &userGroupResourceType{
		resourceType: resourceTypeUserGroup,
		client:       client,
	}
}
