package connector

import (
	"context"
	"fmt"
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

// Create a new connector resource for a Jamf user group.
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

	assigmentOptions := []ent.EntitlementOption{
		ent.WithGrantableTo(resourceTypeUser),
		ent.WithDescription(fmt.Sprintf("Member of %s User Group in Jamf", resource.DisplayName)),
		ent.WithDisplayName(fmt.Sprintf("%s User Group %s", resource.DisplayName, memberEntitlement)),
	}

	en := ent.NewAssignmentEntitlement(resource, memberEntitlement, assigmentOptions...)
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

// isSmartUserGroup fetches current group details and reports is_smart. Always
// re-fetches rather than trusting a cached value from sync, because Grant/
// Revoke are called independently of any prior List() in the same
// process (CLI single-shot grant, or a sync that ran hours earlier).
func (g *userGroupResourceType) isSmartUserGroup(ctx context.Context, groupID int) (bool, error) {
	details, err := g.client.GetUserGroupDetails(ctx, groupID)
	if err != nil {
		return false, err
	}
	return details.IsSmart, nil
}

// Grant adds principal (a Jamf user) to the static user group backing
// entitlement's resource. Smart groups are rejected — their membership is
// computed from criteria, not assignable.
func (g *userGroupResourceType) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) ([]*v2.Grant, annotations.Annotations, error) {
	if principal.Id.ResourceType != resourceTypeUser.Id {
		return nil, nil, status.Errorf(codes.InvalidArgument, "jamf-connector: user group membership can only be granted to users, got resource type %q", principal.Id.ResourceType)
	}

	groupID, err := strconv.Atoi(entitlement.Resource.Id.Resource)
	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "jamf-connector: grant user group member: invalid group id %q: %s", entitlement.Resource.Id.Resource, err)
	}

	isSmart, err := g.isSmartUserGroup(ctx, groupID)
	if err != nil {
		return nil, nil, fmt.Errorf("jamf-connector: grant user group member: %w", err)
	}
	if isSmart {
		return nil, nil, status.Errorf(codes.FailedPrecondition, "jamf-connector: cannot grant membership on smart user group %d — membership is computed from criteria, not assignable", groupID)
	}

	userID, err := strconv.Atoi(principal.Id.Resource)
	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "jamf-connector: grant user group member: invalid user id %q: %s", principal.Id.Resource, err)
	}

	err = g.client.AddUserGroupMembers(ctx, groupID, []int{userID})
	if err != nil {
		// A 409 here isn't necessarily "already a member" — Jamf's Classic API
		// can also return 409 for other validation failures on the same
		// endpoint (e.g. an unknown user id in user_additions), and whether
		// Jamf maps "already a member" onto 409 at all is unverified against
		// a live tenant. Re-fetch the group and only report
		// GrantAlreadyExists if userID is actually present in its Users list;
		// otherwise surface the original error so a real failure isn't
		// misreported as success.
		if jamf.IsAlreadyExistsError(err) {
			group, detailsErr := g.client.GetUserGroupDetails(ctx, groupID)
			if detailsErr != nil {
				return nil, nil, fmt.Errorf("jamf-connector: grant user group member: 409 response, and failed to verify membership: %w", detailsErr)
			}
			for _, member := range group.Users {
				if member.ID == userID {
					return nil, annotations.New(&v2.GrantAlreadyExists{}), nil
				}
			}
			return nil, nil, fmt.Errorf("jamf-connector: grant user group member: %w", err)
		}
		return nil, nil, fmt.Errorf("jamf-connector: grant user group member: %w", err)
	}

	return []*v2.Grant{grant.NewGrant(entitlement.Resource, memberEntitlement, principal.Id)}, nil, nil
}

// Revoke removes gr's principal (a Jamf user) from the static user group
// backing gr's entitlement resource. Smart groups are rejected, same as Grant.
func (g *userGroupResourceType) Revoke(ctx context.Context, gr *v2.Grant) (annotations.Annotations, error) {
	if gr.Principal.Id.ResourceType != resourceTypeUser.Id {
		return nil, status.Errorf(codes.InvalidArgument, "jamf-connector: user group membership can only be revoked for users, got resource type %q", gr.Principal.Id.ResourceType)
	}

	groupID, err := strconv.Atoi(gr.Entitlement.Resource.Id.Resource)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "jamf-connector: revoke user group member: invalid group id %q: %s", gr.Entitlement.Resource.Id.Resource, err)
	}

	isSmart, err := g.isSmartUserGroup(ctx, groupID)
	if err != nil {
		// GetUserGroupDetails 404s when the group itself has been deleted. A
		// deleted group trivially has no membership left to revoke, so this
		// maps to GrantAlreadyRevoked rather than propagating as an error —
		// same reasoning as the RemoveUserGroupMembers 404 case below, just
		// detected earlier (via the GET here instead of the PUT).
		if jamf.IsNotFoundError(err) {
			return annotations.New(&v2.GrantAlreadyRevoked{}), nil
		}
		return nil, fmt.Errorf("jamf-connector: revoke user group member: %w", err)
	}
	if isSmart {
		return nil, status.Errorf(codes.FailedPrecondition, "jamf-connector: cannot revoke membership on smart user group %d", groupID)
	}

	userID, err := strconv.Atoi(gr.Principal.Id.Resource)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "jamf-connector: revoke user group member: invalid user id %q: %s", gr.Principal.Id.Resource, err)
	}

	err = g.client.RemoveUserGroupMembers(ctx, groupID, []int{userID})
	if err != nil {
		// Per RemoveUserGroupMembers's doc comment, a 404 here means the
		// group itself doesn't exist (not "user not a member") — most likely
		// it was deleted between the isSmartUserGroup GET above and this PUT.
		// Same reasoning as the isSmartUserGroup 404 case above: a
		// nonexistent group trivially has no membership left to revoke.
		if jamf.IsNotFoundError(err) {
			return annotations.New(&v2.GrantAlreadyRevoked{}), nil
		}
		return nil, fmt.Errorf("jamf-connector: revoke user group member: %w", err)
	}
	return nil, nil
}

func userGroupBuilder(client *jamf.Client) *userGroupResourceType {
	return &userGroupResourceType{
		resourceType: resourceTypeUserGroup,
		client:       client,
	}
}
