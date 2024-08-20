package connector

import (
	"context"
	"fmt"
	"strconv"

	"github.com/conductorone/baton-jamf/pkg/jamf"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
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

	groupTraitOptions := []rs.GroupTraitOption{rs.WithGroupProfile(profile)}

	ret, err := rs.NewGroupResource(
		group.Name,
		resourceTypeUserGroup,
		group.ID,
		groupTraitOptions,
		rs.WithParentResourceID(parentResourceID),
	)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func (g *userGroupResourceType) List(ctx context.Context, parentId *v2.ResourceId, token *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	userGroups, err := g.client.GetUserGroups(ctx)
	if err != nil {
		return nil, "", nil, fmt.Errorf("jamf-connector: failed to list user groups: %w", err)
	}

	var rv []*v2.Resource
	for _, userGroup := range userGroups {
		userGroupCopy := userGroup
		ur, err := userGroupResource(userGroupCopy, parentId)
		if err != nil {
			return nil, "", nil, err
		}
		rv = append(rv, ur)
	}

	return rv, "", nil, nil
}

func (g *userGroupResourceType) Entitlements(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var rv []*v2.Entitlement

	assigmentOptions := []ent.EntitlementOption{
		ent.WithGrantableTo(resourceTypeUser),
		ent.WithDescription(fmt.Sprintf("Member of %s User Group in Jamf", resource.DisplayName)),
		ent.WithDisplayName(fmt.Sprintf("%s User Group %s", resource.DisplayName, memberEntitlement)),
	}

	en := ent.NewAssignmentEntitlement(resource, memberEntitlement, assigmentOptions...)
	rv = append(rv, en)

	return rv, "", nil, nil
}

func (g *userGroupResourceType) Grants(ctx context.Context, resource *v2.Resource, token *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	var rv []*v2.Grant

	userGroupId, err := strconv.Atoi(resource.Id.Resource)
	if err != nil {
		return nil, "", nil, err
	}

	group, err := g.client.GetUserGroupDetails(ctx, userGroupId)
	if err != nil {
		return nil, "", nil, err
	}

	for _, user := range group.Users {
		userCopy := user
		ur, err := userResource(&userCopy, resource.Id)
		if err != nil {
			return nil, "", nil, err
		}

		grant := grant.NewGrant(resource, memberEntitlement, ur.Id)
		rv = append(rv, grant)
	}

	return rv, "", nil, nil
}

func userGroupBuilder(client *jamf.Client) *userGroupResourceType {
	return &userGroupResourceType{
		resourceType: resourceTypeUserGroup,
		client:       client,
	}
}
