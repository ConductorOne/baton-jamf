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

	groupTraitOptions := []rs.GroupTraitOption{rs.WithGroupProfile(profile)}

	ret, err := rs.NewGroupResource(
		group.Name,
		resourceTypeGroup,
		group.ID,
		groupTraitOptions,
		rs.WithParentResourceID(parentResourceID),
	)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func (g *groupResourceType) List(ctx context.Context, parentId *v2.ResourceId, token *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	_, groups, err := g.client.GetAccounts(ctx)
	if err != nil {
		return nil, "", nil, fmt.Errorf("jamf-connector: failed to list accounts: %w", err)
	}

	var rv []*v2.Resource
	for _, group := range groups {
		groupCopy := group
		gr, err := groupResource(groupCopy, parentId)
		if err != nil {
			return nil, "", nil, err
		}
		rv = append(rv, gr)
	}
	return rv, "", nil, nil
}

func (g *groupResourceType) Entitlements(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var rv []*v2.Entitlement

	assigmentOptions := []ent.EntitlementOption{
		ent.WithGrantableTo(resourceTypeUserAccount),
		ent.WithDescription(fmt.Sprintf("Member of %s Group", resource.DisplayName)),
		ent.WithDisplayName(fmt.Sprintf("%s Group %s", resource.DisplayName, memberEntitlement)),
	}

	en := ent.NewAssignmentEntitlement(resource, memberEntitlement, assigmentOptions...)
	rv = append(rv, en)

	// TODO - access level entitlements & grants

	return rv, "", nil, nil
}

func (g *groupResourceType) Grants(ctx context.Context, resource *v2.Resource, token *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	var rv []*v2.Grant

	groupId, err := strconv.Atoi(resource.Id.Resource)
	if err != nil {
		return nil, "", nil, err
	}

	group, err := g.client.GetGroupDetails(ctx, groupId)
	if err != nil {
		return nil, "", nil, err
	}

	for _, user := range group.Members {
		userCopy := user
		userAccountDetails, err := g.client.GetUserAccountDetails(ctx, userCopy.User.ID)
		if err != nil {
			return nil, "", nil, err
		}
		ur, err := userAccountResource(userAccountDetails, resource.Id)
		if err != nil {
			return nil, "", nil, err
		}

		grant := grant.NewGrant(resource, memberEntitlement, ur.Id)
		rv = append(rv, grant)
	}

	return rv, "", nil, nil
}

func groupBuilder(client *jamf.Client) *groupResourceType {
	return &groupResourceType{
		resourceType: resourceTypeGroup,
		client:       client,
	}
}
