package connector

import (
	"context"
	"fmt"
	"strconv"

	"github.com/ConductorOne/baton-jamf/pkg/jamf"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	grant "github.com/conductorone/baton-sdk/pkg/types/grant"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
)

type siteResourceType struct {
	resourceType *v2.ResourceType
	client       *jamf.Client
}

func (g *siteResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return g.resourceType
}

// Create a new connector resource for a Jamf site.
func siteResource(site *jamf.Site, parentResourceID *v2.ResourceId) (*v2.Resource, error) {
	ret, err := rs.NewResource(
		site.Name,
		resourceTypeSite,
		site.ID,
	)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func (g *siteResourceType) List(ctx context.Context, parentId *v2.ResourceId, token *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	sites, err := g.client.GetSites(ctx)
	if err != nil {
		return nil, "", nil, fmt.Errorf("jamf-connector: failed to list sites: %w", err)
	}

	var rv []*v2.Resource
	for _, site := range sites {
		siteCopy := site
		ur, err := siteResource(&siteCopy, parentId)
		if err != nil {
			return nil, "", nil, err
		}
		rv = append(rv, ur)
	}

	return rv, "", nil, nil
}

func (g *siteResourceType) Entitlements(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var rv []*v2.Entitlement

	assigmentOptions := []ent.EntitlementOption{
		ent.WithGrantableTo(resourceTypeUser),
		ent.WithDescription(fmt.Sprintf("Member of %s Site in Jamf", resource.DisplayName)),
		ent.WithDisplayName(fmt.Sprintf("%s Site %s", resource.DisplayName, memberEntitlement)),
	}

	en := ent.NewAssignmentEntitlement(resource, memberEntitlement, assigmentOptions...)
	rv = append(rv, en)

	return rv, "", nil, nil
}

func (g *siteResourceType) Grants(ctx context.Context, resource *v2.Resource, token *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	var rv []*v2.Grant

	users, err := g.client.GetUsers(ctx)
	if err != nil {
		return rv, "", nil, err
	}

	for _, user := range users {
		userCopy := user
		ur, err := userResource(&userCopy, resource.Id)
		if err != nil {
			return nil, "", nil, err
		}
		for _, site := range user.Sites {
			stringId := strconv.Itoa(site.Site.ID)
			if stringId == resource.Id.Resource {
				userMembershipGrant := grant.NewGrant(resource, memberEntitlement, ur.Id)
				rv = append(rv, userMembershipGrant)
			}
		}
	}

	userGroups, err := g.client.GetUserGroups(ctx)
	if err != nil {
		return nil, "", nil, err
	}

	for _, userGroup := range userGroups {
		userGroupCopy := userGroup
		ugr, err := userGroupResource(&userGroupCopy, resource.Id)
		if err != nil {
			return nil, "", nil, err
		}
		stringId := strconv.Itoa(userGroup.Site.ID)
		if stringId == resource.Id.Resource {
			userGroupMembershipGrant := grant.NewGrant(resource, memberEntitlement, ugr.Id)
			rv = append(rv, userGroupMembershipGrant)
		}
	}

	userAccounts, groups, err := g.client.GetAccounts(ctx)
	if err != nil {
		return nil, "", nil, err
	}

	for _, userAccount := range userAccounts {
		userAccountCopy := userAccount
		uar, err := userAccountResource(&userAccountCopy, resource.Id)
		if err != nil {
			return nil, "", nil, err
		}
		stringId := strconv.Itoa(userAccount.Site.ID)
		if stringId == resource.Id.Resource {
			userGroupMembershipGrant := grant.NewGrant(resource, memberEntitlement, uar.Id)
			rv = append(rv, userGroupMembershipGrant)
		}
	}

	for _, group := range groups {
		groupCopy := group
		gr, err := groupResource(&groupCopy, resource.Id)
		if err != nil {
			return nil, "", nil, err
		}
		stringId := strconv.Itoa(group.Site.ID)
		if stringId == resource.Id.Resource {
			userGroupMembershipGrant := grant.NewGrant(resource, memberEntitlement, gr.Id)
			rv = append(rv, userGroupMembershipGrant)
		}
	}

	return rv, "", nil, nil
}

func siteBuilder(client *jamf.Client) *siteResourceType {
	return &siteResourceType{
		resourceType: resourceTypeSite,
		client:       client,
	}
}
