package connector

import (
	"context"
	"fmt"

	"github.com/conductorone/baton-jamf/pkg/jamf"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	grant "github.com/conductorone/baton-sdk/pkg/types/grant"
	resource "github.com/conductorone/baton-sdk/pkg/types/resource"
)

type roleResourceType struct {
	resourceType *v2.ResourceType
	client       *jamf.Client
}

func (o *roleResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

var privileges = []string{
	"Administrator",
	"Auditor",
	"Enrollment Only",
	"Custom",
}

// Create a new connector resource for a Jamf role.
func roleResource(ctx context.Context, role string, parentResourceID *v2.ResourceId) (*v2.Resource, error) {
	profile := map[string]interface{}{
		"role_name": role,
		"role_id":   role,
	}

	roleTraitOptions := []resource.RoleTraitOption{
		resource.WithRoleProfile(profile),
	}

	ret, err := resource.NewRoleResource(
		role,
		resourceTypeRole,
		role,
		roleTraitOptions,
		resource.WithParentResourceID(parentResourceID),
	)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func (o *roleResourceType) List(ctx context.Context, parentId *v2.ResourceId, token *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	var rv []*v2.Resource
	for _, privilege := range privileges {
		rr, err := roleResource(ctx, privilege, parentId)
		if err != nil {
			return nil, "", nil, err
		}
		rv = append(rv, rr)
	}

	return rv, "", nil, nil
}

func (o *roleResourceType) Entitlements(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var rv []*v2.Entitlement

	privilegeOptions := []ent.EntitlementOption{
		ent.WithGrantableTo(resourceTypeUserAccount, resourceTypeGroup),
		ent.WithDescription(fmt.Sprintf("Priviledge set of %s", resource.DisplayName)),
		ent.WithDisplayName(fmt.Sprintf("%s priviledge %s", resource.DisplayName, memberEntitlement)),
	}

	priviledgesEn := ent.NewPermissionEntitlement(resource, memberEntitlement, privilegeOptions...)
	rv = append(rv, priviledgesEn)

	return rv, "", nil, nil
}

func (o *roleResourceType) Grants(ctx context.Context, resource *v2.Resource, token *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	var rv []*v2.Grant

	userAccounts, groups, err := o.client.GetAccounts(ctx)
	if err != nil {
		return nil, "", nil, err
	}

	for _, group := range groups {
		groupCopy := group
		gr, err := groupResource(&groupCopy, resource.Id)
		if err != nil {
			return nil, "", nil, err
		}

		if resource.Id.Resource == group.PrivilegeSet {
			privilegeGrant := grant.NewGrant(resource, memberEntitlement, gr.Id)
			rv = append(rv, privilegeGrant)
		}
	}

	for _, userAccount := range userAccounts {
		userAccountCopy := userAccount
		gr, err := userAccountResource(&userAccountCopy, resource.Id)
		if err != nil {
			return nil, "", nil, err
		}

		if resource.Id.Resource == userAccount.PrivilegeSet {
			privilegeGrant := grant.NewGrant(resource, memberEntitlement, gr.Id)
			rv = append(rv, privilegeGrant)
		}
	}

	return rv, "", nil, nil
}

func roleBuilder(client *jamf.Client) *roleResourceType {
	return &roleResourceType{
		resourceType: resourceTypeRole,
		client:       client,
	}
}
