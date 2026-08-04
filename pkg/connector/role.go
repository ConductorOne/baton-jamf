package connector

import (
	"context"
	"fmt"
	"slices"

	"github.com/conductorone/baton-jamf/pkg/jamf"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	"github.com/conductorone/baton-sdk/pkg/types/resource"
)

type roleResourceType struct {
	resourceType *v2.ResourceType
	client       *jamf.Client
}

func (o *roleResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

// privilegeSets are the built-in sets; privilegeSetCustom is deliberately
// excluded — a Custom account's access is described by its individual privileges.
var privilegeSets = []string{privilegeSetAdministrator, privilegeSetAuditor, privilegeSetEnrollmentOnly}

// Create a new connector resource for a Jamf role.
func roleResource(ctx context.Context, role string, parentResourceID *v2.ResourceId) (*v2.Resource, error) {
	profile := map[string]interface{}{
		"role_name": role,
		"role_id":   role,
	}

	ret, err := resource.NewRoleResource(
		role,
		resourceTypeRole,
		role,
		nil,
		resource.WithParentResourceID(parentResourceID),
		resource.WithResourceProfile(profile),
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

	res, err := o.client.GetPrivileges(ctx)
	if err != nil {
		return nil, nil, err
	}

	for _, privilege := range res.Privileges {
		rr, err := roleResource(ctx, privilege, parentId)
		if err != nil {
			return nil, nil, err
		}
		rv = append(rv, rr)
	}

	return rv, nil, nil
}

func (o *roleResourceType) Entitlements(_ context.Context, resource *v2.Resource, _ resource.SyncOpAttrs) ([]*v2.Entitlement, *resource.SyncOpResults, error) {
	var rv []*v2.Entitlement

	privilegeOptions := []ent.EntitlementOption{
		ent.WithGrantableTo(resourceTypeUserAccount, resourceTypeGroup),
		ent.WithDescription(fmt.Sprintf("Privilege set of %s", resource.DisplayName)),
		ent.WithDisplayName(fmt.Sprintf("%s privilege set %s", resource.DisplayName, memberEntitlement)),
	}

	privilegesEn := ent.NewPermissionEntitlement(resource, memberEntitlement, privilegeOptions...)
	rv = append(rv, privilegesEn)

	return rv, nil, nil
}

// matchesIndividualPrivilege reports whether an account/group holding
// privilegeSet and privileges should be granted the given individual
// privilege role. Privileges is only meaningful for a Custom privilege_set
// (see jamf.UserAccountCreateBody.Privileges) — a built-in set's Privileges
// data, if Jamf ever returns any, must not be treated as an access grant.
func matchesIndividualPrivilege(privilegeSet string, privileges *jamf.Privileges, privilege string) bool {
	return privilegeSet == privilegeSetCustom && privileges.Contains(privilege)
}

func (o *roleResourceType) Grants(ctx context.Context, resource *v2.Resource, attrs resource.SyncOpAttrs) ([]*v2.Grant, *resource.SyncOpResults, error) {
	var rv []*v2.Grant
	isCustomPrivilege := !slices.Contains(privilegeSets, resource.Id.Resource)
	userAccounts, groups, err := o.client.GetAccounts(ctx)
	if err != nil {
		return nil, nil, err
	}

	for _, group := range groups {
		groupCopy := group
		gr, err := groupResource(groupCopy, resource.Id)
		if err != nil {
			return nil, nil, err
		}

		if isCustomPrivilege && matchesIndividualPrivilege(group.PrivilegeSet, &group.Privileges, resource.Id.Resource) {
			privilegeGrant := grant.NewGrant(resource, memberEntitlement, gr.Id)
			rv = append(rv, privilegeGrant)
			continue
		}
		if group.PrivilegeSet == resource.Id.Resource {
			privilegeGrant := grant.NewGrant(resource, memberEntitlement, gr.Id)
			rv = append(rv, privilegeGrant)
		}
	}

	for _, userAccount := range userAccounts {
		userAccountCopy := userAccount
		gr, err := userAccountResource(userAccountCopy, resource.Id)
		if err != nil {
			return nil, nil, err
		}

		if isCustomPrivilege && matchesIndividualPrivilege(userAccount.PrivilegeSet, &userAccount.Privileges, resource.Id.Resource) {
			privilegeGrant := grant.NewGrant(resource, memberEntitlement, gr.Id)
			rv = append(rv, privilegeGrant)
			continue
		}
		if userAccount.PrivilegeSet == resource.Id.Resource {
			privilegeGrant := grant.NewGrant(resource, memberEntitlement, gr.Id)
			rv = append(rv, privilegeGrant)
		}
	}
	return rv, nil, nil
}

func roleBuilder(client *jamf.Client) *roleResourceType {
	return &roleResourceType{
		resourceType: resourceTypeRole,
		client:       client,
	}
}
