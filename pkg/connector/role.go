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
	"github.com/conductorone/baton-sdk/pkg/types/resource"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

	description := fmt.Sprintf("Privilege set of %s", resource.DisplayName)
	privilegeOptions := []ent.EntitlementOption{
		ent.WithDisplayName(fmt.Sprintf("%s privilege set %s", resource.DisplayName, memberEntitlement)),
	}

	// Grant/Revoke provisioning (see Grant/Revoke below) is scoped to the 3
	// built-in privilege sets: granting one displaces whatever privilege_set
	// the principal previously held, and revoking always downgrades to
	// Enrollment Only. Individual-privilege Role resources are meaningful
	// only under a Custom privilege_set and are sync-only — WithGrantableTo
	// is deliberately not declared for them, so the catalog never advertises
	// provisioning that Grant/Revoke would then reject.
	if slices.Contains(privilegeSets, resource.Id.Resource) {
		description = fmt.Sprintf("%s — granting this overwrites the principal's current privilege set; revoking downgrades to %q", description, privilegeSetEnrollmentOnly)
		privilegeOptions = append(privilegeOptions, ent.WithGrantableTo(resourceTypeUserAccount, resourceTypeGroup))
	}
	privilegeOptions = append(privilegeOptions, ent.WithDescription(description))

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

// Grant sets principal (a userAccount or group) to hold the built-in
// privilege set backing entitlement's resource. Single-valued/exclusive:
// this displaces whatever privilege_set the principal previously held —
// same pattern as Managed Device's "assigned" entitlement and Site's
// non-user principals elsewhere in this connector. Individual-privilege
// Role resources are out of scope (see Entitlements) and rejected here.
func (o *roleResourceType) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) ([]*v2.Grant, annotations.Annotations, error) {
	targetPrivilegeSet := entitlement.Resource.Id.Resource
	if !slices.Contains(privilegeSets, targetPrivilegeSet) {
		return nil, nil, status.Errorf(codes.InvalidArgument, "jamf-connector: role provisioning is only supported for the built-in privilege sets %v, got %q", privilegeSets, targetPrivilegeSet)
	}

	newGrant := grant.NewGrant(entitlement.Resource, memberEntitlement, principal.Id)

	switch principal.Id.ResourceType {
	case resourceTypeUserAccount.Id:
		userID, err := strconv.Atoi(principal.Id.Resource)
		if err != nil {
			return nil, nil, status.Errorf(codes.InvalidArgument, "jamf-connector: grant role: invalid user account id %q: %s", principal.Id.Resource, err)
		}

		current, err := o.client.GetUserAccountDetails(ctx, userID)
		if err != nil {
			return nil, nil, fmt.Errorf("jamf-connector: grant role: %w", err)
		}
		if current.PrivilegeSet == targetPrivilegeSet {
			// Already holds this exact privilege set — nothing would be
			// displaced, and re-sending the same PUT would only churn Jamf's
			// audit log.
			return []*v2.Grant{newGrant}, annotations.New(&v2.GrantAlreadyExists{}), nil
		}

		if err := o.client.SetUserAccountPrivilegeSet(ctx, userID, targetPrivilegeSet); err != nil {
			return nil, nil, fmt.Errorf("jamf-connector: grant role: %w", err)
		}
	case resourceTypeGroup.Id:
		groupID, err := strconv.Atoi(principal.Id.Resource)
		if err != nil {
			return nil, nil, status.Errorf(codes.InvalidArgument, "jamf-connector: grant role: invalid group id %q: %s", principal.Id.Resource, err)
		}

		current, err := o.client.GetGroupDetails(ctx, groupID)
		if err != nil {
			return nil, nil, fmt.Errorf("jamf-connector: grant role: %w", err)
		}
		if current.PrivilegeSet == targetPrivilegeSet {
			return []*v2.Grant{newGrant}, annotations.New(&v2.GrantAlreadyExists{}), nil
		}

		if err := o.client.SetGroupPrivilegeSet(ctx, groupID, targetPrivilegeSet); err != nil {
			return nil, nil, fmt.Errorf("jamf-connector: grant role: %w", err)
		}
	default:
		return nil, nil, status.Errorf(codes.InvalidArgument, "jamf-connector: role can only be granted to a user account or group, got resource type %q", principal.Id.ResourceType)
	}

	return []*v2.Grant{newGrant}, nil, nil
}

// Revoke always downgrades gr's principal (a userAccount or group) to the
// fixed Enrollment Only privilege set, regardless of which built-in set is
// being revoked. Jamf's privilege_set enum has no neutral/no-access value,
// so Enrollment Only — the least-privileged built-in set — is the
// deliberate, fixed downgrade target for every Revoke; this is not an
// attempt to compute a "smarter" target. Entitlements no longer declares
// WithGrantableTo for individual-privilege Role resources, so the platform
// should never invoke Revoke for one; the principal-type guard below is the
// only rejection needed here.
func (o *roleResourceType) Revoke(ctx context.Context, gr *v2.Grant) (annotations.Annotations, error) {
	switch gr.Principal.Id.ResourceType {
	case resourceTypeUserAccount.Id:
		userID, err := strconv.Atoi(gr.Principal.Id.Resource)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "jamf-connector: revoke role: invalid user account id %q: %s", gr.Principal.Id.Resource, err)
		}

		current, err := o.client.GetUserAccountDetails(ctx, userID)
		if err != nil {
			return nil, fmt.Errorf("jamf-connector: revoke role: %w", err)
		}
		if current.PrivilegeSet == privilegeSetEnrollmentOnly {
			return annotations.New(&v2.GrantAlreadyRevoked{}), nil
		}

		if err := o.client.SetUserAccountPrivilegeSet(ctx, userID, privilegeSetEnrollmentOnly); err != nil {
			return nil, fmt.Errorf("jamf-connector: revoke role: %w", err)
		}
	case resourceTypeGroup.Id:
		groupID, err := strconv.Atoi(gr.Principal.Id.Resource)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "jamf-connector: revoke role: invalid group id %q: %s", gr.Principal.Id.Resource, err)
		}

		current, err := o.client.GetGroupDetails(ctx, groupID)
		if err != nil {
			return nil, fmt.Errorf("jamf-connector: revoke role: %w", err)
		}
		if current.PrivilegeSet == privilegeSetEnrollmentOnly {
			return annotations.New(&v2.GrantAlreadyRevoked{}), nil
		}

		if err := o.client.SetGroupPrivilegeSet(ctx, groupID, privilegeSetEnrollmentOnly); err != nil {
			return nil, fmt.Errorf("jamf-connector: revoke role: %w", err)
		}
	default:
		return nil, status.Errorf(codes.InvalidArgument, "jamf-connector: role can only be revoked for a user account or group, got resource type %q", gr.Principal.Id.ResourceType)
	}

	return nil, nil
}

func roleBuilder(client *jamf.Client) *roleResourceType {
	return &roleResourceType{
		resourceType: resourceTypeRole,
		client:       client,
	}
}
