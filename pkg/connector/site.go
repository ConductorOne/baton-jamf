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
)

type siteResourceType struct {
	resourceType *v2.ResourceType
	client       *jamf.Client
}

func (g *siteResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return g.resourceType
}

// siteResource creates a new connector resource for a Jamf site.
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

func (g *siteResourceType) List(ctx context.Context, parentId *v2.ResourceId, attrs rs.SyncOpAttrs) ([]*v2.Resource, *rs.SyncOpResults, error) {
	sites, err := g.client.GetSites(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("jamf-connector: failed to list sites: %w", err)
	}

	var rv []*v2.Resource
	for _, site := range *sites {
		siteCopy := site
		ur, err := siteResource(&siteCopy, parentId)
		if err != nil {
			return nil, nil, err
		}
		rv = append(rv, ur)
	}

	return rv, nil, nil
}

func (g *siteResourceType) Entitlements(_ context.Context, resource *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	var rv []*v2.Entitlement

	// WithGrantableTo intentionally names only resourceTypeUser, even though
	// Grants() below emits grants for user, userGroup, userAccount, and group:
	// site membership is only genuinely multi-valued for user (<sites> is a
	// real list); for the other three, "site" is a single-valued/exclusive
	// attribute, so Grant/Revoke provisioning is scoped to user only. Do not
	// widen this to match Grants() without also adding exclusive-entitlement
	// handling for the other three principal types.
	assignmentOptions := []ent.EntitlementOption{
		ent.WithGrantableTo(resourceTypeUser),
		ent.WithDescription(fmt.Sprintf("Member of %s Site in Jamf", resource.DisplayName)),
		ent.WithDisplayName(fmt.Sprintf("%s Site %s", resource.DisplayName, memberEntitlement)),
	}

	en := ent.NewAssignmentEntitlement(resource, memberEntitlement, assignmentOptions...)
	rv = append(rv, en)

	return rv, nil, nil
}

func (g *siteResourceType) Grants(ctx context.Context, resource *v2.Resource, attrs rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	var rv []*v2.Grant

	users, err := g.client.GetUsers(ctx)
	if err != nil {
		return rv, nil, err
	}

	for _, user := range users {
		userCopy := user
		ur, err := userResource(userCopy, resource.Id)
		if err != nil {
			return nil, nil, err
		}
		for _, site := range user.Sites {
			stringId := strconv.Itoa(site.ID)
			if stringId == resource.Id.Resource {
				userMembershipGrant := grant.NewGrant(resource, memberEntitlement, ur.Id)
				rv = append(rv, userMembershipGrant)
			}
		}
	}

	userGroups, err := g.client.GetUserGroups(ctx)
	if err != nil {
		return nil, nil, err
	}

	for _, userGroup := range userGroups {
		userGroupCopy := userGroup
		ugr, err := userGroupResource(userGroupCopy, resource.Id)
		if err != nil {
			return nil, nil, err
		}
		stringId := strconv.Itoa(userGroup.Site.ID)
		if stringId == resource.Id.Resource {
			userGroupMembershipGrant := grant.NewGrant(resource, memberEntitlement, ugr.Id)
			rv = append(rv, userGroupMembershipGrant)
		}
	}

	userAccounts, groups, err := g.client.GetAccounts(ctx)
	if err != nil {
		return nil, nil, err
	}

	for _, userAccount := range userAccounts {
		userAccountCopy := userAccount
		uar, err := userAccountResource(userAccountCopy, resource.Id)
		if err != nil {
			return nil, nil, err
		}
		stringId := strconv.Itoa(userAccount.Site.ID)
		if stringId == resource.Id.Resource {
			userGroupMembershipGrant := grant.NewGrant(resource, memberEntitlement, uar.Id)
			rv = append(rv, userGroupMembershipGrant)
		}
	}

	for _, group := range groups {
		groupCopy := group
		gr, err := groupResource(groupCopy, resource.Id)
		if err != nil {
			return nil, nil, err
		}
		stringId := strconv.Itoa(group.Site.ID)
		if stringId == resource.Id.Resource {
			userGroupMembershipGrant := grant.NewGrant(resource, memberEntitlement, gr.Id)
			rv = append(rv, userGroupMembershipGrant)
		}
	}

	return rv, nil, nil
}

// Grant adds principal (a Jamf user) to the multi-valued <sites> list of the
// site backing entitlement's resource. The principal-type guard is defense-
// in-depth: Grants() emits site grants for four principal types, but only
// user is genuinely multi-valued/grantable — see the WithGrantableTo note in
// Entitlements above.
//
// client.AddUserSite reports via its bool return whether the user was
// already a site member, so that case is surfaced here as GrantAlreadyExists
// instead of a fresh grant.
func (g *siteResourceType) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) ([]*v2.Grant, annotations.Annotations, error) {
	ctx = jamf.WithFreshReads(ctx)

	if err := requirePrincipalType(principal.Id.ResourceType, resourceTypeUser, "site membership", "granted to users"); err != nil {
		return nil, nil, err
	}

	siteID, err := parseResourceID("jamf-connector: grant site member: invalid site id", entitlement.Resource.Id.Resource)
	if err != nil {
		return nil, nil, err
	}
	userID, err := parseResourceID("jamf-connector: grant site member: invalid user id", principal.Id.Resource)
	if err != nil {
		return nil, nil, err
	}

	alreadyMember, err := g.client.AddUserSite(ctx, userID, siteID)
	if err != nil {
		return nil, nil, membershipWriteError("grant site member", "the user or site", err)
	}
	if alreadyMember {
		return nil, annotations.New(&v2.GrantAlreadyExists{}), nil
	}
	return []*v2.Grant{grant.NewGrant(entitlement.Resource, memberEntitlement, principal.Id)}, nil, nil
}

// Revoke removes gr's principal (a Jamf user) from the <sites> list of the
// site backing gr's entitlement resource. See Grant for the principal-type
// guard rationale. client.RemoveUserSite reports via its bool return whether
// the user was already absent from the site (including the case where the
// user has since been deleted), so that case is surfaced here as
// GrantAlreadyRevoked instead of a plain success.
func (g *siteResourceType) Revoke(ctx context.Context, gr *v2.Grant) (annotations.Annotations, error) {
	ctx = jamf.WithFreshReads(ctx)

	if err := requirePrincipalType(gr.Principal.Id.ResourceType, resourceTypeUser, "site membership", "revoked for users"); err != nil {
		return nil, err
	}

	siteID, err := parseResourceID("jamf-connector: revoke site member: invalid site id", gr.Entitlement.Resource.Id.Resource)
	if err != nil {
		return nil, err
	}
	userID, err := parseResourceID("jamf-connector: revoke site member: invalid user id", gr.Principal.Id.Resource)
	if err != nil {
		return nil, err
	}

	alreadyAbsent, err := g.client.RemoveUserSite(ctx, userID, siteID)
	if err != nil {
		return nil, membershipWriteError("revoke site member", "the user or site", err)
	}
	if alreadyAbsent {
		return annotations.New(&v2.GrantAlreadyRevoked{}), nil
	}
	return nil, nil
}

func siteBuilder(client *jamf.Client) *siteResourceType {
	return &siteResourceType{
		resourceType: resourceTypeSite,
		client:       client,
	}
}
