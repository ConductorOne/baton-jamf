package connector

import (
	"context"
	"fmt"
	"slices"
	"strconv"

	"github.com/conductorone/baton-jamf/pkg/jamf"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	sitePhaseUser      = "user"
	sitePhaseUserGroup = "userGroup"
	sitePhaseAdmins    = "admins"
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
		ur, err := siteResource(&site, parentId)
		if err != nil {
			return nil, nil, err
		}
		rv = append(rv, ur)
	}

	return rv, nil, nil
}

// Entitlements is unused: StaticEntitlements declares the member entitlement.
func (g *siteResourceType) Entitlements(_ context.Context, _ *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	return nil, nil, nil
}

func (g *siteResourceType) StaticEntitlements(_ context.Context, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	// Only a user's site membership is multi-valued; for the other principal types
	// site is single-valued, so provisioning is user-only.
	return []*v2.Entitlement{
		ent.NewAssignmentEntitlement(nil, memberEntitlement,
			ent.WithDisplayName("Member"),
			ent.WithDescription("Member of the Jamf site"),
			ent.WithGrantableTo(resourceTypeUser),
		),
	}, nil, nil
}

// Grants emits the site's members in three phases: users, user groups and admin accounts.
func (g *siteResourceType) Grants(ctx context.Context, resource *v2.Resource, attrs rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	siteID, err := strconv.Atoi(resource.Id.Resource)
	if err != nil {
		return nil, nil, fmt.Errorf("jamf-connector: invalid site id %q: %w", resource.Id.Resource, err)
	}

	bag := &pagination.Bag{}
	if err := bag.Unmarshal(attrs.PageToken.Token); err != nil {
		return nil, nil, fmt.Errorf("jamf-connector: parse site %s grants page token: %w", resource.Id.Resource, err)
	}
	if bag.Current() == nil {
		bag.Push(pagination.PageState{ResourceTypeID: sitePhaseAdmins})
		bag.Push(pagination.PageState{ResourceTypeID: sitePhaseUserGroup})
		bag.Push(pagination.PageState{ResourceTypeID: sitePhaseUser})
	}

	phase := bag.Current()
	var grants []*v2.Grant
	var nextPage string
	switch phase.ResourceTypeID {
	case sitePhaseUser:
		grants, nextPage, err = g.siteObjectGrants(ctx, resource, siteID, "User", resourceTypeUser, phase.Token)
	case sitePhaseUserGroup:
		grants, nextPage, err = g.siteObjectGrants(ctx, resource, siteID, "User Group", resourceTypeUserGroup, phase.Token)
	case sitePhaseAdmins:
		grants, nextPage, err = g.adminGrants(ctx, resource, siteID, phase.Token)
	default:
		err = fmt.Errorf("unknown phase %q", phase.ResourceTypeID)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("jamf-connector: list site %s %s grants: %w", resource.Id.Resource, phase.ResourceTypeID, err)
	}

	nextToken, err := bag.NextToken(nextPage)
	if err != nil {
		return nil, nil, fmt.Errorf("jamf-connector: build site %s grants page token: %w", resource.Id.Resource, err)
	}
	return grants, &rs.SyncOpResults{NextPageToken: nextToken}, nil
}

// siteObjectGrants grants the site's objects of objectType on one page.
func (g *siteResourceType) siteObjectGrants(
	ctx context.Context,
	site *v2.Resource,
	siteID int,
	objectType string,
	principalType *v2.ResourceType,
	page string,
) ([]*v2.Grant, string, error) {
	objects, nextPage, err := g.client.GetSiteObjects(ctx, siteID, objectType, page)
	if err != nil {
		return nil, "", err
	}

	grants := make([]*v2.Grant, 0, len(objects))
	for _, object := range objects {
		principal := &v2.ResourceId{ResourceType: principalType.Id, Resource: strconv.Itoa(object.ObjectID)}
		grants = append(grants, grant.NewGrant(site, memberEntitlement, principal))
	}
	return grants, nextPage, nil
}

// adminGrants grants the admin accounts assigned to the site on one page. Groups assigned to it come from the group Grants.
func (g *siteResourceType) adminGrants(ctx context.Context, site *v2.Resource, siteID int, page string) ([]*v2.Grant, string, error) {
	accounts, nextPage, err := g.client.GetProAccounts(ctx, fmt.Sprintf("siteId==%d", siteID), page, jamf.AccountsPageSize)
	if err != nil {
		return nil, "", err
	}

	grants := make([]*v2.Grant, 0, len(accounts))
	for _, account := range accounts {
		principal := &v2.ResourceId{ResourceType: resourceTypeUserAccount.Id, Resource: strconv.Itoa(account.ID)}
		grants = append(grants, grant.NewGrant(site, memberEntitlement, principal))
	}
	return grants, nextPage, nil
}

// Grant adds principal (a Jamf user) to the multi-valued <sites> list of the
// site backing entitlement's resource. The principal-type guard is defense-
// in-depth: site grants are emitted for four principal types, but only
// user is genuinely multi-valued/grantable — see the WithGrantableTo note in
// StaticEntitlements above.
func (g *siteResourceType) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) ([]*v2.Grant, annotations.Annotations, error) {
	ctx = jamf.WithFreshReads(ctx)

	siteID, userID, err := membershipIDs("grant site member", resourceTypeUser, entitlement.Resource.Id, principal.Id)
	if err != nil {
		return nil, nil, err
	}

	user, err := g.client.GetUserDetails(ctx, userID)
	if err != nil {
		if jamf.IsNotFoundError(err) {
			return nil, nil, status.Errorf(codes.NotFound, "jamf-connector: grant site member: user %d not found", userID)
		}
		return nil, nil, fmt.Errorf("jamf-connector: grant site member: %w", err)
	}
	if slices.ContainsFunc(user.Sites, func(s jamf.BaseType) bool { return s.ID == siteID }) {
		return nil, annotations.New(&v2.GrantAlreadyExists{}), nil
	}

	newSites := append(append(jamf.UserSites{}, user.Sites...), jamf.BaseType{ID: siteID})
	if err := g.client.UpdateUserSites(ctx, userID, newSites); err != nil {
		return nil, nil, membershipWriteError("grant site member", "the user or site", err)
	}
	return []*v2.Grant{grant.NewGrant(entitlement.Resource, memberEntitlement, principal.Id)}, nil, nil
}

// Revoke removes gr's principal (a Jamf user) from the <sites> list of the
// site backing gr's entitlement resource. See Grant for the principal-type
// guard rationale.
func (g *siteResourceType) Revoke(ctx context.Context, gr *v2.Grant) (annotations.Annotations, error) {
	ctx = jamf.WithFreshReads(ctx)

	siteID, userID, err := membershipIDs("revoke site member", resourceTypeUser, gr.Entitlement.Resource.Id, gr.Principal.Id)
	if err != nil {
		return nil, err
	}

	user, err := g.client.GetUserDetails(ctx, userID)
	if err != nil {
		if jamf.IsNotFoundError(err) {
			// The user has been deleted — a deleted user trivially has no
			// site membership left to revoke.
			return annotations.New(&v2.GrantAlreadyRevoked{}), nil
		}
		return nil, fmt.Errorf("jamf-connector: revoke site member: %w", err)
	}

	remaining := make(jamf.UserSites, 0, len(user.Sites))
	found := false
	for _, s := range user.Sites {
		if s.ID == siteID {
			found = true
			continue
		}
		remaining = append(remaining, s)
	}
	if !found {
		return annotations.New(&v2.GrantAlreadyRevoked{}), nil
	}

	if err := g.client.UpdateUserSites(ctx, userID, remaining); err != nil {
		return nil, membershipWriteError("revoke site member", "the user or site", err)
	}
	return nil, nil
}

func siteBuilder(client *jamf.Client) *siteResourceType {
	return &siteResourceType{
		resourceType: resourceTypeSite,
		client:       client,
	}
}
