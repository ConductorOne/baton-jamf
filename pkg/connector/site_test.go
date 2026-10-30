package connector

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/conductorone/baton-jamf/pkg/jamf"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func siteEntitlement(t *testing.T, siteID int) *v2.Entitlement {
	t.Helper()
	resource, err := siteResource(&jamf.Site{BaseType: jamf.BaseType{ID: siteID, Name: "HQ"}}, nil)
	if err != nil {
		t.Fatalf("siteResource: %v", err)
	}
	return ent.NewAssignmentEntitlement(resource, memberEntitlement, ent.WithGrantableTo(resourceTypeUser))
}

func userGroupPrincipal(t *testing.T, groupID int) *v2.Resource {
	t.Helper()
	r, err := userGroupResource(&jamf.UserGroup{BaseType: jamf.BaseType{ID: groupID, Name: "Group"}}, nil)
	if err != nil {
		t.Fatalf("userGroupResource: %v", err)
	}
	return r
}

// jamfUserSitesHandler serves GET /JSSResource/users/id/{id} returning the
// user's current site memberships in the flat JSON shape a live Jamf Pro
// 11.32.1 tenant serves (each entry's id/name at the top level, not wrapped
// under a "site" key), and records the <sites> payload of any PUT to the
// same path so tests can assert the read-modify-write result.
func jamfUserSitesHandler(t *testing.T, currentSiteIDs []int, gotPUTBody *[]byte) http.HandlerFunc {
	t.Helper()
	return jamfUserSitesStatefulHandler(t, currentSiteIDs, currentSiteIDs, http.StatusCreated, gotPUTBody)
}

// jamfUserSitesStatefulHandler serves GET /JSSResource/users/id/{id},
// reporting sitesBeforePut on the first GET and sitesAfterPut on every GET
// thereafter. PUT records its body and returns putStatus.
func jamfUserSitesStatefulHandler(t *testing.T, sitesBeforePut, sitesAfterPut []int, putStatus int, gotPUTBody *[]byte) http.HandlerFunc {
	t.Helper()
	getCalls := 0
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			getCalls++
			ids := sitesBeforePut
			if getCalls > 1 {
				ids = sitesAfterPut
			}
			sites := make([]map[string]any, 0, len(ids))
			for _, id := range ids {
				sites = append(sites, map[string]any{"id": id, "name": "Site"})
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user": map[string]any{"id": 42, "name": "jappleseed", "sites": sites},
			})
		case http.MethodPut:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read PUT body: %v", err)
			}
			*gotPUTBody = body
			w.WriteHeader(putStatus)
		default:
			t.Fatalf("unexpected method %s", r.Method)
		}
	}
}

func TestSiteGrant_UserNotYetMember_IssuesPUT(t *testing.T) {
	var putBody []byte
	client := newTestJamfClient(t, jamfUserSitesHandler(t, []int{1}, &putBody))
	s := siteBuilder(client)

	grants, annos, err := s.Grant(context.Background(), userPrincipal(t, 42), siteEntitlement(t, 2))
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("want 1 grant, got %d", len(grants))
	}
	if annos != nil {
		t.Errorf("expected no annotations — Sites absorbs idempotency client-side, got %v", annos)
	}
	if len(putBody) == 0 {
		t.Fatal("expected a PUT to be issued to add the new site")
	}
	if got := string(putBody); !strings.Contains(got, `<id>1</id>`) || !strings.Contains(got, `<id>2</id>`) {
		t.Errorf("expected PUT body to contain both the existing and new site ids, got: %s", got)
	}
}

// TestSiteGrant_UserAlreadyMember_MapsToGrantAlreadyExists exercises the
// idempotency mapping for Grant: when AddUserSite reports the user is
// already a site member, Grant returns a GrantAlreadyExists annotation
// instead of a fresh grant, mirroring userGroup.go's Grant pattern.
func TestSiteGrant_UserAlreadyMember_MapsToGrantAlreadyExists(t *testing.T) {
	var putBody []byte
	client := newTestJamfClient(t, jamfUserSitesHandler(t, []int{2}, &putBody))
	s := siteBuilder(client)

	grants, annos, err := s.Grant(context.Background(), userPrincipal(t, 42), siteEntitlement(t, 2))
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if grants != nil {
		t.Errorf("expected no grants returned on the already-member path, got %v", grants)
	}
	if ok, _ := annos.Pick(&v2.GrantAlreadyExists{}); !ok {
		t.Errorf("expected a GrantAlreadyExists annotation for an already-member grant, got %v", annos)
	}
	if len(putBody) != 0 {
		t.Errorf("expected no PUT for an already-member grant, got body: %s", putBody)
	}
}

func TestSiteRevoke_UserIsMember_IssuesPUT(t *testing.T) {
	var putBody []byte
	client := newTestJamfClient(t, jamfUserSitesHandler(t, []int{1, 2}, &putBody))
	s := siteBuilder(client)

	gr := grant.NewGrant(siteEntitlement(t, 2).Resource, memberEntitlement, userPrincipal(t, 42).Id)
	annos, err := s.Revoke(context.Background(), gr)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if annos != nil {
		t.Errorf("expected no annotations, got %v", annos)
	}
	if len(putBody) == 0 {
		t.Fatal("expected a PUT to be issued to remove the site")
	}
	if got := string(putBody); strings.Contains(got, `<id>2</id>`) {
		t.Errorf("expected revoked site id to be absent from PUT body, got: %s", got)
	}
}

// TestSiteRevoke_UserNotMember_MapsToGrantAlreadyRevoked exercises the
// idempotency mapping for Revoke: when RemoveUserSite reports the user is
// already absent from the site, Revoke returns a GrantAlreadyRevoked
// annotation instead of a plain success, mirroring userGroup.go's Revoke
// pattern.
func TestSiteRevoke_UserNotMember_MapsToGrantAlreadyRevoked(t *testing.T) {
	var putBody []byte
	client := newTestJamfClient(t, jamfUserSitesHandler(t, []int{1}, &putBody))
	s := siteBuilder(client)

	gr := grant.NewGrant(siteEntitlement(t, 2).Resource, memberEntitlement, userPrincipal(t, 42).Id)
	annos, err := s.Revoke(context.Background(), gr)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if ok, _ := annos.Pick(&v2.GrantAlreadyRevoked{}); !ok {
		t.Errorf("expected a GrantAlreadyRevoked annotation for a not-a-member revoke, got %v", annos)
	}
	if len(putBody) != 0 {
		t.Errorf("expected no PUT for a not-a-member revoke, got body: %s", putBody)
	}
}

// TestSiteRevoke_UserDeleted_MapsToGrantAlreadyRevoked exercises the
// idempotency mapping for Revoke when the user backing the grant has since
// been deleted: the getUserDetails lookup inside RemoveUserSite 404s, which
// is treated as alreadyAbsent (a deleted user trivially has no site
// membership left to revoke) rather than a hard error.
func TestSiteRevoke_UserDeleted_MapsToGrantAlreadyRevoked(t *testing.T) {
	client := newTestJamfClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	s := siteBuilder(client)

	gr := grant.NewGrant(siteEntitlement(t, 2).Resource, memberEntitlement, userPrincipal(t, 42).Id)
	annos, err := s.Revoke(context.Background(), gr)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if ok, _ := annos.Pick(&v2.GrantAlreadyRevoked{}); !ok {
		t.Errorf("expected a GrantAlreadyRevoked annotation for a deleted-user revoke, got %v", annos)
	}
}

func TestSiteGrant_NonUserPrincipal_Errors(t *testing.T) {
	s := siteBuilder(nil)
	_, _, err := s.Grant(context.Background(), userGroupPrincipal(t, 7), siteEntitlement(t, 2))
	if err == nil {
		t.Fatal("expected an error granting site membership to a non-user principal")
	}
}

func TestSiteRevoke_NonUserPrincipal_Errors(t *testing.T) {
	s := siteBuilder(nil)
	gr := grant.NewGrant(siteEntitlement(t, 2).Resource, memberEntitlement, userGroupPrincipal(t, 7).Id)
	_, err := s.Revoke(context.Background(), gr)
	if err == nil {
		t.Fatal("expected an error revoking site membership from a non-user principal")
	}
}

// TestSiteGrant_UserDeleted_ReturnsNotFound covers Grant's read of the user:
// a 404 there means the user has been deleted, which must surface as
// codes.NotFound rather than being absorbed as success.
func TestSiteGrant_UserDeleted_ReturnsNotFound(t *testing.T) {
	client := newTestJamfClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected method %s", r.Method)
		}
		w.WriteHeader(http.StatusNotFound)
	})
	s := siteBuilder(client)

	_, _, err := s.Grant(context.Background(), userPrincipal(t, 42), siteEntitlement(t, 2))
	if err == nil {
		t.Fatal("expected an error granting site membership for a deleted user")
	}
	if status.Code(err) != codes.NotFound {
		t.Errorf("expected NotFound, got %v", err)
	}
}

// TestSiteGrant_Conflict_ReturnsFailedPrecondition covers a 409 on the write
// (e.g. an unknown site id): the pre-write read already ruled out "already a
// member", so Grant surfaces the 409 as FailedPrecondition instead of
// AlreadyExists or success.
func TestSiteGrant_Conflict_ReturnsFailedPrecondition(t *testing.T) {
	var putBody []byte
	client := newTestJamfClient(t, jamfUserSitesStatefulHandler(t, []int{1}, []int{1}, http.StatusConflict, &putBody))
	s := siteBuilder(client)

	_, _, err := s.Grant(context.Background(), userPrincipal(t, 42), siteEntitlement(t, 2))
	if err == nil {
		t.Fatal("expected an error for a 409 on the write")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("expected FailedPrecondition for a 409 on the write, got %v", err)
	}
	if len(putBody) == 0 {
		t.Error("expected the PUT to be attempted since the pre-write check shows no site")
	}
}

// TestSiteRevoke_LastSite_SendsExplicitEmptySitesElement covers the
// last-site-removal case: the PUT body must carry an explicit empty
// <sites></sites> element so Jamf actually clears membership, not omit the
// element and leave the prior value untouched.
func TestSiteRevoke_LastSite_SendsExplicitEmptySitesElement(t *testing.T) {
	var putBody []byte
	client := newTestJamfClient(t, jamfUserSitesHandler(t, []int{2}, &putBody))
	s := siteBuilder(client)

	gr := grant.NewGrant(siteEntitlement(t, 2).Resource, memberEntitlement, userPrincipal(t, 42).Id)
	annos, err := s.Revoke(context.Background(), gr)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if annos != nil {
		t.Errorf("expected no annotations, got %v", annos)
	}
	if want := "<user><sites></sites></user>"; string(putBody) != want {
		t.Errorf("PUT body = %q, want %q", string(putBody), want)
	}
}

// TestSiteRevoke_Conflict_ReturnsFailedPrecondition covers a 409 on the
// write: the pre-write read already ruled out "not a member", so Revoke
// surfaces the 409 as FailedPrecondition instead of assuming success.
func TestSiteRevoke_Conflict_ReturnsFailedPrecondition(t *testing.T) {
	var putBody []byte
	client := newTestJamfClient(t, jamfUserSitesStatefulHandler(t, []int{1, 2}, []int{1, 2}, http.StatusConflict, &putBody))
	s := siteBuilder(client)

	gr := grant.NewGrant(siteEntitlement(t, 2).Resource, memberEntitlement, userPrincipal(t, 42).Id)
	_, err := s.Revoke(context.Background(), gr)
	if err == nil {
		t.Fatal("expected an error for a 409 on the write")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("expected FailedPrecondition for a 409 on the write, got %v", err)
	}
	if len(putBody) == 0 {
		t.Error("expected the PUT to be attempted since the pre-write check shows the site present")
	}
}

// Site grants walk the site's users, then its user groups, then the accounts assigned to it, one page per call.
func TestSiteGrants_WalksUsersUserGroupsThenAdmins(t *testing.T) {
	siteAuditor := testAccount(7, privilegeSetAuditor)
	siteAuditor.Site = jamf.BaseType{ID: 1}
	siteCustom := testAccount(8, privilegeSetCustom)
	siteCustom.Site = jamf.BaseType{ID: 1}
	otherSiteAuditor := testAccount(9, privilegeSetAuditor)
	otherSiteAuditor.Site = jamf.BaseType{ID: 2}
	noSiteAuditor := testAccount(10, privilegeSetAuditor)

	userIDs := idRange(1, jamf.SiteObjectsPageSize+50) // a full page and a short one
	userGroupIDs := idRange(500, 30)
	fixture := newAdminFixture(t, []jamf.UserAccount{siteAuditor, siteCustom, otherSiteAuditor, noSiteAuditor}, nil)
	fixture.siteObjects = map[string][]int{
		"1/User":       userIDs,
		"1/User Group": userGroupIDs,
		"2/User":       {999},
	}
	builder := siteBuilder(fixture.client())
	site, err := siteResource(&jamf.Site{BaseType: jamf.BaseType{ID: 1, Name: "Site 1"}}, nil)
	if err != nil {
		t.Fatalf("siteResource: %v", err)
	}

	grants, calls := collectGrants(t, builder.Grants, site, newMemorySessionStore())

	// Two user pages, one user group page, one admin page.
	if calls != 4 {
		t.Errorf("Grants calls = %d, want 4", calls)
	}
	if got := fixture.requestCount("/api/v1/sites/1/objects"); got != 3 {
		t.Errorf("site objects requests = %d, want 3", got)
	}
	if got := fixture.accountsRequestsSeen(); len(got) != 1 || got[0].filter != "siteId==1" {
		t.Errorf("accounts requests = %v, want one with filter siteId==1", got)
	}
	if got := fixture.requestCount("/JSSResource"); got != 0 {
		t.Errorf("Classic requests = %d, want 0", got)
	}

	var want []string
	for _, userID := range userIDs {
		want = append(want, "user:"+strconv.Itoa(userID))
	}
	for _, userGroupID := range userGroupIDs {
		want = append(want, "userGroup:"+strconv.Itoa(userGroupID))
	}
	want = append(want, "userAccount:7", "userAccount:8")
	slices.Sort(want)
	if got := grantPrincipals(t, grants); !slices.Equal(got, want) {
		t.Errorf("principals = %v, want %v", got, want)
	}
}
