package connector

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/conductorone/baton-jamf/pkg/jamf"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
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
// user's current site memberships, and records the <sites> payload of any PUT
// to the same path so tests can assert the read-modify-write result.
func jamfUserSitesHandler(t *testing.T, currentSiteIDs []int, gotPUTBody *[]byte) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			sites := make([]map[string]any, 0, len(currentSiteIDs))
			for _, id := range currentSiteIDs {
				sites = append(sites, map[string]any{"site": map[string]any{"id": id, "name": "Site"}})
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
			w.WriteHeader(http.StatusOK)
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

func TestSiteGrant_UserAlreadyMember_NoOpNoPUT(t *testing.T) {
	var putBody []byte
	client := newTestJamfClient(t, jamfUserSitesHandler(t, []int{2}, &putBody))
	s := siteBuilder(client)

	grants, annos, err := s.Grant(context.Background(), userPrincipal(t, 42), siteEntitlement(t, 2))
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("want 1 grant, got %d", len(grants))
	}
	if annos != nil {
		t.Errorf("expected no annotations on the already-member no-op, got %v", annos)
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

func TestSiteRevoke_UserNotMember_NoOpNoPUT(t *testing.T) {
	var putBody []byte
	client := newTestJamfClient(t, jamfUserSitesHandler(t, []int{1}, &putBody))
	s := siteBuilder(client)

	gr := grant.NewGrant(siteEntitlement(t, 2).Resource, memberEntitlement, userPrincipal(t, 42).Id)
	annos, err := s.Revoke(context.Background(), gr)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if annos != nil {
		t.Errorf("expected no annotations, got %v", annos)
	}
	if len(putBody) != 0 {
		t.Errorf("expected no PUT for a not-a-member revoke, got body: %s", putBody)
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
