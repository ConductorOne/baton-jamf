package jamf

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/conductorone/baton-sdk/pkg/uhttp"
)

// newTestClient spins up an httptest.Server driven by handler and returns a
// real *Client pointed at it, mirroring pkg/connector's newTestJamfClient
// helper — mocking at the HTTP boundary rather than introducing a client
// interface the rest of the package doesn't otherwise need. The server is
// closed automatically when the test ends.
func newTestClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	return NewClient(uhttp.NewBaseHttpClient(server.Client()), "user", "pass", "test-token", server.URL)
}

// userSitesHandler serves GET /JSSResource/users/id/{id} returning the
// user's current site memberships, and records the <sites> payload of any PUT
// to the same path so tests can assert the read-modify-write result.
func userSitesHandler(t *testing.T, currentSiteIDs []int, gotPUTBody *[]byte) http.HandlerFunc {
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

func TestAddUserSite_NotYetMember_IssuesPUTReturnsFalse(t *testing.T) {
	var putBody []byte
	client := newTestClient(t, userSitesHandler(t, []int{1}, &putBody))

	alreadyMember, err := client.AddUserSite(context.Background(), 42, 2)
	if err != nil {
		t.Fatalf("AddUserSite: %v", err)
	}
	if alreadyMember {
		t.Error("expected alreadyMember=false when the site is being newly added")
	}
	if len(putBody) == 0 {
		t.Fatal("expected a PUT to be issued to add the new site")
	}
}

// TestAddUserSite_AlreadyMember_ReturnsTrueNoPUT covers the bool-return
// idempotency signal AddUserSite now surfaces (previously absorbed silently
// as a plain nil error), which site.go's Grant keys off to report
// GrantAlreadyExists instead of a fresh grant.
func TestAddUserSite_AlreadyMember_ReturnsTrueNoPUT(t *testing.T) {
	var putBody []byte
	client := newTestClient(t, userSitesHandler(t, []int{2}, &putBody))

	alreadyMember, err := client.AddUserSite(context.Background(), 42, 2)
	if err != nil {
		t.Fatalf("AddUserSite: %v", err)
	}
	if !alreadyMember {
		t.Error("expected alreadyMember=true when the user already has the site")
	}
	if len(putBody) != 0 {
		t.Errorf("expected no PUT for an already-member add, got body: %s", putBody)
	}
}

func TestRemoveUserSite_IsMember_IssuesPUTReturnsFalse(t *testing.T) {
	var putBody []byte
	client := newTestClient(t, userSitesHandler(t, []int{1, 2}, &putBody))

	alreadyAbsent, err := client.RemoveUserSite(context.Background(), 42, 2)
	if err != nil {
		t.Fatalf("RemoveUserSite: %v", err)
	}
	if alreadyAbsent {
		t.Error("expected alreadyAbsent=false when the site is actually being removed")
	}
	if len(putBody) == 0 {
		t.Fatal("expected a PUT to be issued to remove the site")
	}
}

// TestRemoveUserSite_AlreadyAbsent_ReturnsTrueNoPUT covers the bool-return
// idempotency signal RemoveUserSite now surfaces (previously absorbed
// silently as a plain nil error), which site.go's Revoke keys off to report
// GrantAlreadyRevoked instead of a plain success.
func TestRemoveUserSite_AlreadyAbsent_ReturnsTrueNoPUT(t *testing.T) {
	var putBody []byte
	client := newTestClient(t, userSitesHandler(t, []int{1}, &putBody))

	alreadyAbsent, err := client.RemoveUserSite(context.Background(), 42, 2)
	if err != nil {
		t.Fatalf("RemoveUserSite: %v", err)
	}
	if !alreadyAbsent {
		t.Error("expected alreadyAbsent=true when the user never had the site")
	}
	if len(putBody) != 0 {
		t.Errorf("expected no PUT for an already-absent remove, got body: %s", putBody)
	}
}

// TestRemoveUserSite_UserDeleted_ReturnsTrueNoError covers the fix for the
// getUserDetails-404 case: if the user backing the revoke has since been
// deleted, the initial GET 404s, and RemoveUserSite must treat that as
// alreadyAbsent=true (a deleted user trivially has no site membership left
// to revoke) rather than propagating a hard error.
func TestRemoveUserSite_UserDeleted_ReturnsTrueNoError(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected method %s", r.Method)
		}
		w.WriteHeader(http.StatusNotFound)
	})

	alreadyAbsent, err := client.RemoveUserSite(context.Background(), 42, 2)
	if err != nil {
		t.Fatalf("RemoveUserSite: %v", err)
	}
	if !alreadyAbsent {
		t.Error("expected alreadyAbsent=true when the user has been deleted")
	}
}
