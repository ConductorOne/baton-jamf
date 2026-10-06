package jamf

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

// putOnlyHandler serves a bare PUT-capturing handler, failing the test if
// any other method is hit.
func putOnlyHandler(t *testing.T, gotPUTBody *[]byte) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Fatalf("unexpected method %s", r.Method)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read PUT body: %v", err)
		}
		*gotPUTBody = body
		w.WriteHeader(http.StatusCreated)
	}
}

// TestUpdateAccountPrivileges_MinimalBody_NoPrivileges covers the plain
// privilege-set write path: the PUT body must carry only <name> and
// <privilege_set> — no password, site, or privileges element at all — when
// privileges is nil.
func TestUpdateAccountPrivileges_MinimalBody_NoPrivileges(t *testing.T) {
	var putBody []byte
	client := newTestClient(t, putOnlyHandler(t, &putBody))

	if err := client.UpdateAccountPrivileges(context.Background(), 42, "jappleseed", "Administrator", nil); err != nil {
		t.Fatalf("UpdateAccountPrivileges: %v", err)
	}

	got := string(putBody)
	want := "<account><name>jappleseed</name><privilege_set>Administrator</privilege_set></account>"
	if got != want {
		t.Errorf("PUT body = %s, want %s", got, want)
	}
	for _, unwanted := range []string{"password", "<site>", "privileges", "full_name", "access_level"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("PUT body must not contain %q, got: %s", unwanted, got)
		}
	}
}

// TestUpdateAccountPrivileges_ExplicitEmptyPrivileges covers the Revoke
// path: a non-nil pointer to an all-empty Privileges must still emit an
// explicit <privileges></privileges> element rather than omitting it — a
// nil pointer and a non-nil-but-empty one must marshal differently, since
// omitting the element entirely leaves Jamf's stored privileges untouched
// (or, when transitioning into Custom, triggers a privilege-escalation copy
// of the previous set), while an explicit empty element clears them down to
// Jamf's floor.
func TestUpdateAccountPrivileges_ExplicitEmptyPrivileges(t *testing.T) {
	var putBody []byte
	client := newTestClient(t, putOnlyHandler(t, &putBody))

	if err := client.UpdateAccountPrivileges(context.Background(), 42, "jappleseed", "Custom", &Privileges{}); err != nil {
		t.Fatalf("UpdateAccountPrivileges: %v", err)
	}

	want := "<account><name>jappleseed</name><privilege_set>Custom</privilege_set><privileges></privileges></account>"
	if got := string(putBody); got != want {
		t.Errorf("PUT body = %s, want %s", got, want)
	}
}

// TestUpdateAccountPrivileges_WithPrivileges_OnlyPopulatedCategories covers
// granting an individual privilege: the <privileges> block must carry only
// the populated categories.
func TestUpdateAccountPrivileges_WithPrivileges_OnlyPopulatedCategories(t *testing.T) {
	var putBody []byte
	client := newTestClient(t, putOnlyHandler(t, &putBody))

	privileges := &Privileges{JSSObjects: []string{"Read User", "Update User"}}
	if err := client.UpdateAccountPrivileges(context.Background(), 42, "jappleseed", "Custom", privileges); err != nil {
		t.Fatalf("UpdateAccountPrivileges: %v", err)
	}

	want := "<account><name>jappleseed</name><privilege_set>Custom</privilege_set>" +
		"<privileges><jss_objects><privilege>Read User</privilege><privilege>Update User</privilege></jss_objects></privileges></account>"
	if got := string(putBody); got != want {
		t.Errorf("PUT body = %s, want %s", got, want)
	}
}

// TestUpdateAccountPrivileges_NoPrivilegeSet_OmitsElement covers a
// hypothetical bare-name write: PrivilegeSet empty must omit <privilege_set>
// entirely rather than send an empty element.
func TestUpdateAccountPrivileges_NoPrivilegeSet_OmitsElement(t *testing.T) {
	var putBody []byte
	client := newTestClient(t, putOnlyHandler(t, &putBody))

	if err := client.UpdateAccountPrivileges(context.Background(), 42, "jappleseed", "", nil); err != nil {
		t.Fatalf("UpdateAccountPrivileges: %v", err)
	}

	want := "<account><name>jappleseed</name></account>"
	if got := string(putBody); got != want {
		t.Errorf("PUT body = %s, want %s", got, want)
	}
}

// TestUpdateGroupPrivileges_MinimalBody_NeverSendsMembersOrSite covers
// group.go's sibling concern for Role writes: the PUT body must never carry
// <members> or <site>, since Role Grant/Revoke must never touch a group's
// membership.
func TestUpdateGroupPrivileges_MinimalBody_NeverSendsMembersOrSite(t *testing.T) {
	var putBody []byte
	client := newTestClient(t, putOnlyHandler(t, &putBody))

	if err := client.UpdateGroupPrivileges(context.Background(), 7, "Test Group", "Auditor", nil); err != nil {
		t.Fatalf("UpdateGroupPrivileges: %v", err)
	}

	got := string(putBody)
	want := "<group><name>Test Group</name><privilege_set>Auditor</privilege_set></group>"
	if got != want {
		t.Errorf("PUT body = %s, want %s", got, want)
	}
	for _, unwanted := range []string{"members", "<site>", "access_level"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("PUT body must not contain %q, got: %s", unwanted, got)
		}
	}
}

// TestUpdateGroupPrivileges_ExplicitEmptyPrivileges is
// TestUpdateAccountPrivileges_ExplicitEmptyPrivileges's group counterpart.
func TestUpdateGroupPrivileges_ExplicitEmptyPrivileges(t *testing.T) {
	var putBody []byte
	client := newTestClient(t, putOnlyHandler(t, &putBody))

	if err := client.UpdateGroupPrivileges(context.Background(), 7, "Test Group", "Custom", &Privileges{}); err != nil {
		t.Fatalf("UpdateGroupPrivileges: %v", err)
	}

	want := "<group><name>Test Group</name><privilege_set>Custom</privilege_set><privileges></privileges></group>"
	if got := string(putBody); got != want {
		t.Errorf("PUT body = %s, want %s", got, want)
	}
}

// TestRemoveUserSite_UserDeleted_ReturnsTrueNoError covers the fix for the
// getUserDetails-404 case: if the user backing the revoke has since been
// deleted, the initial GET 404s, and RemoveUserSite must treat that as
// alreadyAbsent=true (a deleted user trivially has no site membership left
// to revoke) rather than propagating a hard error.
// TestUpdateGroupMembers_NonEmpty_MinimalBody covers group.go's Grant/Revoke
// write path: the PUT body must carry only <name> and <members> — no
// access_level, privilege_set, or site — since resending those risks
// reintroducing a zero site (rejected with 409 on a live tenant) and isn't
// needed: the endpoint leaves them untouched when omitted.
func TestUpdateGroupMembers_NonEmpty_MinimalBody(t *testing.T) {
	var putBody []byte
	client := newTestClient(t, putOnlyHandler(t, &putBody))

	members := []BaseType{{ID: 10, Name: "jsmith"}, {ID: 11, Name: "jdoe"}}
	if err := client.UpdateGroupMembers(context.Background(), 7, "Test Group", members); err != nil {
		t.Fatalf("UpdateGroupMembers: %v", err)
	}

	got := string(putBody)
	want := "<group><name>Test Group</name><members><user><id>10</id><name>jsmith</name></user><user><id>11</id><name>jdoe</name></user></members></group>"
	if got != want {
		t.Errorf("PUT body = %s, want %s", got, want)
	}
	for _, unwanted := range []string{"access_level", "privilege_set", "<site>"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("PUT body must not resend %q, got: %s", unwanted, got)
		}
	}
}

// TestUpdateGroupMembers_EmptySlice_EmitsExplicitEmptyMembersElement covers
// the last-member-removal case: Members must be a non-nil pointer so an
// empty <members></members> element is emitted, not omitted — a nil slice
// under `xml:"members>user"` would omit the element entirely, which Jamf
// interprets as "leave members unchanged" rather than "clear members".
func TestUpdateGroupMembers_EmptySlice_EmitsExplicitEmptyMembersElement(t *testing.T) {
	var putBody []byte
	client := newTestClient(t, putOnlyHandler(t, &putBody))

	if err := client.UpdateGroupMembers(context.Background(), 7, "Test Group", []BaseType{}); err != nil {
		t.Fatalf("UpdateGroupMembers: %v", err)
	}

	got := string(putBody)
	want := "<group><name>Test Group</name><members></members></group>"
	if got != want {
		t.Errorf("PUT body = %s, want %s", got, want)
	}
}

// TestUpdateGroupMembers_NilSlice_AlsoEmitsExplicitEmptyMembersElement
// guards against a nil (rather than empty non-nil) members slice silently
// omitting the element instead — callers must get the explicit-clear
// behavior regardless of which kind of empty slice they pass.
func TestUpdateGroupMembers_NilSlice_AlsoEmitsExplicitEmptyMembersElement(t *testing.T) {
	var putBody []byte
	client := newTestClient(t, putOnlyHandler(t, &putBody))

	if err := client.UpdateGroupMembers(context.Background(), 7, "Test Group", nil); err != nil {
		t.Fatalf("UpdateGroupMembers: %v", err)
	}

	if want := "<members></members>"; !strings.Contains(string(putBody), want) {
		t.Errorf("PUT body missing %q, got: %s", want, string(putBody))
	}
}

// userDetailsHandler serves GET /JSSResource/users/id/{id}, counting hits and
// returning a name that changes on every real server hit, so tests can tell a
// cached response (name unchanged) from a fresh one (name changed).
func userDetailsHandler(t *testing.T, hits *int) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected method %s", r.Method)
		}
		*hits++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"user": map[string]any{"id": 42, "name": fmt.Sprintf("name-%d", *hits)},
		})
	}
}

// TestDoRequest_GETsAreCachedByDefault covers the baseline caching behavior
// that WithFreshReads must be able to bypass: two GETs of the same URL on a
// plain context hit the server once, with the second call served from the
// HTTP wrapper's cache.
func TestDoRequest_GETsAreCachedByDefault(t *testing.T) {
	var hits int
	client := newTestClient(t, userDetailsHandler(t, &hits))

	first, err := client.GetUserDetails(context.Background(), 42)
	if err != nil {
		t.Fatalf("GetUserDetails: %v", err)
	}
	second, err := client.GetUserDetails(context.Background(), 42)
	if err != nil {
		t.Fatalf("GetUserDetails: %v", err)
	}

	if hits != 1 {
		t.Fatalf("want 1 server hit (second GET served from cache), got %d", hits)
	}
	if first.Name != second.Name {
		t.Errorf("expected the cached response to be identical, got %q vs %q", first.Name, second.Name)
	}
}

// TestDoRequest_WithFreshReads_BypassesCache covers WithFreshReads: the same
// two GETs, but with ctx wrapped, must both reach the server and the second
// must observe the server's updated response rather than a cached one.
func TestDoRequest_WithFreshReads_BypassesCache(t *testing.T) {
	var hits int
	client := newTestClient(t, userDetailsHandler(t, &hits))
	ctx := WithFreshReads(context.Background())

	first, err := client.GetUserDetails(ctx, 42)
	if err != nil {
		t.Fatalf("GetUserDetails: %v", err)
	}
	second, err := client.GetUserDetails(ctx, 42)
	if err != nil {
		t.Fatalf("GetUserDetails: %v", err)
	}

	if hits != 2 {
		t.Fatalf("want 2 server hits (cache bypassed), got %d", hits)
	}
	if first.Name == second.Name {
		t.Errorf("expected the second read to reflect the server's updated response, got %q both times", first.Name)
	}
}

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
