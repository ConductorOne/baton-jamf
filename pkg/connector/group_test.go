package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/conductorone/baton-jamf/pkg/jamf"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
)

func groupEntitlement(t *testing.T, groupID int) *v2.Entitlement {
	t.Helper()
	resource, err := groupResource(&jamf.Group{BaseType: jamf.BaseType{ID: groupID, Name: "Test Group"}}, nil)
	if err != nil {
		t.Fatalf("groupResource: %v", err)
	}
	return ent.NewAssignmentEntitlement(resource, memberEntitlement, ent.WithGrantableTo(resourceTypeUserAccount))
}

// groupDetailsResponse builds the GET /JSSResource/accounts/groupid/{id}
// JSON body groupHandler serves, with members built from memberIDs.
func groupDetailsResponse(id int, name string, memberIDs []int) map[string]any {
	members := make([]map[string]any, 0, len(memberIDs))
	for _, m := range memberIDs {
		members = append(members, map[string]any{"id": m, "name": fmt.Sprintf("user%d", m)})
	}
	return map[string]any{
		"group": map[string]any{"id": id, "name": name, "members": members},
	}
}

// groupHandler serves GET /JSSResource/accounts/groupid/{id}, returning the
// n-th entry of getMemberSnapshots on the n-th GET (clamped to the last
// entry once exhausted — Grant issues a second GET after a successful PUT to
// verify the write actually took effect). Every PUT body received is
// appended to putBodies. The account GET Grant's Group Access guard now also
// issues (/JSSResource/accounts/userid/{id}) is routed to a Group Access
// account by default — see accountAccessLevelHandler and routeByPath for
// tests that need a different access level or a 404.
func groupHandler(t *testing.T, groupID int, groupName string, getMemberSnapshots [][]int, putBodies *[][]byte) http.HandlerFunc {
	t.Helper()
	return routeByPath(
		rawGroupHandler(t, groupID, groupName, getMemberSnapshots, putBodies),
		accountAccessLevelHandler(accessLevelGroupAccess),
	)
}

// rawGroupHandler is groupHandler without the account-endpoint routing, for
// tests that need to supply their own account handler (or none at all).
func rawGroupHandler(t *testing.T, groupID int, groupName string, getMemberSnapshots [][]int, putBodies *[][]byte) http.HandlerFunc {
	t.Helper()
	getCount := 0
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			idx := getCount
			if idx >= len(getMemberSnapshots) {
				idx = len(getMemberSnapshots) - 1
			}
			getCount++
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(groupDetailsResponse(groupID, groupName, getMemberSnapshots[idx]))
		case http.MethodPut:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read PUT body: %v", err)
			}
			*putBodies = append(*putBodies, body)
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected method %s", r.Method)
		}
	}
}

// accountAccessLevelHandler serves GET /JSSResource/accounts/userid/{id}
// with the given access_level — used to satisfy or deliberately fail Group
// Grant's Group Access guard.
func accountAccessLevelHandler(accessLevel string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"account": map[string]any{"id": 42, "name": "jappleseed", "access_level": accessLevel},
		})
	}
}

// accountNotFoundHandler serves a bare 404 for GET
// /JSSResource/accounts/userid/{id} — used to exercise Group Grant's
// account-not-found guard path.
func accountNotFoundHandler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected method %s", r.Method)
		}
		w.WriteHeader(http.StatusNotFound)
	}
}

// routeByPath dispatches to accountH for the account endpoint and groupH for
// everything else — Group Grant now issues a GET against both endpoints.
func routeByPath(groupH, accountH http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/accounts/userid/") {
			accountH(w, r)
			return
		}
		groupH(w, r)
	}
}

// groupNotFoundHandler serves a bare 404 for GET, failing the test on any
// write — used by the group-deleted test cases, which must never PUT.
func groupNotFoundHandler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected method %s, expected no write for a 404'd group", r.Method)
		}
		w.WriteHeader(http.StatusNotFound)
	}
}

// failOnCallHandler fails the test if the client ever makes a request —
// used to assert Grant/Revoke rejects an invalid principal type before
// touching the API at all.
func failOnCallHandler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected request %s %s; principal-type guard should reject before any API call", r.Method, r.URL.Path)
	}
}

func TestGroupGrant_Success(t *testing.T) {
	var putBodies [][]byte
	client := newTestJamfClient(t, groupHandler(t, 7, "Test Group", [][]int{{10}, {10, 42}}, &putBodies))
	g := groupBuilder(client)

	grants, annos, err := g.Grant(context.Background(), userAccountPrincipal(t, 42), groupEntitlement(t, 7))
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if len(putBodies) != 1 {
		t.Fatalf("want 1 PUT, got %d", len(putBodies))
	}
	if !strings.Contains(string(putBodies[0]), "<members><user><id>10</id>") || !strings.Contains(string(putBodies[0]), "<id>42</id>") {
		t.Errorf("expected PUT body to carry the existing member plus the new one, got: %s", putBodies[0])
	}
	if len(grants) != 1 {
		t.Fatalf("want 1 grant, got %d", len(grants))
	}
	if annos != nil {
		if ok, _ := annos.Pick(&v2.GrantAlreadyExists{}); ok {
			t.Error("fresh grant must not carry GrantAlreadyExists")
		}
	}
}

func TestGroupGrant_AlreadyMember_MapsToGrantAlreadyExists(t *testing.T) {
	var putBodies [][]byte
	client := newTestJamfClient(t, groupHandler(t, 7, "Test Group", [][]int{{10, 42}}, &putBodies))
	g := groupBuilder(client)

	_, annos, err := g.Grant(context.Background(), userAccountPrincipal(t, 42), groupEntitlement(t, 7))
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if len(putBodies) != 0 {
		t.Errorf("expected no PUT when the principal is already a member, got %d", len(putBodies))
	}
	if ok, _ := annos.Pick(&v2.GrantAlreadyExists{}); !ok {
		t.Errorf("expected GrantAlreadyExists, got %v", annos)
	}
}

func TestGroupGrant_EmptyMemberList_AbortsWithoutWrite(t *testing.T) {
	var putBodies [][]byte
	client := newTestJamfClient(t, groupHandler(t, 7, "Test Group", [][]int{{}}, &putBodies))
	g := groupBuilder(client)

	_, _, err := g.Grant(context.Background(), userAccountPrincipal(t, 42), groupEntitlement(t, 7))
	if err == nil {
		t.Fatal("expected an error when Jamf returns no members")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("expected FailedPrecondition, got %v", err)
	}
	if len(putBodies) != 0 {
		t.Errorf("expected no PUT when the member list is empty, got %d", len(putBodies))
	}
}

func TestGroupGrant_PrincipalNotAppliedAfterWrite_ReturnsError(t *testing.T) {
	var putBodies [][]byte
	// The post-PUT verification GET still comes back without the new member
	// (e.g. Jamf silently dropped it) — Grant must not report success.
	client := newTestJamfClient(t, groupHandler(t, 7, "Test Group", [][]int{{10}, {10}}, &putBodies))
	g := groupBuilder(client)

	_, _, err := g.Grant(context.Background(), userAccountPrincipal(t, 42), groupEntitlement(t, 7))
	if err == nil {
		t.Fatal("expected an error when the re-read doesn't show the new member")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("expected FailedPrecondition, got %v", err)
	}
	if len(putBodies) != 1 {
		t.Errorf("expected the PUT to still have been attempted, got %d", len(putBodies))
	}
}

func TestGroupGrant_Group404_MapsToNotFound(t *testing.T) {
	client := newTestJamfClient(t, groupNotFoundHandler(t))
	g := groupBuilder(client)

	_, _, err := g.Grant(context.Background(), userAccountPrincipal(t, 42), groupEntitlement(t, 7))
	if err == nil {
		t.Fatal("expected an error for a missing group")
	}
	if status.Code(err) != codes.NotFound {
		t.Errorf("expected NotFound, got %v", err)
	}
}

// TestGroupGrant_AccountFullAccess_Rejected covers the Group Access guard:
// a Full/Site Access account gains nothing from group membership, so Grant
// must reject it with FailedPrecondition before writing.
func TestGroupGrant_AccountFullAccess_Rejected(t *testing.T) {
	var putBodies [][]byte
	client := newTestJamfClient(t, routeByPath(
		rawGroupHandler(t, 7, "Test Group", [][]int{{10}}, &putBodies),
		accountAccessLevelHandler("Full Access"),
	))
	g := groupBuilder(client)

	_, _, err := g.Grant(context.Background(), userAccountPrincipal(t, 42), groupEntitlement(t, 7))
	if err == nil {
		t.Fatal("expected an error granting group membership to a Full Access account")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("expected FailedPrecondition, got %v", err)
	}
	if len(putBodies) != 0 {
		t.Error("expected no PUT for a Full Access account")
	}
}

// TestGroupGrant_AccountNotFound_MapsToNotFound covers the guard's own
// account lookup 404ing.
func TestGroupGrant_AccountNotFound_MapsToNotFound(t *testing.T) {
	var putBodies [][]byte
	client := newTestJamfClient(t, routeByPath(
		rawGroupHandler(t, 7, "Test Group", [][]int{{10}}, &putBodies),
		accountNotFoundHandler(t),
	))
	g := groupBuilder(client)

	_, _, err := g.Grant(context.Background(), userAccountPrincipal(t, 42), groupEntitlement(t, 7))
	if err == nil {
		t.Fatal("expected an error when the account backing the guard's lookup is missing")
	}
	if status.Code(err) != codes.NotFound {
		t.Errorf("expected NotFound, got %v", err)
	}
	if len(putBodies) != 0 {
		t.Error("expected no PUT when the account is missing")
	}
}

func TestGroupGrant_NonUserAccountPrincipal_Rejected(t *testing.T) {
	client := newTestJamfClient(t, failOnCallHandler(t))
	g := groupBuilder(client)

	_, _, err := g.Grant(context.Background(), groupPrincipal(t, 99), groupEntitlement(t, 7))
	if err == nil {
		t.Fatal("expected an error for a non-userAccount principal")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got %v", err)
	}
}

func TestGroupRevoke_Success(t *testing.T) {
	var putBodies [][]byte
	client := newTestJamfClient(t, groupHandler(t, 7, "Test Group", [][]int{{10, 42}}, &putBodies))
	g := groupBuilder(client)

	gr := groupRevokeGrant(t, 7, 42)
	annos, err := g.Revoke(context.Background(), gr)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if len(putBodies) != 1 {
		t.Fatalf("want 1 PUT, got %d", len(putBodies))
	}
	got := string(putBodies[0])
	if strings.Contains(got, "<id>42</id>") {
		t.Errorf("expected the revoked member to be gone from the PUT body, got: %s", got)
	}
	if !strings.Contains(got, "<id>10</id>") {
		t.Errorf("expected the remaining member to still be present, got: %s", got)
	}
	if annos != nil {
		if ok, _ := annos.Pick(&v2.GrantAlreadyRevoked{}); ok {
			t.Error("a fresh revoke must not carry GrantAlreadyRevoked")
		}
	}
}

func TestGroupRevoke_LastMember_ExplicitEmptyMembersElement(t *testing.T) {
	var putBodies [][]byte
	client := newTestJamfClient(t, groupHandler(t, 7, "Test Group", [][]int{{42}}, &putBodies))
	g := groupBuilder(client)

	gr := groupRevokeGrant(t, 7, 42)
	if _, err := g.Revoke(context.Background(), gr); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if len(putBodies) != 1 {
		t.Fatalf("want 1 PUT, got %d", len(putBodies))
	}
	if want := "<members></members>"; !strings.Contains(string(putBodies[0]), want) {
		t.Errorf("expected an explicit empty <members> element when removing the last member, got: %s", putBodies[0])
	}
}

func TestGroupRevoke_NotAMember_MapsToGrantAlreadyRevoked(t *testing.T) {
	var putBodies [][]byte
	client := newTestJamfClient(t, groupHandler(t, 7, "Test Group", [][]int{{10}}, &putBodies))
	g := groupBuilder(client)

	gr := groupRevokeGrant(t, 7, 42)
	annos, err := g.Revoke(context.Background(), gr)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if len(putBodies) != 0 {
		t.Errorf("expected no PUT when the principal is not a member, got %d", len(putBodies))
	}
	if ok, _ := annos.Pick(&v2.GrantAlreadyRevoked{}); !ok {
		t.Errorf("expected GrantAlreadyRevoked, got %v", annos)
	}
}

func TestGroupRevoke_EmptyMemberList_MapsToGrantAlreadyRevokedNoWrite(t *testing.T) {
	var putBodies [][]byte
	client := newTestJamfClient(t, groupHandler(t, 7, "Test Group", [][]int{{}}, &putBodies))
	g := groupBuilder(client)

	gr := groupRevokeGrant(t, 7, 42)
	annos, err := g.Revoke(context.Background(), gr)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if len(putBodies) != 0 {
		t.Errorf("expected no PUT when the member list is empty, got %d", len(putBodies))
	}
	if ok, _ := annos.Pick(&v2.GrantAlreadyRevoked{}); !ok {
		t.Errorf("expected GrantAlreadyRevoked, got %v", annos)
	}
}

func TestGroupRevoke_Group404_MapsToGrantAlreadyRevoked(t *testing.T) {
	client := newTestJamfClient(t, groupNotFoundHandler(t))
	g := groupBuilder(client)

	gr := groupRevokeGrant(t, 7, 42)
	annos, err := g.Revoke(context.Background(), gr)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if ok, _ := annos.Pick(&v2.GrantAlreadyRevoked{}); !ok {
		t.Errorf("expected GrantAlreadyRevoked for a deleted group, got %v", annos)
	}
}

func TestGroupRevoke_NonUserAccountPrincipal_Rejected(t *testing.T) {
	client := newTestJamfClient(t, failOnCallHandler(t))
	g := groupBuilder(client)

	gr := groupRevokeGrantForPrincipal(t, 7, groupPrincipal(t, 99))
	_, err := g.Revoke(context.Background(), gr)
	if err == nil {
		t.Fatal("expected an error for a non-userAccount principal")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got %v", err)
	}
}

// groupRevokeGrant builds a *v2.Grant naming groupID's member entitlement and
// userID as a userAccount principal, as role.go/userGroup.go's own tests do.
func groupRevokeGrant(t *testing.T, groupID int, userID int) *v2.Grant {
	t.Helper()
	return groupRevokeGrantForPrincipal(t, groupID, userAccountPrincipal(t, userID))
}

func groupRevokeGrantForPrincipal(t *testing.T, groupID int, principal *v2.Resource) *v2.Grant {
	t.Helper()
	return grant.NewGrant(groupEntitlement(t, groupID).Resource, memberEntitlement, principal.Id)
}
