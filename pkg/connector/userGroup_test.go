package connector

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"testing"

	"github.com/conductorone/baton-jamf/pkg/jamf"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func userGroupEntitlement(t *testing.T, groupID int) *v2.Entitlement {
	t.Helper()
	resource, err := userGroupResource(&jamf.UserGroup{BaseType: jamf.BaseType{ID: groupID, Name: "Test Group"}}, nil)
	if err != nil {
		t.Fatalf("userGroupResource: %v", err)
	}
	return ent.NewAssignmentEntitlement(resource, memberEntitlement, ent.WithGrantableTo(resourceTypeUser))
}

func userPrincipal(t *testing.T, userID int) *v2.Resource {
	t.Helper()
	r, err := userResource(&jamf.User{BaseType: jamf.BaseType{ID: userID, Name: "jappleseed"}}, nil)
	if err != nil {
		t.Fatalf("userResource: %v", err)
	}
	return r
}

// jamfUserGroupHandler serves GET /JSSResource/usergroups/id/{id} returning
// is_smart, and PUT to the same path recording whether it was called. It
// returns putStatus for the PUT so tests can force idempotency-mapping paths
// (404/409) as well as the happy path.
func jamfUserGroupHandler(t *testing.T, isSmart bool, putStatus int, putCalled *bool) http.HandlerFunc {
	t.Helper()
	return jamfUserGroupHandlerWithMembers(t, isSmart, putStatus, nil, putCalled)
}

// jamfUserGroupHandlerWithMembers is jamfUserGroupHandler with control over
// the group's current membership (as returned by the GetUserGroupDetails GET
// used both by isSmartUserGroup and by Grant's post-409 re-verification), so
// tests can distinguish a genuine "already a member" 409 from some other
// validation failure that also happens to 409.
func jamfUserGroupHandlerWithMembers(t *testing.T, isSmart bool, putStatus int, memberIDs []int, putCalled *bool) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			users := make([]map[string]any, 0, len(memberIDs))
			for _, id := range memberIDs {
				users = append(users, map[string]any{"id": id, "name": "jappleseed"})
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user_group": map[string]any{"id": 5, "name": "Test Group", "is_smart": isSmart, "users": users},
			})
		case http.MethodPut:
			*putCalled = true
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read PUT body: %v", err)
			}
			var mutation jamf.UserGroupMemberMutation
			if err := xml.Unmarshal(body, &mutation); err != nil {
				t.Fatalf("unmarshal PUT body: %v", err)
			}
			w.WriteHeader(putStatus)
		default:
			t.Fatalf("unexpected method %s", r.Method)
		}
	}
}

func TestUserGroupGrant_StaticGroup_Succeeds(t *testing.T) {
	putCalled := false
	client := newTestJamfClient(t, jamfUserGroupHandler(t, false, http.StatusCreated, &putCalled))
	g := userGroupBuilder(client)

	grants, annos, err := g.Grant(context.Background(), userPrincipal(t, 1938), userGroupEntitlement(t, 5))
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if !putCalled {
		t.Error("expected PUT to be called for a static group")
	}
	if len(grants) != 1 {
		t.Fatalf("want 1 grant, got %d", len(grants))
	}
	if annos != nil {
		t.Errorf("expected no annotations on a plain success, got %v", annos)
	}
}

func TestUserGroupGrant_SmartGroup_RejectedWithoutCallingAPI(t *testing.T) {
	putCalled := false
	client := newTestJamfClient(t, jamfUserGroupHandler(t, true, http.StatusCreated, &putCalled))
	g := userGroupBuilder(client)

	_, _, err := g.Grant(context.Background(), userPrincipal(t, 1938), userGroupEntitlement(t, 5))
	if err == nil {
		t.Fatal("expected an error granting membership on a smart group")
	}
	if putCalled {
		t.Error("expected no mutating PUT call against a smart group")
	}
}

func TestUserGroupRevoke_SmartGroup_RejectedWithoutCallingAPI(t *testing.T) {
	putCalled := false
	client := newTestJamfClient(t, jamfUserGroupHandler(t, true, http.StatusCreated, &putCalled))
	g := userGroupBuilder(client)

	gr := grant.NewGrant(userGroupEntitlement(t, 5).Resource, memberEntitlement, userPrincipal(t, 1938).Id)
	_, err := g.Revoke(context.Background(), gr)
	if err == nil {
		t.Fatal("expected an error revoking membership on a smart group")
	}
	if putCalled {
		t.Error("expected no mutating PUT call against a smart group")
	}
}

func TestUserGroupRevoke_StaticGroup_Succeeds(t *testing.T) {
	putCalled := false
	client := newTestJamfClient(t, jamfUserGroupHandler(t, false, http.StatusOK, &putCalled))
	g := userGroupBuilder(client)

	gr := grant.NewGrant(userGroupEntitlement(t, 5).Resource, memberEntitlement, userPrincipal(t, 1938).Id)
	annos, err := g.Revoke(context.Background(), gr)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if !putCalled {
		t.Error("expected PUT to be called for a static group")
	}
	if annos != nil {
		t.Errorf("expected no annotations on a plain success, got %v", annos)
	}
}

// TestUserGroupRevoke_NonMember_MapsToGrantAlreadyRevoked exercises the
// idempotency mapping for Revoke: a 404 from the PUT is treated as "already
// revoked", not an error. This mapping is a best guess — unverified against
// a live Jamf tenant.
func TestUserGroupRevoke_NonMember_MapsToGrantAlreadyRevoked(t *testing.T) {
	putCalled := false
	client := newTestJamfClient(t, jamfUserGroupHandler(t, false, http.StatusNotFound, &putCalled))
	g := userGroupBuilder(client)

	gr := grant.NewGrant(userGroupEntitlement(t, 5).Resource, memberEntitlement, userPrincipal(t, 1938).Id)
	annos, err := g.Revoke(context.Background(), gr)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if !putCalled {
		t.Error("expected PUT to be attempted before the 404 short-circuits")
	}
	got := annos
	if ok, _ := got.Pick(&v2.GrantAlreadyRevoked{}); !ok {
		t.Error("expected a GrantAlreadyRevoked annotation for a 404 response")
	}
}

// TestUserGroupGrant_AlreadyMember_MapsToGrantAlreadyExists exercises the
// idempotency mapping for Grant: a 409 from the PUT is treated as "already a
// member", not an error — but only once re-verified against the group's
// actual membership (see the 409-disambiguation fix), so the fake group here
// already lists user 1938. This mapping is a best guess — unverified against
// a live Jamf tenant.
func TestUserGroupGrant_AlreadyMember_MapsToGrantAlreadyExists(t *testing.T) {
	putCalled := false
	client := newTestJamfClient(t, jamfUserGroupHandlerWithMembers(t, false, http.StatusConflict, []int{1938}, &putCalled))
	g := userGroupBuilder(client)

	grants, annos, err := g.Grant(context.Background(), userPrincipal(t, 1938), userGroupEntitlement(t, 5))
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if grants != nil {
		t.Errorf("expected no grants returned on the already-exists path, got %v", grants)
	}
	got := annos
	if ok, _ := got.Pick(&v2.GrantAlreadyExists{}); !ok {
		t.Error("expected a GrantAlreadyExists annotation for a 409 response backed by actual membership")
	}
}

// TestUserGroupGrant_ConflictButNotMember_ReturnsError covers the suggestion
// fix: Jamf's Classic API can 409 for reasons other than "already a member"
// (e.g. an unknown user id in user_additions). If the re-fetched group does
// NOT actually list the principal as a member, Grant must surface the
// original error instead of misreporting it as GrantAlreadyExists.
func TestUserGroupGrant_ConflictButNotMember_ReturnsError(t *testing.T) {
	putCalled := false
	// 409 response, but the re-fetched group has no members at all — user
	// 1938 is not actually in the group, so this wasn't a real
	// "already exists" conflict.
	client := newTestJamfClient(t, jamfUserGroupHandlerWithMembers(t, false, http.StatusConflict, nil, &putCalled))
	g := userGroupBuilder(client)

	grants, annos, err := g.Grant(context.Background(), userPrincipal(t, 1938), userGroupEntitlement(t, 5))
	if err == nil {
		t.Fatal("expected the original error to be surfaced when the 409 isn't backed by actual membership")
	}
	if grants != nil {
		t.Errorf("expected no grants returned, got %v", grants)
	}
	if annos != nil {
		t.Errorf("expected no GrantAlreadyExists annotation when membership can't be confirmed, got %v", annos)
	}
}

func TestUserGroupGrant_NonUserPrincipal_RejectedWithoutCallingAPI(t *testing.T) {
	putCalled := false
	client := newTestJamfClient(t, jamfUserGroupHandler(t, false, http.StatusCreated, &putCalled))
	g := userGroupBuilder(client)

	_, _, err := g.Grant(context.Background(), userGroupPrincipal(t, 7), userGroupEntitlement(t, 5))
	if err == nil {
		t.Fatal("expected an error granting user group membership to a non-user principal")
	}
	if putCalled {
		t.Error("expected no API call for a non-user principal")
	}
}

func TestUserGroupRevoke_NonUserPrincipal_RejectedWithoutCallingAPI(t *testing.T) {
	putCalled := false
	client := newTestJamfClient(t, jamfUserGroupHandler(t, false, http.StatusOK, &putCalled))
	g := userGroupBuilder(client)

	gr := grant.NewGrant(userGroupEntitlement(t, 5).Resource, memberEntitlement, userGroupPrincipal(t, 7).Id)
	_, err := g.Revoke(context.Background(), gr)
	if err == nil {
		t.Fatal("expected an error revoking user group membership from a non-user principal")
	}
	if putCalled {
		t.Error("expected no API call for a non-user principal")
	}
}

// TestUserGroupRevoke_DeletedGroup_MapsToGrantAlreadyRevoked exercises the
// isSmartUserGroup 404 path (Fix 2): the group backing the grant was deleted,
// so GetUserGroupDetails 404s before RemoveUserGroupMembers is ever called.
func TestUserGroupRevoke_DeletedGroup_MapsToGrantAlreadyRevoked(t *testing.T) {
	client := newTestJamfClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	g := userGroupBuilder(client)

	gr := grant.NewGrant(userGroupEntitlement(t, 5).Resource, memberEntitlement, userPrincipal(t, 1938).Id)
	annos, err := g.Revoke(context.Background(), gr)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if ok, _ := annos.Pick(&v2.GrantAlreadyRevoked{}); !ok {
		t.Errorf("expected a GrantAlreadyRevoked annotation for a deleted group, got %v", annos)
	}
}

func TestUserGroupGrant_InvalidGroupID_Errors(t *testing.T) {
	g := userGroupBuilder(nil)
	badEntitlement := ent.NewAssignmentEntitlement(&v2.Resource{Id: &v2.ResourceId{ResourceType: "userGroup", Resource: "not-a-number"}}, memberEntitlement)
	_, _, err := g.Grant(context.Background(), userPrincipal(t, 1938), badEntitlement)
	if err == nil {
		t.Fatal("expected an error for a non-numeric group id")
	}
}

// jamfUserGroupFlippingHandler serves GET /JSSResource/usergroups/id/{id},
// reporting is_smart=false on the first real server hit and is_smart=true on
// every hit after that — so a test can tell a cache-served GET (still sees
// the first, stale response) apart from one that actually reached the
// server again.
func jamfUserGroupFlippingHandler(t *testing.T, putCalled *int) http.HandlerFunc {
	t.Helper()
	hits := 0
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			hits++
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user_group": map[string]any{"id": 5, "name": "Test Group", "is_smart": hits > 1, "users": []map[string]any{}},
			})
		case http.MethodPut:
			*putCalled++
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected method %s", r.Method)
		}
	}
}

// TestUserGroupGrant_SecondCall_SeesServerSideIsSmartChange proves Grant's
// isSmartUserGroup check reads live server state on every independent call
// rather than a cached GET, now that ctx is wrapped with jamf.WithFreshReads:
// the group starts non-smart (first Grant succeeds and PUTs), then the mock
// server reports it as smart from the second GET onward — a second,
// independent Grant call must observe that and reject. Before the fix, the
// second call's GET would have been served from the HTTP cache with the
// first (stale, non-smart) response, and Grant would have incorrectly
// succeeded again.
func TestUserGroupGrant_SecondCall_SeesServerSideIsSmartChange(t *testing.T) {
	var putCalled int
	client := newTestJamfClient(t, jamfUserGroupFlippingHandler(t, &putCalled))
	g := userGroupBuilder(client)

	if _, _, err := g.Grant(context.Background(), userPrincipal(t, 42), userGroupEntitlement(t, 5)); err != nil {
		t.Fatalf("first Grant: %v", err)
	}
	if putCalled != 1 {
		t.Fatalf("want 1 PUT after the first Grant, got %d", putCalled)
	}

	_, _, err := g.Grant(context.Background(), userPrincipal(t, 43), userGroupEntitlement(t, 5))
	if err == nil {
		t.Fatal("expected the second Grant to reject once the group is smart server-side")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("expected FailedPrecondition, got %v", err)
	}
	if putCalled != 1 {
		t.Errorf("expected no additional PUT once the group is smart, got %d total", putCalled)
	}
}
