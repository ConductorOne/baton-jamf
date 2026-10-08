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
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
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
// returns putStatus for the PUT so tests can force a write failure (409) as
// well as the happy path.
func jamfUserGroupHandler(t *testing.T, isSmart bool, putStatus int, putCalled *bool) http.HandlerFunc {
	t.Helper()
	return jamfUserGroupHandlerWithMembers(t, isSmart, putStatus, nil, putCalled)
}

// jamfUserGroupHandlerWithMembers is jamfUserGroupHandler with control over
// the group's current membership (as returned by every GetUserGroupDetails
// GET), so tests can exercise Grant/Revoke's pre-write membership check.
func jamfUserGroupHandlerWithMembers(t *testing.T, isSmart bool, putStatus int, memberIDs []int, putCalled *bool) http.HandlerFunc {
	t.Helper()
	return jamfUserGroupStatefulHandler(t, isSmart, putStatus, memberIDs, memberIDs, putCalled)
}

// jamfUserGroupStatefulHandler serves GET /JSSResource/usergroups/id/{id},
// reporting membersBeforePut on the first GET and membersAfterPut on every
// GET thereafter. PUT records that it was called and returns putStatus.
func jamfUserGroupStatefulHandler(t *testing.T, isSmart bool, putStatus int, membersBeforePut, membersAfterPut []int, putCalled *bool) http.HandlerFunc {
	t.Helper()
	getCalls := 0
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			getCalls++
			members := membersBeforePut
			if getCalls > 1 {
				members = membersAfterPut
			}
			users := make([]map[string]any, 0, len(members))
			for _, id := range members {
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
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("expected FailedPrecondition, got %v", err)
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
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("expected FailedPrecondition, got %v", err)
	}
	if putCalled {
		t.Error("expected no mutating PUT call against a smart group")
	}
}

func TestUserGroupRevoke_StaticGroup_Succeeds(t *testing.T) {
	putCalled := false
	client := newTestJamfClient(t, jamfUserGroupHandlerWithMembers(t, false, http.StatusOK, []int{1938}, &putCalled))
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

// TestUserGroupRevoke_NotAMember_MapsToGrantAlreadyRevokedWithoutCallingAPI
// exercises Revoke's pre-write membership check: if the fresh GET already
// shows the principal isn't a member, Revoke reports GrantAlreadyRevoked
// without ever issuing the PUT.
func TestUserGroupRevoke_NotAMember_MapsToGrantAlreadyRevokedWithoutCallingAPI(t *testing.T) {
	putCalled := false
	client := newTestJamfClient(t, jamfUserGroupHandler(t, false, http.StatusConflict, &putCalled))
	g := userGroupBuilder(client)

	gr := grant.NewGrant(userGroupEntitlement(t, 5).Resource, memberEntitlement, userPrincipal(t, 1938).Id)
	annos, err := g.Revoke(context.Background(), gr)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if putCalled {
		t.Error("expected no PUT when the pre-write check already shows the principal isn't a member")
	}
	if ok, _ := annos.Pick(&v2.GrantAlreadyRevoked{}); !ok {
		t.Error("expected a GrantAlreadyRevoked annotation")
	}
}

// TestUserGroupRevoke_Conflict_ReturnsFailedPrecondition covers a 409 on the
// write: the pre-write read already ruled out "not a member", so Revoke
// surfaces the 409 as FailedPrecondition instead of assuming success.
func TestUserGroupRevoke_Conflict_ReturnsFailedPrecondition(t *testing.T) {
	putCalled := false
	client := newTestJamfClient(t, jamfUserGroupHandlerWithMembers(t, false, http.StatusConflict, []int{1938}, &putCalled))
	g := userGroupBuilder(client)

	gr := grant.NewGrant(userGroupEntitlement(t, 5).Resource, memberEntitlement, userPrincipal(t, 1938).Id)
	_, err := g.Revoke(context.Background(), gr)
	if err == nil {
		t.Fatal("expected an error for a 409 on the write")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("expected FailedPrecondition for a 409 on the write, got %v", err)
	}
	if !putCalled {
		t.Error("expected the PUT to be attempted since the pre-write check shows a member")
	}
}

// TestUserGroupGrant_AlreadyMember_MapsToGrantAlreadyExistsWithoutCallingAPI
// exercises Grant's pre-write membership check: if the fresh GET already
// shows the principal as a member, Grant reports GrantAlreadyExists without
// ever issuing the PUT.
func TestUserGroupGrant_AlreadyMember_MapsToGrantAlreadyExistsWithoutCallingAPI(t *testing.T) {
	putCalled := false
	client := newTestJamfClient(t, jamfUserGroupHandlerWithMembers(t, false, http.StatusConflict, []int{1938}, &putCalled))
	g := userGroupBuilder(client)

	grants, annos, err := g.Grant(context.Background(), userPrincipal(t, 1938), userGroupEntitlement(t, 5))
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if putCalled {
		t.Error("expected no PUT when the pre-write check already shows the principal as a member")
	}
	if grants != nil {
		t.Errorf("expected no grants returned on the already-exists path, got %v", grants)
	}
	got := annos
	if ok, _ := got.Pick(&v2.GrantAlreadyExists{}); !ok {
		t.Error("expected a GrantAlreadyExists annotation")
	}
}

// TestUserGroupGrant_Conflict_ReturnsFailedPrecondition covers a 409 on the
// write (e.g. a user deleted since the pre-write read): the read already
// ruled out "already a member", so Grant surfaces the 409 as
// FailedPrecondition instead of AlreadyExists or success.
func TestUserGroupGrant_Conflict_ReturnsFailedPrecondition(t *testing.T) {
	putCalled := false
	client := newTestJamfClient(t, jamfUserGroupHandler(t, false, http.StatusConflict, &putCalled))
	g := userGroupBuilder(client)

	grants, annos, err := g.Grant(context.Background(), userPrincipal(t, 1938), userGroupEntitlement(t, 5))
	if err == nil {
		t.Fatal("expected an error for a 409 on the write")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("expected FailedPrecondition for a 409 on the write, got %v", err)
	}
	if !putCalled {
		t.Error("expected the PUT to be attempted since the pre-write check shows no member")
	}
	if grants != nil {
		t.Errorf("expected no grants returned, got %v", grants)
	}
	if annos != nil {
		t.Errorf("expected no annotations on a write failure, got %v", annos)
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
// pre-write GET 404 path: the group backing the grant was deleted, so
// GetUserGroupDetails 404s before RemoveUserGroupMembers is ever called.
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

// TestUserGroupGrant_DeletedGroup_ReturnsNotFound exercises the pre-write
// GET 404 path on Grant: the group backing the entitlement was deleted, so
// GetUserGroupDetails 404s before AddUserGroupMembers is ever called.
func TestUserGroupGrant_DeletedGroup_ReturnsNotFound(t *testing.T) {
	client := newTestJamfClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	g := userGroupBuilder(client)

	_, _, err := g.Grant(context.Background(), userPrincipal(t, 1938), userGroupEntitlement(t, 5))
	if err == nil {
		t.Fatal("expected an error granting membership on a deleted group")
	}
	if status.Code(err) != codes.NotFound {
		t.Errorf("expected NotFound, got %v", err)
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
// smart-group check reads live server state on every independent call
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

// TestUserGroupGrants_SingleRead_BuildsPrincipalIDsFromMembers covers the
// sync Grants() path: it must emit a grant per member built directly from
// the group's own GetUserGroupDetails response, with a single GET and no
// member-by-member re-fetch.
func TestUserGroupGrants_SingleRead_BuildsPrincipalIDsFromMembers(t *testing.T) {
	var getCalls int
	client := newTestJamfClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected method %s", r.Method)
		}
		getCalls++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"user_group": map[string]any{"id": 5, "name": "Test Group", "is_smart": false, "users": []map[string]any{
				{"id": 10, "name": "jsmith"},
				{"id": 11, "name": "jdoe"},
			}},
		})
	})
	g := userGroupBuilder(client)

	resource, err := userGroupResource(&jamf.UserGroup{BaseType: jamf.BaseType{ID: 5, Name: "Test Group"}}, nil)
	if err != nil {
		t.Fatalf("userGroupResource: %v", err)
	}

	grants, _, err := g.Grants(context.Background(), resource, rs.SyncOpAttrs{})
	if err != nil {
		t.Fatalf("Grants: %v", err)
	}
	if len(grants) != 2 {
		t.Fatalf("want 2 grants, got %d", len(grants))
	}
	for i, wantID := range []string{"10", "11"} {
		p := grants[i].GetPrincipal().GetId()
		if p.GetResourceType() != resourceTypeUser.Id || p.GetResource() != wantID {
			t.Errorf("grant %d principal = %s:%s, want %s:%s", i, p.GetResourceType(), p.GetResource(), resourceTypeUser.Id, wantID)
		}
	}
	if getCalls != 1 {
		t.Errorf("want exactly 1 GET, got %d", getCalls)
	}
}
