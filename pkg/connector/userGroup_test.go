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
	"github.com/conductorone/baton-sdk/pkg/annotations"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
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
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user_group": map[string]any{"id": 5, "name": "Test Group", "is_smart": isSmart},
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
// best-guess idempotency mapping from architecture-plan.md §2.4/§9 item 1:
// a 404 from the PUT is treated as "already revoked", not an error.
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
	got := annotations.Annotations(annos)
	if ok, _ := got.Pick(&v2.GrantAlreadyRevoked{}); !ok {
		t.Error("expected a GrantAlreadyRevoked annotation for a 404 response")
	}
}

// TestUserGroupGrant_AlreadyMember_MapsToGrantAlreadyExists exercises the
// best-guess idempotency mapping from architecture-plan.md §2.4/§9 item 1:
// a 409 from the PUT is treated as "already a member", not an error.
func TestUserGroupGrant_AlreadyMember_MapsToGrantAlreadyExists(t *testing.T) {
	putCalled := false
	client := newTestJamfClient(t, jamfUserGroupHandler(t, false, http.StatusConflict, &putCalled))
	g := userGroupBuilder(client)

	grants, annos, err := g.Grant(context.Background(), userPrincipal(t, 1938), userGroupEntitlement(t, 5))
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if grants != nil {
		t.Errorf("expected no grants returned on the already-exists path, got %v", grants)
	}
	got := annotations.Annotations(annos)
	if ok, _ := got.Pick(&v2.GrantAlreadyExists{}); !ok {
		t.Error("expected a GrantAlreadyExists annotation for a 409 response")
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
