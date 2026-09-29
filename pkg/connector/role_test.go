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

// TestMatchesIndividualPrivilege_CustomOnly guards against PR #28 review
// feedback: widening Privileges.Contains to all 7 categories must not grant
// individual-privilege roles to built-in-privilege-set accounts, even if
// their Privileges data happens to be populated.
func TestMatchesIndividualPrivilege_CustomOnly(t *testing.T) {
	populated := &jamf.Privileges{JSSObjects: []string{"Read User"}}

	tests := []struct {
		name         string
		privilegeSet string
		privileges   *jamf.Privileges
		privilege    string
		want         bool
	}{
		{"custom account with matching privilege", privilegeSetCustom, populated, "Read User", true},
		{"custom account without matching privilege", privilegeSetCustom, populated, "Update User", false},
		{"administrator account with populated privileges must not match", privilegeSetAdministrator, populated, "Read User", false},
		{"auditor account with populated privileges must not match", privilegeSetAuditor, populated, "Read User", false},
		{"enrollment only account with populated privileges must not match", privilegeSetEnrollmentOnly, populated, "Read User", false},
		{"custom account with empty privileges", privilegeSetCustom, &jamf.Privileges{}, "Read User", false},
		{"nil privileges", privilegeSetCustom, nil, "Read User", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesIndividualPrivilege(tt.privilegeSet, tt.privileges, tt.privilege)
			if got != tt.want {
				t.Errorf("matchesIndividualPrivilege(%q, %+v, %q) = %v, want %v", tt.privilegeSet, tt.privileges, tt.privilege, got, tt.want)
			}
		})
	}
}

func roleEntitlement(t *testing.T, privilegeSet string) *v2.Entitlement {
	t.Helper()
	resource, err := roleResource(context.Background(), privilegeSet, nil)
	if err != nil {
		t.Fatalf("roleResource: %v", err)
	}
	return ent.NewPermissionEntitlement(resource, memberEntitlement, ent.WithGrantableTo(resourceTypeUserAccount, resourceTypeGroup))
}

func userAccountPrincipal(t *testing.T, id int) *v2.Resource {
	t.Helper()
	r, err := userAccountResource(&jamf.UserAccount{BaseType: jamf.BaseType{ID: id, Name: "jappleseed"}}, nil)
	if err != nil {
		t.Fatalf("userAccountResource: %v", err)
	}
	return r
}

func groupPrincipal(t *testing.T, id int) *v2.Resource {
	t.Helper()
	r, err := groupResource(&jamf.Group{BaseType: jamf.BaseType{ID: id, Name: "Test Group"}}, nil)
	if err != nil {
		t.Fatalf("groupResource: %v", err)
	}
	return r
}

// jamfUserAccountHandler serves GET /JSSResource/accounts/userid/{id} with
// the given current privilege_set, and records the PUT body of any PUT to
// the same path so tests can assert Grant/Revoke's write (or its absence).
func jamfUserAccountHandler(t *testing.T, currentPrivilegeSet string, putCalled *bool, gotPUTBody *[]byte) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"account": map[string]any{"id": 42, "name": "jappleseed", "privilege_set": currentPrivilegeSet},
			})
		case http.MethodPut:
			*putCalled = true
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

// jamfGroupHandler is jamfUserAccountHandler's counterpart for
// /JSSResource/accounts/groupid/{id}.
func jamfGroupHandler(t *testing.T, currentPrivilegeSet string, putCalled *bool, gotPUTBody *[]byte) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"group": map[string]any{"id": 7, "name": "Test Group", "privilege_set": currentPrivilegeSet},
			})
		case http.MethodPut:
			*putCalled = true
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

func TestRoleGrant_UserAccount_SetsPrivilegeSet(t *testing.T) {
	putCalled := false
	var putBody []byte
	client := newTestJamfClient(t, jamfUserAccountHandler(t, privilegeSetAuditor, &putCalled, &putBody))
	r := roleBuilder(client)

	grants, annos, err := r.Grant(context.Background(), userAccountPrincipal(t, 42), roleEntitlement(t, privilegeSetAdministrator))
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if !putCalled {
		t.Error("expected a PUT to set the new privilege_set")
	}
	if !strings.Contains(string(putBody), "<privilege_set>Administrator</privilege_set>") {
		t.Errorf("expected PUT body to set privilege_set to Administrator, got: %s", putBody)
	}
	if len(grants) != 1 {
		t.Fatalf("want 1 grant, got %d", len(grants))
	}
	if annos != nil {
		t.Errorf("expected no annotations on a plain grant, got %v", annos)
	}
}

func TestRoleGrant_Group_SetsPrivilegeSet(t *testing.T) {
	putCalled := false
	var putBody []byte
	client := newTestJamfClient(t, jamfGroupHandler(t, privilegeSetAuditor, &putCalled, &putBody))
	r := roleBuilder(client)

	grants, annos, err := r.Grant(context.Background(), groupPrincipal(t, 7), roleEntitlement(t, privilegeSetAdministrator))
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if !putCalled {
		t.Error("expected a PUT to set the new privilege_set")
	}
	if !strings.Contains(string(putBody), "<privilege_set>Administrator</privilege_set>") {
		t.Errorf("expected PUT body to set privilege_set to Administrator, got: %s", putBody)
	}
	if len(grants) != 1 {
		t.Fatalf("want 1 grant, got %d", len(grants))
	}
	if annos != nil {
		t.Errorf("expected no annotations on a plain grant, got %v", annos)
	}
}

// TestRoleGrant_AlreadyHasPrivilegeSet_MapsToGrantAlreadyExists exercises the
// idempotency check: Grant reads the principal's current privilege_set
// before writing, and short-circuits to GrantAlreadyExists instead of
// re-sending an identical PUT.
func TestRoleGrant_AlreadyHasPrivilegeSet_MapsToGrantAlreadyExists(t *testing.T) {
	putCalled := false
	var putBody []byte
	client := newTestJamfClient(t, jamfUserAccountHandler(t, privilegeSetAdministrator, &putCalled, &putBody))
	r := roleBuilder(client)

	grants, annos, err := r.Grant(context.Background(), userAccountPrincipal(t, 42), roleEntitlement(t, privilegeSetAdministrator))
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if putCalled {
		t.Error("expected no PUT when the principal already holds this privilege set")
	}
	if len(grants) != 1 {
		t.Fatalf("expected the matching grant to still be returned, got %v", grants)
	}
	if ok, _ := annos.Pick(&v2.GrantAlreadyExists{}); !ok {
		t.Errorf("expected a GrantAlreadyExists annotation, got %v", annos)
	}
}

// TestRoleGrant_IndividualPrivilege_RejectedWithoutCallingAPI covers the
// confirmed-scope guard: individual privileges (meaningful only under a
// Custom privilege_set) are out of scope for Grant/Revoke.
func TestRoleGrant_IndividualPrivilege_RejectedWithoutCallingAPI(t *testing.T) {
	putCalled := false
	var putBody []byte
	client := newTestJamfClient(t, jamfUserAccountHandler(t, privilegeSetAuditor, &putCalled, &putBody))
	r := roleBuilder(client)

	_, _, err := r.Grant(context.Background(), userAccountPrincipal(t, 42), roleEntitlement(t, "Read User"))
	if err == nil {
		t.Fatal("expected an error granting an individual-privilege role")
	}
	if putCalled {
		t.Error("expected no API call for a rejected individual-privilege grant")
	}
}

func TestRoleGrant_NonUserAccountOrGroupPrincipal_Rejected(t *testing.T) {
	r := roleBuilder(nil)
	_, _, err := r.Grant(context.Background(), userPrincipal(t, 42), roleEntitlement(t, privilegeSetAdministrator))
	if err == nil {
		t.Fatal("expected an error granting a role to a non-userAccount/group principal")
	}
}

func TestRoleRevoke_UserAccount_SetsEnrollmentOnly(t *testing.T) {
	putCalled := false
	var putBody []byte
	client := newTestJamfClient(t, jamfUserAccountHandler(t, privilegeSetAdministrator, &putCalled, &putBody))
	r := roleBuilder(client)

	gr := grant.NewGrant(roleEntitlement(t, privilegeSetAdministrator).Resource, memberEntitlement, userAccountPrincipal(t, 42).Id)
	annos, err := r.Revoke(context.Background(), gr)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if !putCalled {
		t.Error("expected a PUT to downgrade to Enrollment Only")
	}
	if !strings.Contains(string(putBody), "<privilege_set>Enrollment Only</privilege_set>") {
		t.Errorf("expected PUT body to set privilege_set to Enrollment Only, got: %s", putBody)
	}
	if annos != nil {
		t.Errorf("expected no annotations on a plain revoke, got %v", annos)
	}
}

func TestRoleRevoke_Group_SetsEnrollmentOnly(t *testing.T) {
	putCalled := false
	var putBody []byte
	client := newTestJamfClient(t, jamfGroupHandler(t, privilegeSetAdministrator, &putCalled, &putBody))
	r := roleBuilder(client)

	gr := grant.NewGrant(roleEntitlement(t, privilegeSetAdministrator).Resource, memberEntitlement, groupPrincipal(t, 7).Id)
	annos, err := r.Revoke(context.Background(), gr)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if !putCalled {
		t.Error("expected a PUT to downgrade to Enrollment Only")
	}
	if !strings.Contains(string(putBody), "<privilege_set>Enrollment Only</privilege_set>") {
		t.Errorf("expected PUT body to set privilege_set to Enrollment Only, got: %s", putBody)
	}
	if annos != nil {
		t.Errorf("expected no annotations on a plain revoke, got %v", annos)
	}
}

// TestRoleRevoke_AlreadyEnrollmentOnly_MapsToGrantAlreadyRevoked exercises
// the idempotency check: Revoke reads the principal's current privilege_set
// before writing, and short-circuits to GrantAlreadyRevoked instead of
// re-sending an identical PUT.
func TestRoleRevoke_AlreadyEnrollmentOnly_MapsToGrantAlreadyRevoked(t *testing.T) {
	putCalled := false
	var putBody []byte
	client := newTestJamfClient(t, jamfUserAccountHandler(t, privilegeSetEnrollmentOnly, &putCalled, &putBody))
	r := roleBuilder(client)

	gr := grant.NewGrant(roleEntitlement(t, privilegeSetAdministrator).Resource, memberEntitlement, userAccountPrincipal(t, 42).Id)
	annos, err := r.Revoke(context.Background(), gr)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if putCalled {
		t.Error("expected no PUT when the principal is already Enrollment Only")
	}
	if ok, _ := annos.Pick(&v2.GrantAlreadyRevoked{}); !ok {
		t.Errorf("expected a GrantAlreadyRevoked annotation, got %v", annos)
	}
}

func TestRoleRevoke_NonUserAccountOrGroupPrincipal_Rejected(t *testing.T) {
	r := roleBuilder(nil)
	gr := grant.NewGrant(roleEntitlement(t, privilegeSetAdministrator).Resource, memberEntitlement, userPrincipal(t, 42).Id)
	_, err := r.Revoke(context.Background(), gr)
	if err == nil {
		t.Fatal("expected an error revoking a role from a non-userAccount/group principal")
	}
}
