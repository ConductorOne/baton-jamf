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
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

// accountRoleHandler serves GET /JSSResource/accounts/userid/{id} returning
// the n-th entry of snapshots on the n-th GET (clamped to the last entry once
// exhausted — Grant/Revoke re-read after a successful write to verify it took
// effect). Every PUT body received is appended to putBodies.
func accountRoleHandler(t *testing.T, id int, name string, snapshots []jamf.UserAccount, putBodies *[][]byte) http.HandlerFunc {
	t.Helper()
	getCount := 0
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			idx := getCount
			if idx >= len(snapshots) {
				idx = len(snapshots) - 1
			}
			getCount++
			snap := snapshots[idx]
			snap.ID = id
			snap.Name = name
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jamf.UserAccountResponse{UserAccount: snap})
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

// groupRoleHandler is accountRoleHandler's group counterpart, for
// /JSSResource/accounts/groupid/{id}.
func groupRoleHandler(t *testing.T, id int, name string, snapshots []jamf.Group, putBodies *[][]byte) http.HandlerFunc {
	t.Helper()
	getCount := 0
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			idx := getCount
			if idx >= len(snapshots) {
				idx = len(snapshots) - 1
			}
			getCount++
			snap := snapshots[idx]
			snap.ID = id
			snap.Name = name
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jamf.GroupResponse{Group: snap})
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

// ── Grant: privilege sets ────────────────────────────────────────────────

func TestRoleGrant_UserAccount_SetsPrivilegeSet(t *testing.T) {
	var putBodies [][]byte
	client := newTestJamfClient(t, accountRoleHandler(t, 42, "jappleseed", []jamf.UserAccount{
		{PrivilegeSet: privilegeSetAuditor},
		{PrivilegeSet: privilegeSetAdministrator},
	}, &putBodies))
	r := roleBuilder(client)

	grants, annos, err := r.Grant(context.Background(), userAccountPrincipal(t, 42), roleEntitlement(t, privilegeSetAdministrator))
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if len(putBodies) != 1 {
		t.Fatalf("want 1 PUT, got %d", len(putBodies))
	}
	if !strings.Contains(string(putBodies[0]), "<privilege_set>Administrator</privilege_set>") {
		t.Errorf("expected PUT body to set privilege_set to Administrator, got: %s", putBodies[0])
	}
	if strings.Contains(string(putBodies[0]), "<privileges>") || strings.Contains(string(putBodies[0]), "<site>") {
		t.Errorf("expected no privileges/site element when granting a built-in set, got: %s", putBodies[0])
	}
	if len(grants) != 1 {
		t.Fatalf("want 1 grant, got %d", len(grants))
	}
	replaced := &v2.GrantReplaced{}
	ok, err := annos.Pick(replaced)
	if err != nil {
		t.Fatalf("annos.Pick: %v", err)
	}
	if !ok {
		t.Fatalf("expected a GrantReplaced annotation displacing the previous Auditor grant, got %v", annos)
	}

	oldResource, err := roleResource(context.Background(), privilegeSetAuditor, nil)
	if err != nil {
		t.Fatalf("roleResource: %v", err)
	}
	oldEntitlement := ent.NewPermissionEntitlement(oldResource, memberEntitlement)
	wantReplacedID := grant.NewGrantID(userAccountPrincipal(t, 42).Id, oldEntitlement)
	if replaced.GetReplacedGrantId() != wantReplacedID {
		t.Errorf("GrantReplaced.ReplacedGrantId = %q, want %q", replaced.GetReplacedGrantId(), wantReplacedID)
	}
}

func TestRoleGrant_Group_SetsPrivilegeSet(t *testing.T) {
	var putBodies [][]byte
	client := newTestJamfClient(t, groupRoleHandler(t, 7, "Test Group", []jamf.Group{
		{PrivilegeSet: privilegeSetAuditor},
		{PrivilegeSet: privilegeSetAdministrator},
	}, &putBodies))
	r := roleBuilder(client)

	grants, annos, err := r.Grant(context.Background(), groupPrincipal(t, 7), roleEntitlement(t, privilegeSetAdministrator))
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if len(putBodies) != 1 {
		t.Fatalf("want 1 PUT, got %d", len(putBodies))
	}
	got := string(putBodies[0])
	if !strings.Contains(got, "<privilege_set>Administrator</privilege_set>") {
		t.Errorf("expected PUT body to set privilege_set to Administrator, got: %s", got)
	}
	for _, unwanted := range []string{"members", "<site>"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("group Role write must never send %q, got: %s", unwanted, got)
		}
	}
	if len(grants) != 1 {
		t.Fatalf("want 1 grant, got %d", len(grants))
	}
	if ok, _ := annos.Pick(&v2.GrantReplaced{}); !ok {
		t.Errorf("expected a GrantReplaced annotation displacing the previous Auditor grant, got %v", annos)
	}
}

// TestRoleGrant_EnrollmentOnly_IsGrantable covers the design change from the
// old fixed-floor model: Enrollment Only is now an independently grantable
// set like any other, not a dead end.
func TestRoleGrant_EnrollmentOnly_IsGrantable(t *testing.T) {
	var putBodies [][]byte
	client := newTestJamfClient(t, accountRoleHandler(t, 42, "jappleseed", []jamf.UserAccount{
		{PrivilegeSet: privilegeSetAdministrator},
		{PrivilegeSet: privilegeSetEnrollmentOnly},
	}, &putBodies))
	r := roleBuilder(client)

	grants, _, err := r.Grant(context.Background(), userAccountPrincipal(t, 42), roleEntitlement(t, privilegeSetEnrollmentOnly))
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if len(putBodies) != 1 {
		t.Fatalf("want 1 PUT, got %d", len(putBodies))
	}
	if len(grants) != 1 {
		t.Fatalf("want 1 grant, got %d", len(grants))
	}
}

func TestRoleGrant_NoGrantReplaced_WhenPreviouslyCustomOrUnassigned(t *testing.T) {
	for _, previous := range []string{privilegeSetCustom, ""} {
		t.Run(previous, func(t *testing.T) {
			var putBodies [][]byte
			client := newTestJamfClient(t, accountRoleHandler(t, 42, "jappleseed", []jamf.UserAccount{
				{PrivilegeSet: previous},
				{PrivilegeSet: privilegeSetAdministrator},
			}, &putBodies))
			r := roleBuilder(client)

			grants, annos, err := r.Grant(context.Background(), userAccountPrincipal(t, 42), roleEntitlement(t, privilegeSetAdministrator))
			if err != nil {
				t.Fatalf("Grant: %v", err)
			}
			if len(putBodies) != 1 {
				t.Error("expected a PUT to set the new privilege_set")
			}
			if len(grants) != 1 {
				t.Fatalf("want 1 grant, got %d", len(grants))
			}
			if annos != nil {
				t.Errorf("expected no annotations when the previous privilege_set was %q, got %v", previous, annos)
			}
		})
	}
}

func TestRoleGrant_AlreadyHasPrivilegeSet_MapsToGrantAlreadyExists(t *testing.T) {
	var putBodies [][]byte
	client := newTestJamfClient(t, accountRoleHandler(t, 42, "jappleseed", []jamf.UserAccount{
		{PrivilegeSet: privilegeSetAdministrator},
	}, &putBodies))
	r := roleBuilder(client)

	grants, annos, err := r.Grant(context.Background(), userAccountPrincipal(t, 42), roleEntitlement(t, privilegeSetAdministrator))
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if len(putBodies) != 0 {
		t.Error("expected no PUT when the principal already holds this privilege set")
	}
	if len(grants) != 1 {
		t.Fatalf("expected the matching grant to still be returned, got %v", grants)
	}
	if ok, _ := annos.Pick(&v2.GrantAlreadyExists{}); !ok {
		t.Errorf("expected a GrantAlreadyExists annotation, got %v", annos)
	}
}

func TestRoleGrant_PrivilegeSetNotApplied_ReturnsFailedPrecondition(t *testing.T) {
	var putBodies [][]byte
	// The post-PUT verification GET still shows the old privilege_set.
	client := newTestJamfClient(t, accountRoleHandler(t, 42, "jappleseed", []jamf.UserAccount{
		{PrivilegeSet: privilegeSetAuditor},
		{PrivilegeSet: privilegeSetAuditor},
	}, &putBodies))
	r := roleBuilder(client)

	_, _, err := r.Grant(context.Background(), userAccountPrincipal(t, 42), roleEntitlement(t, privilegeSetAdministrator))
	if err == nil {
		t.Fatal("expected an error when the re-read doesn't show the new privilege_set")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("expected FailedPrecondition, got %v", err)
	}
}

func TestRoleGrant_Deleted404_MapsToNotFound(t *testing.T) {
	for _, tc := range []struct {
		name      string
		principal *v2.Resource
	}{
		{"userAccount", userAccountPrincipal(t, 42)},
		{"group", groupPrincipal(t, 7)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := roleBuilder(newTestJamfClient(t, func(w http.ResponseWriter, req *http.Request) {
				if req.Method != http.MethodGet {
					t.Fatalf("unexpected method %s", req.Method)
				}
				w.WriteHeader(http.StatusNotFound)
			}))

			_, _, err := r.Grant(context.Background(), tc.principal, roleEntitlement(t, privilegeSetAdministrator))
			if err == nil {
				t.Fatal("expected an error for a missing principal")
			}
			if status.Code(err) != codes.NotFound {
				t.Errorf("expected NotFound, got %v", err)
			}
		})
	}
}

func TestRoleGrant_GroupAccessAccount_Rejected(t *testing.T) {
	var putBodies [][]byte
	client := newTestJamfClient(t, accountRoleHandler(t, 42, "jappleseed", []jamf.UserAccount{
		{PrivilegeSet: privilegeSetAuditor, AccessLevel: accessLevelGroupAccess},
	}, &putBodies))
	r := roleBuilder(client)

	_, _, err := r.Grant(context.Background(), userAccountPrincipal(t, 42), roleEntitlement(t, privilegeSetAdministrator))
	if err == nil {
		t.Fatal("expected an error granting a role to a Group Access account")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("expected FailedPrecondition, got %v", err)
	}
	if len(putBodies) != 0 {
		t.Error("expected no PUT for a Group Access account")
	}
}

func TestRoleGrant_NonUserAccountOrGroupPrincipal_Rejected(t *testing.T) {
	r := roleBuilder(newTestJamfClient(t, failOnCallHandler(t)))
	_, _, err := r.Grant(context.Background(), userPrincipal(t, 42), roleEntitlement(t, privilegeSetAdministrator))
	if err == nil {
		t.Fatal("expected an error granting a role to a non-userAccount/group principal")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got %v", err)
	}
}

// ── Grant: individual privileges ─────────────────────────────────────────

func TestRoleGrant_IndividualPrivilege_Success(t *testing.T) {
	var putBodies [][]byte
	client := newTestJamfClient(t, accountRoleHandler(t, 42, "jappleseed", []jamf.UserAccount{
		{PrivilegeSet: privilegeSetCustom, Privileges: jamf.Privileges{JSSObjects: []string{"Read User"}}},
		{PrivilegeSet: privilegeSetCustom, Privileges: jamf.Privileges{JSSObjects: []string{"Read User", "Update User"}}},
	}, &putBodies))
	r := roleBuilder(client)

	grants, annos, err := r.Grant(context.Background(), userAccountPrincipal(t, 42), roleEntitlement(t, "Update User"))
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if len(putBodies) != 1 {
		t.Fatalf("want 1 PUT, got %d", len(putBodies))
	}
	got := string(putBodies[0])
	if !strings.Contains(got, "<privilege_set>Custom</privilege_set>") {
		t.Errorf("expected PUT body to set privilege_set to Custom, got: %s", got)
	}
	if !strings.Contains(got, "<privileges>") || !strings.Contains(got, "Update User") || !strings.Contains(got, "Read User") {
		t.Errorf("expected PUT body to carry the existing privilege plus the new one, got: %s", got)
	}
	if len(grants) != 1 {
		t.Fatalf("want 1 grant, got %d", len(grants))
	}
	if annos != nil {
		t.Errorf("expected no annotations on a fresh individual-privilege grant, got %v", annos)
	}
}

func TestRoleGrant_IndividualPrivilege_Group_Success(t *testing.T) {
	var putBodies [][]byte
	client := newTestJamfClient(t, groupRoleHandler(t, 7, "Test Group", []jamf.Group{
		{PrivilegeSet: privilegeSetCustom},
		{PrivilegeSet: privilegeSetCustom, Privileges: jamf.Privileges{JSSObjects: []string{"Read User"}}},
	}, &putBodies))
	r := roleBuilder(client)

	grants, _, err := r.Grant(context.Background(), groupPrincipal(t, 7), roleEntitlement(t, "Read User"))
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if len(putBodies) != 1 {
		t.Fatalf("want 1 PUT, got %d", len(putBodies))
	}
	got := string(putBodies[0])
	for _, unwanted := range []string{"members", "<site>"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("group Role write must never send %q, got: %s", unwanted, got)
		}
	}
	if len(grants) != 1 {
		t.Fatalf("want 1 grant, got %d", len(grants))
	}
}

func TestRoleGrant_IndividualPrivilege_AlreadyHeld_MapsToGrantAlreadyExists(t *testing.T) {
	var putBodies [][]byte
	client := newTestJamfClient(t, accountRoleHandler(t, 42, "jappleseed", []jamf.UserAccount{
		{PrivilegeSet: privilegeSetCustom, Privileges: jamf.Privileges{JSSObjects: []string{"Read User"}}},
	}, &putBodies))
	r := roleBuilder(client)

	grants, annos, err := r.Grant(context.Background(), userAccountPrincipal(t, 42), roleEntitlement(t, "Read User"))
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if len(putBodies) != 0 {
		t.Error("expected no PUT when the privilege is already held")
	}
	if len(grants) != 1 {
		t.Fatalf("want 1 grant, got %d", len(grants))
	}
	if ok, _ := annos.Pick(&v2.GrantAlreadyExists{}); !ok {
		t.Errorf("expected a GrantAlreadyExists annotation, got %v", annos)
	}
}

func TestRoleGrant_IndividualPrivilege_NotCustom_Rejected(t *testing.T) {
	var putBodies [][]byte
	client := newTestJamfClient(t, accountRoleHandler(t, 42, "jappleseed", []jamf.UserAccount{
		{PrivilegeSet: privilegeSetAuditor},
	}, &putBodies))
	r := roleBuilder(client)

	_, _, err := r.Grant(context.Background(), userAccountPrincipal(t, 42), roleEntitlement(t, "Read User"))
	if err == nil {
		t.Fatal("expected an error granting an individual privilege to a non-Custom principal")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("expected FailedPrecondition, got %v", err)
	}
	if len(putBodies) != 0 {
		t.Error("expected no PUT for a rejected individual-privilege grant")
	}
}

func TestRoleGrant_IndividualPrivilege_NotApplied_ReturnsFailedPrecondition(t *testing.T) {
	var putBodies [][]byte
	// Jamf silently drops the unrecognized privilege name — the verification
	// GET comes back without it.
	client := newTestJamfClient(t, accountRoleHandler(t, 42, "jappleseed", []jamf.UserAccount{
		{PrivilegeSet: privilegeSetCustom},
		{PrivilegeSet: privilegeSetCustom},
	}, &putBodies))
	r := roleBuilder(client)

	_, _, err := r.Grant(context.Background(), userAccountPrincipal(t, 42), roleEntitlement(t, "Read Knobs"))
	if err == nil {
		t.Fatal("expected an error when Jamf doesn't apply the privilege")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("expected FailedPrecondition, got %v", err)
	}
	if len(putBodies) != 1 {
		t.Errorf("expected the PUT to still have been attempted, got %d", len(putBodies))
	}
}

func TestRoleGrant_IndividualPrivilege_GroupAccessAccount_Rejected(t *testing.T) {
	client := newTestJamfClient(t, accountRoleHandler(t, 42, "jappleseed", []jamf.UserAccount{
		{PrivilegeSet: privilegeSetCustom, AccessLevel: accessLevelGroupAccess},
	}, &[][]byte{}))
	r := roleBuilder(client)

	_, _, err := r.Grant(context.Background(), userAccountPrincipal(t, 42), roleEntitlement(t, "Read User"))
	if err == nil {
		t.Fatal("expected an error granting an individual privilege to a Group Access account")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("expected FailedPrecondition, got %v", err)
	}
}

// ── Revoke: privilege sets ───────────────────────────────────────────────

func TestRoleRevoke_UserAccount_MovesToCustomWithExplicitEmptyBlock(t *testing.T) {
	var putBodies [][]byte
	client := newTestJamfClient(t, accountRoleHandler(t, 42, "jappleseed", []jamf.UserAccount{
		{PrivilegeSet: privilegeSetAdministrator},
		{PrivilegeSet: privilegeSetCustom},
	}, &putBodies))
	r := roleBuilder(client)

	gr := grant.NewGrant(roleEntitlement(t, privilegeSetAdministrator).Resource, memberEntitlement, userAccountPrincipal(t, 42).Id)
	annos, err := r.Revoke(context.Background(), gr)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if len(putBodies) != 1 {
		t.Fatalf("want 1 PUT, got %d", len(putBodies))
	}
	got := string(putBodies[0])
	want := "<account><name>jappleseed</name><privilege_set>Custom</privilege_set><privileges></privileges></account>"
	if got != want {
		t.Errorf("PUT body = %s, want %s", got, want)
	}
	if annos != nil {
		t.Errorf("expected no annotations on a plain revoke, got %v", annos)
	}
}

func TestRoleRevoke_Group_MovesToCustomWithExplicitEmptyBlock(t *testing.T) {
	var putBodies [][]byte
	client := newTestJamfClient(t, groupRoleHandler(t, 7, "Test Group", []jamf.Group{
		{PrivilegeSet: privilegeSetAdministrator},
		{PrivilegeSet: privilegeSetCustom},
	}, &putBodies))
	r := roleBuilder(client)

	gr := grant.NewGrant(roleEntitlement(t, privilegeSetAdministrator).Resource, memberEntitlement, groupPrincipal(t, 7).Id)
	annos, err := r.Revoke(context.Background(), gr)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if len(putBodies) != 1 {
		t.Fatalf("want 1 PUT, got %d", len(putBodies))
	}
	got := string(putBodies[0])
	want := "<group><name>Test Group</name><privilege_set>Custom</privilege_set><privileges></privileges></group>"
	if got != want {
		t.Errorf("PUT body = %s, want %s", got, want)
	}
	if annos != nil {
		t.Errorf("expected no annotations on a plain revoke, got %v", annos)
	}
}

func TestRoleRevoke_EnrollmentOnly_IsRevocable(t *testing.T) {
	var putBodies [][]byte
	client := newTestJamfClient(t, accountRoleHandler(t, 42, "jappleseed", []jamf.UserAccount{
		{PrivilegeSet: privilegeSetEnrollmentOnly},
		{PrivilegeSet: privilegeSetCustom},
	}, &putBodies))
	r := roleBuilder(client)

	gr := grant.NewGrant(roleEntitlement(t, privilegeSetEnrollmentOnly).Resource, memberEntitlement, userAccountPrincipal(t, 42).Id)
	if _, err := r.Revoke(context.Background(), gr); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if len(putBodies) != 1 {
		t.Fatalf("want 1 PUT, got %d", len(putBodies))
	}
}

func TestRoleRevoke_StalePrivilegeSet_NoWrite(t *testing.T) {
	var putBodies [][]byte
	client := newTestJamfClient(t, accountRoleHandler(t, 42, "jappleseed", []jamf.UserAccount{
		{PrivilegeSet: privilegeSetAuditor},
	}, &putBodies))
	r := roleBuilder(client)

	gr := grant.NewGrant(roleEntitlement(t, privilegeSetAdministrator).Resource, memberEntitlement, userAccountPrincipal(t, 42).Id)
	annos, err := r.Revoke(context.Background(), gr)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if len(putBodies) != 0 {
		t.Error("expected no PUT when the account has since moved to a different privilege set")
	}
	if ok, _ := annos.Pick(&v2.GrantAlreadyRevoked{}); !ok {
		t.Errorf("expected a GrantAlreadyRevoked annotation, got %v", annos)
	}
}

func TestRoleRevoke_PrivilegeSetNotMovedToCustom_ReturnsFailedPrecondition(t *testing.T) {
	var putBodies [][]byte
	client := newTestJamfClient(t, accountRoleHandler(t, 42, "jappleseed", []jamf.UserAccount{
		{PrivilegeSet: privilegeSetAdministrator},
		{PrivilegeSet: privilegeSetAdministrator},
	}, &putBodies))
	r := roleBuilder(client)

	gr := grant.NewGrant(roleEntitlement(t, privilegeSetAdministrator).Resource, memberEntitlement, userAccountPrincipal(t, 42).Id)
	_, err := r.Revoke(context.Background(), gr)
	if err == nil {
		t.Fatal("expected an error when the re-read doesn't show Custom")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("expected FailedPrecondition, got %v", err)
	}
}

func TestRoleRevoke_Deleted404_MapsToGrantAlreadyRevoked(t *testing.T) {
	for _, tc := range []struct {
		name      string
		principal *v2.Resource
	}{
		{"userAccount", userAccountPrincipal(t, 42)},
		{"group", groupPrincipal(t, 7)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := roleBuilder(newTestJamfClient(t, func(w http.ResponseWriter, req *http.Request) {
				if req.Method != http.MethodGet {
					t.Fatalf("unexpected method %s", req.Method)
				}
				w.WriteHeader(http.StatusNotFound)
			}))

			gr := grant.NewGrant(roleEntitlement(t, privilegeSetAdministrator).Resource, memberEntitlement, tc.principal.Id)
			annos, err := r.Revoke(context.Background(), gr)
			if err != nil {
				t.Fatalf("Revoke: %v", err)
			}
			if ok, _ := annos.Pick(&v2.GrantAlreadyRevoked{}); !ok {
				t.Errorf("expected a GrantAlreadyRevoked annotation when the principal has been deleted, got %v", annos)
			}
		})
	}
}

func TestRoleRevoke_GroupAccessAccount_Rejected(t *testing.T) {
	var putBodies [][]byte
	client := newTestJamfClient(t, accountRoleHandler(t, 42, "jappleseed", []jamf.UserAccount{
		{PrivilegeSet: privilegeSetAdministrator, AccessLevel: accessLevelGroupAccess},
	}, &putBodies))
	r := roleBuilder(client)

	gr := grant.NewGrant(roleEntitlement(t, privilegeSetAdministrator).Resource, memberEntitlement, userAccountPrincipal(t, 42).Id)
	_, err := r.Revoke(context.Background(), gr)
	if err == nil {
		t.Fatal("expected an error revoking a role from a Group Access account")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("expected FailedPrecondition, got %v", err)
	}
	if len(putBodies) != 0 {
		t.Error("expected no PUT for a Group Access account")
	}
}

func TestRoleRevoke_NonUserAccountOrGroupPrincipal_Rejected(t *testing.T) {
	r := roleBuilder(newTestJamfClient(t, failOnCallHandler(t)))
	gr := grant.NewGrant(roleEntitlement(t, privilegeSetAdministrator).Resource, memberEntitlement, userPrincipal(t, 42).Id)
	_, err := r.Revoke(context.Background(), gr)
	if err == nil {
		t.Fatal("expected an error revoking a role from a non-userAccount/group principal")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got %v", err)
	}
}

// ── Revoke: individual privileges ────────────────────────────────────────

func TestRoleRevoke_IndividualPrivilege_Success(t *testing.T) {
	var putBodies [][]byte
	client := newTestJamfClient(t, accountRoleHandler(t, 42, "jappleseed", []jamf.UserAccount{
		{PrivilegeSet: privilegeSetCustom, Privileges: jamf.Privileges{JSSObjects: []string{"Read User", "Update User"}}},
		{PrivilegeSet: privilegeSetCustom, Privileges: jamf.Privileges{JSSObjects: []string{"Read User"}}},
	}, &putBodies))
	r := roleBuilder(client)

	gr := grant.NewGrant(roleEntitlement(t, "Update User").Resource, memberEntitlement, userAccountPrincipal(t, 42).Id)
	annos, err := r.Revoke(context.Background(), gr)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if len(putBodies) != 1 {
		t.Fatalf("want 1 PUT, got %d", len(putBodies))
	}
	got := string(putBodies[0])
	if strings.Contains(got, "Update User") {
		t.Errorf("expected the revoked privilege to be gone from the PUT body, got: %s", got)
	}
	if !strings.Contains(got, "Read User") {
		t.Errorf("expected the remaining privilege to still be present, got: %s", got)
	}
	if annos != nil {
		t.Errorf("expected no annotations on a fresh individual-privilege revoke, got %v", annos)
	}
}

// TestRoleRevoke_IndividualPrivilege_LastOne_ExplicitEmptyBlock covers
// removing the last remaining individual privilege: the PUT body must still
// carry an explicit, empty <privileges> block rather than omitting the
// element (which would leave Jamf's stored privileges untouched instead of
// clearing them).
func TestRoleRevoke_IndividualPrivilege_LastOne_ExplicitEmptyBlock(t *testing.T) {
	var putBodies [][]byte
	client := newTestJamfClient(t, accountRoleHandler(t, 42, "jappleseed", []jamf.UserAccount{
		{PrivilegeSet: privilegeSetCustom, Privileges: jamf.Privileges{JSSObjects: []string{"Read User"}}},
		{PrivilegeSet: privilegeSetCustom},
	}, &putBodies))
	r := roleBuilder(client)

	gr := grant.NewGrant(roleEntitlement(t, "Read User").Resource, memberEntitlement, userAccountPrincipal(t, 42).Id)
	if _, err := r.Revoke(context.Background(), gr); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if len(putBodies) != 1 {
		t.Fatalf("want 1 PUT, got %d", len(putBodies))
	}
	want := "<account><name>jappleseed</name><privilege_set>Custom</privilege_set><privileges></privileges></account>"
	if got := string(putBodies[0]); got != want {
		t.Errorf("PUT body = %s, want %s", got, want)
	}
}

func TestRoleRevoke_IndividualPrivilege_NotHeld_MapsToGrantAlreadyRevoked(t *testing.T) {
	var putBodies [][]byte
	client := newTestJamfClient(t, accountRoleHandler(t, 42, "jappleseed", []jamf.UserAccount{
		{PrivilegeSet: privilegeSetCustom, Privileges: jamf.Privileges{JSSObjects: []string{"Read User"}}},
	}, &putBodies))
	r := roleBuilder(client)

	gr := grant.NewGrant(roleEntitlement(t, "Update User").Resource, memberEntitlement, userAccountPrincipal(t, 42).Id)
	annos, err := r.Revoke(context.Background(), gr)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if len(putBodies) != 0 {
		t.Error("expected no PUT when the privilege isn't held")
	}
	if ok, _ := annos.Pick(&v2.GrantAlreadyRevoked{}); !ok {
		t.Errorf("expected a GrantAlreadyRevoked annotation, got %v", annos)
	}
}

func TestRoleRevoke_IndividualPrivilege_NotCustom_MapsToGrantAlreadyRevoked(t *testing.T) {
	var putBodies [][]byte
	client := newTestJamfClient(t, accountRoleHandler(t, 42, "jappleseed", []jamf.UserAccount{
		{PrivilegeSet: privilegeSetAdministrator},
	}, &putBodies))
	r := roleBuilder(client)

	gr := grant.NewGrant(roleEntitlement(t, "Read User").Resource, memberEntitlement, userAccountPrincipal(t, 42).Id)
	annos, err := r.Revoke(context.Background(), gr)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if len(putBodies) != 0 {
		t.Error("expected no PUT when the principal isn't Custom")
	}
	if ok, _ := annos.Pick(&v2.GrantAlreadyRevoked{}); !ok {
		t.Errorf("expected a GrantAlreadyRevoked annotation, got %v", annos)
	}
}

func TestRoleRevoke_ReadLicenseInformation_Rejected(t *testing.T) {
	var putBodies [][]byte
	client := newTestJamfClient(t, accountRoleHandler(t, 42, "jappleseed", []jamf.UserAccount{
		{PrivilegeSet: privilegeSetCustom, Privileges: jamf.Privileges{JSSObjects: []string{privilegeReadLicenseInformation}}},
	}, &putBodies))
	r := roleBuilder(client)

	gr := grant.NewGrant(roleEntitlement(t, privilegeReadLicenseInformation).Resource, memberEntitlement, userAccountPrincipal(t, 42).Id)
	_, err := r.Revoke(context.Background(), gr)
	if err == nil {
		t.Fatal("expected an error revoking Read License Information")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("expected FailedPrecondition, got %v", err)
	}
	if !strings.Contains(err.Error(), privilegeReadLicenseInformation) || !strings.Contains(err.Error(), "jappleseed") {
		t.Errorf("expected error to name both the privilege and the principal, got %v", err)
	}
	if len(putBodies) != 0 {
		t.Error("expected no PUT revoking Read License Information")
	}
}

func TestRoleRevoke_IndividualPrivilege_NotRemoved_ReturnsFailedPrecondition(t *testing.T) {
	var putBodies [][]byte
	// The verification GET still shows the privilege present.
	client := newTestJamfClient(t, accountRoleHandler(t, 42, "jappleseed", []jamf.UserAccount{
		{PrivilegeSet: privilegeSetCustom, Privileges: jamf.Privileges{JSSObjects: []string{"Read User"}}},
		{PrivilegeSet: privilegeSetCustom, Privileges: jamf.Privileges{JSSObjects: []string{"Read User"}}},
	}, &putBodies))
	r := roleBuilder(client)

	gr := grant.NewGrant(roleEntitlement(t, "Read User").Resource, memberEntitlement, userAccountPrincipal(t, 42).Id)
	_, err := r.Revoke(context.Background(), gr)
	if err == nil {
		t.Fatal("expected an error when Jamf doesn't remove the privilege")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("expected FailedPrecondition, got %v", err)
	}
}

// ── Entitlements ──────────────────────────────────────────────────────────

// TestRoleEntitlements_AllGrantableToBothPrincipalTypes covers the design
// change: all three built-in sets AND individual privileges are grantable to
// both userAccount and group — there is no longer a restricted subset.
func TestRoleEntitlements_AllGrantableToBothPrincipalTypes(t *testing.T) {
	r := roleBuilder(nil)
	for _, roleID := range append(append([]string{}, privilegeSets...), "Read User") {
		t.Run(roleID, func(t *testing.T) {
			res, err := roleResource(context.Background(), roleID, nil)
			if err != nil {
				t.Fatalf("roleResource: %v", err)
			}
			ents, _, err := r.Entitlements(context.Background(), res, rs.SyncOpAttrs{})
			if err != nil {
				t.Fatalf("Entitlements: %v", err)
			}
			if len(ents) != 1 {
				t.Fatalf("want 1 entitlement, got %d", len(ents))
			}
			grantableTo := ents[0].GetGrantableTo()
			if len(grantableTo) != 2 {
				t.Fatalf("expected %q to be grantable to exactly 2 resource types, got %v", roleID, grantableTo)
			}
			var sawUserAccount, sawGroup bool
			for _, rt := range grantableTo {
				switch rt.Id {
				case resourceTypeUserAccount.Id:
					sawUserAccount = true
				case resourceTypeGroup.Id:
					sawGroup = true
				}
			}
			if !sawUserAccount || !sawGroup {
				t.Errorf("expected %q to be grantable to both userAccount and group, got %v", roleID, grantableTo)
			}
		})
	}
}
