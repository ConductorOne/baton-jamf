package connector

import (
	"context"
	"net/http"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestResolvePrivileges_CustomWithPrivileges(t *testing.T) {
	profileMap := map[string]interface{}{
		profileFieldPrivilegesJSSObjects: []interface{}{"Read User"},
	}
	got, err := resolvePrivileges(profileMap, privilegeSetCustom)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || got.IsEmpty() {
		t.Fatal("expected a populated Privileges value for a Custom account with privileges set")
	}
}

func TestResolvePrivileges_CustomWithNoPrivileges_Errors(t *testing.T) {
	_, err := resolvePrivileges(map[string]interface{}{}, privilegeSetCustom)
	if err == nil {
		t.Fatal("expected an error when privilege_set is Custom but no privileges are set")
	}
}

func TestResolvePrivileges_NonCustomWithNoPrivileges_OK(t *testing.T) {
	got, err := resolvePrivileges(map[string]interface{}{}, privilegeSetAuditor)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil Privileges for a non-Custom account with no privileges fields set, got %+v", got)
	}
}

// TestResolvePrivileges_NonCustomWithPrivileges_Errors guards against
// silently discarding privileges_* input when privilege_set is left at its
// default.
func TestResolvePrivileges_NonCustomWithPrivileges_Errors(t *testing.T) {
	profileMap := map[string]interface{}{
		profileFieldPrivilegesRecon: []interface{}{"Read Advanced Computer Searches"},
	}
	got, err := resolvePrivileges(profileMap, privilegeSetAuditor)
	if err == nil {
		t.Fatal("expected an error when privileges are set but privilege_set is not Custom")
	}
	if got != nil {
		t.Fatalf("expected nil Privileges alongside the error, got %+v", got)
	}
}

func TestResolvePrivileges_DiscardsMalformedEntries(t *testing.T) {
	profileMap := map[string]interface{}{
		profileFieldPrivilegesJSSObjects: []interface{}{"Read User", 123, ""},
	}
	got, err := resolvePrivileges(profileMap, privilegeSetCustom)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"Read User"}
	if len(got.JSSObjects) != len(want) || got.JSSObjects[0] != want[0] {
		t.Fatalf("expected malformed/empty entries filtered out, got %v", got.JSSObjects)
	}
}

// Deleting the account the connector authenticates with would cut its own access, so Delete refuses it.
func TestUserAccountDelete_RefusesTheConnectorsOwnAccount(t *testing.T) {
	var deletes []string
	client := newTestJamfClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/auth":
			w.Header().Set("Content-Type", "application/json")
			encodeJSON(t, w, map[string]any{"account": map[string]any{"id": "7", "username": "connector"}})
		case r.Method == http.MethodDelete:
			deletes = append(deletes, r.URL.Path)
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	})
	builder := userAccountBuilder(client)

	_, err := builder.Delete(context.Background(), &v2.ResourceId{ResourceType: resourceTypeUserAccount.Id, Resource: "7"}, nil)

	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("Delete own account err = %v, want FailedPrecondition", err)
	}
	if len(deletes) != 0 {
		t.Fatalf("want no DELETE for the connector's own account, got %v", deletes)
	}
}
