package connector

import (
	"testing"
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
// silently discarding an operator's privileges_* input when they leave
// privilege_set at its default — see PR #28 review feedback.
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
