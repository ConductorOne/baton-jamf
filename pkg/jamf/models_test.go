package jamf

import (
	"encoding/xml"
	"strings"
	"testing"
)

func TestUserAccountCreateBody_Privileges_OmitsEmptyCategories(t *testing.T) {
	body := UserAccountCreateBody{
		Name:         "customadmin",
		Password:     "pw",
		PrivilegeSet: "Custom",
		Privileges: &Privileges{
			JSSObjects: []string{"Read User", "Update User"},
			Recon:      []string{"Read Advanced Computer Searches"},
		},
	}

	out, err := xml.Marshal(body) //nolint:gosec // test-only literal password, not a real secret
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := string(out)

	for _, want := range []string{
		"<jss_objects><privilege>Read User</privilege><privilege>Update User</privilege></jss_objects>",
		"<recon><privilege>Read Advanced Computer Searches</privilege></recon>",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("expected output to contain %q, got: %s", want, got)
		}
	}

	for _, category := range []string{"jss_settings", "jss_actions", "casper_admin", "casper_remote", "casper_imaging"} {
		if strings.Contains(got, "<"+category+">") {
			t.Errorf("expected unset category %q to be omitted entirely, got: %s", category, got)
		}
	}
}

func TestUserAccountCreateBody_Privileges_NilOmitsWholeElement(t *testing.T) {
	body := UserAccountCreateBody{Name: "auditor1", Password: "pw", PrivilegeSet: "Auditor"}

	out, err := xml.Marshal(body) //nolint:gosec // test-only literal password, not a real secret
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(string(out), "<privileges") {
		t.Errorf("expected no <privileges> element for a non-Custom account, got: %s", string(out))
	}
}

func TestPrivileges_Contains(t *testing.T) {
	p := &Privileges{
		JSSObjects: []string{"Read User"},
		Recon:      []string{"Read Advanced Computer Searches"},
	}

	if !p.Contains("Read User") {
		t.Error("expected Contains to find a JSSObjects privilege")
	}
	if !p.Contains("Read Advanced Computer Searches") {
		t.Error("expected Contains to find a Recon privilege")
	}
	if p.Contains("Update User") {
		t.Error("expected Contains to return false for an unlisted privilege")
	}
	if (*Privileges)(nil).Contains("anything") {
		t.Error("expected Contains to return false on a nil receiver")
	}
}

func TestPrivileges_IsEmpty(t *testing.T) {
	if !(&Privileges{}).IsEmpty() {
		t.Error("expected an all-nil Privileges to be empty")
	}
	if (&Privileges{Recon: []string{"x"}}).IsEmpty() {
		t.Error("expected a Privileges with one populated category to not be empty")
	}
	if !(*Privileges)(nil).IsEmpty() {
		t.Error("expected a nil Privileges to be empty")
	}
}
