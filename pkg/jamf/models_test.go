package jamf

import (
	"encoding/json"
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

func TestUserGroupMemberMutation_AdditionsMarshalsUserAdditions(t *testing.T) {
	body := UserGroupMemberMutation{Additions: &userGroupUsers{Users: []BaseType{{ID: 1938}}}}

	out, err := xml.Marshal(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := string(out)

	if want := "<user_additions><user><id>1938</id></user></user_additions>"; !strings.Contains(got, want) {
		t.Errorf("expected output to contain %q, got: %s", want, got)
	}
	if strings.Contains(got, "user_deletions") {
		t.Errorf("expected no <user_deletions> element when Deletions is nil, got: %s", got)
	}
}

func TestUserGroupMemberMutation_DeletionsMarshalsUserDeletions(t *testing.T) {
	body := UserGroupMemberMutation{Deletions: &userGroupUsers{Users: []BaseType{{ID: 42}}}}

	out, err := xml.Marshal(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := string(out)

	if want := "<user_deletions><user><id>42</id></user></user_deletions>"; !strings.Contains(got, want) {
		t.Errorf("expected output to contain %q, got: %s", want, got)
	}
	if strings.Contains(got, "user_additions") {
		t.Errorf("expected no <user_additions> element when Additions is nil, got: %s", got)
	}
}

func TestUserSitesUpdateBody_MarshalsSitesList(t *testing.T) {
	body := UserSitesUpdateBody{Sites: []userSiteItem{{ID: 1}, {ID: 2}}}

	out, err := xml.Marshal(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := string(out)

	if want := "<user><sites><site><id>1</id></site><site><id>2</id></site></sites></user>"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestUserSitesUpdateBody_EmptySitesSendsEmptyWrapper documents (rather than
// works around) encoding/xml's behavior for a nil slice behind a ">"-chained
// tag with no omitempty — see the wrapper-emission caveat already documented
// on Privileges.MarshalXML. This is the desired behavior here: RemoveUserSite
// reconstructing a zero-length <sites> list (the user's last site was
// removed) must PUT an explicit empty <sites></sites> to actually clear
// membership, not omit the element and leave the prior value untouched.
func TestUserSitesUpdateBody_EmptySitesSendsEmptyWrapper(t *testing.T) {
	body := UserSitesUpdateBody{Sites: []userSiteItem{}}

	out, err := xml.Marshal(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := "<user><sites></sites></user>"; string(out) != want {
		t.Errorf("got %q, want %q", string(out), want)
	}
}

func TestComputerAssignedUserUpdate_JSONRoundTrip(t *testing.T) {
	body := ComputerAssignedUserUpdate{UserAndLocation: ComputerAssignedUserUpdateLocation{Username: "jappleseed"}}

	out, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := `{"userAndLocation":{"username":"jappleseed"}}`; string(out) != want {
		t.Errorf("got %q, want %q", string(out), want)
	}

	var decoded ComputerAssignedUserUpdate
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decoded.UserAndLocation.Username != "jappleseed" {
		t.Errorf("got %q, want %q", decoded.UserAndLocation.Username, "jappleseed")
	}
}

func TestComputerAssignedUserUpdate_EmptyUsernameClearsField(t *testing.T) {
	body := ComputerAssignedUserUpdate{UserAndLocation: ComputerAssignedUserUpdateLocation{Username: ""}}

	out, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := `{"userAndLocation":{"username":""}}`; string(out) != want {
		t.Errorf("got %q, want %q", string(out), want)
	}
}

func TestMobileDeviceAssignedUserUpdate_JSONRoundTrip(t *testing.T) {
	body := MobileDeviceAssignedUserUpdate{Location: MobileDeviceAssignedUserUpdateLocation{Username: "jappleseed"}}

	out, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := `{"location":{"username":"jappleseed"}}`; string(out) != want {
		t.Errorf("got %q, want %q", string(out), want)
	}

	var decoded MobileDeviceAssignedUserUpdate
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decoded.Location.Username != "jappleseed" {
		t.Errorf("got %q, want %q", decoded.Location.Username, "jappleseed")
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
