package connector

import (
	"testing"

	"github.com/conductorone/baton-jamf/pkg/jamf"
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
