package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/conductorone/baton-jamf/pkg/jamf"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/conductorone/baton-sdk/pkg/types/sessions"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func mustDeviceTrait(t *testing.T, r *v2.Resource) *v2.ManagedDeviceTrait {
	t.Helper()
	trait := &v2.ManagedDeviceTrait{}
	annos := annotations.Annotations(r.GetAnnotations())
	ok, err := annos.Pick(trait)
	if err != nil {
		t.Fatalf("pick ManagedDeviceTrait: %v", err)
	}
	if !ok {
		t.Fatal("ManagedDeviceTrait annotation not present on resource")
	}
	return trait
}

func testUserIndex() map[string]*v2.ResourceId {
	rid := &v2.ResourceId{}
	rid.SetResourceType("user")
	rid.SetResource("42")
	return map[string]*v2.ResourceId{
		"jappleseed":        rid,
		"jappleseed@ex.com": rid,
	}
}

func TestComputerResource_FullMapping(t *testing.T) {
	c := &jamf.ComputerInventory{
		ID:   "17",
		UDID: "00008110-000A4D8E0C8A801E",
		General: &jamf.ComputerGeneral{
			Name:             "Johnny's MacBook",
			LastEnrolledDate: "2026-01-02T03:04:05.000Z",
			Supervised:       true,
			MDMCapable:       &jamf.ComputerMDMCapable{Capable: true},
			RemoteManagement: &jamf.ComputerRemoteManagement{Managed: true},
			Site:             &jamf.NamedRef{ID: "1", Name: "HQ"},
		},
		Hardware: &jamf.ComputerHardware{
			Make:            "Apple",
			Model:           "MacBook Pro (16-inch, 2021)",
			ModelIdentifier: "MacBookPro18,3",
			SerialNumber:    "C02XL0THJGH5",
		},
		OperatingSystem: &jamf.ComputerOperatingSystem{
			Name:    "macOS",
			Version: "14.5",
			Build:   "23F79",
		},
		UserAndLocation: &jamf.ComputerUserAndLocation{
			Username:     "jappleseed",
			Email:        "jappleseed@ex.com",
			Position:     "Engineer",
			DepartmentID: "7",
			BuildingID:   "3",
			Room:         "201",
		},
		DiskEncryption: &jamf.ComputerDiskEncryption{
			BootPartitionEncryptionDetails: &jamf.BootPartitionEncryptionDetails{
				PartitionFileVault2State: "ENCRYPTED",
			},
		},
		Security: &jamf.ComputerSecurity{
			ActivationLockEnabled: true,
			RecoveryLockEnabled:   false,
			FirewallEnabled:       true,
			SipStatus:             "ENABLED",
		},
	}

	r, err := computerResource(c, nil)
	if err != nil {
		t.Fatalf("computerResource: %v", err)
	}

	if got, want := r.GetId().GetResource(), "computer:17"; got != want {
		t.Errorf("resource id = %q, want %q", got, want)
	}
	if got, want := r.GetDisplayName(), "Johnny's MacBook"; got != want {
		t.Errorf("display name = %q, want %q", got, want)
	}

	trait := mustDeviceTrait(t, r)

	if got, want := trait.GetSerial(), "C02XL0THJGH5"; got != want {
		t.Errorf("serial = %q, want %q", got, want)
	}
	if got, want := trait.GetUdid(), "00008110-000A4D8E0C8A801E"; got != want {
		t.Errorf("udid = %q, want %q", got, want)
	}
	if got, want := trait.GetDeviceType(), v2.ManagedDeviceTrait_DEVICE_TYPE_LAPTOP; got != want {
		t.Errorf("device type = %v, want %v", got, want)
	}
	if got, want := trait.GetModel(), "MacBook Pro (16-inch, 2021)"; got != want {
		t.Errorf("model = %q, want %q", got, want)
	}
	if got, want := trait.GetVendor(), "Apple"; got != want {
		t.Errorf("vendor = %q, want %q", got, want)
	}
	if got, want := trait.GetOs().GetType(), v2.DeviceOS_OS_TYPE_MACOS; got != want {
		t.Errorf("os type = %v, want %v", got, want)
	}
	if got, want := trait.GetOs().GetVersion(), "14.5"; got != want {
		t.Errorf("os version = %q, want %q", got, want)
	}
	if got, want := trait.GetOs().GetBuild_(), "23F79"; got != want {
		t.Errorf("os build = %q, want %q", got, want)
	}

	if trait.GetIsEncrypted() == nil || !trait.GetIsEncrypted().GetValue() {
		t.Error("is_encrypted should be true")
	}
	if trait.GetIsSupervised() == nil || !trait.GetIsSupervised().GetValue() {
		t.Error("is_supervised should be true")
	}
	if got, want := trait.GetManagementState(), v2.ManagedDeviceTrait_MANAGEMENT_STATE_MANAGED; got != want {
		t.Errorf("management state = %v, want %v", got, want)
	}
	if got, want := trait.GetCompliance(), v2.ManagedDeviceTrait_COMPLIANCE_UNSPECIFIED; got != want {
		t.Errorf("compliance should stay unspecified, got %v", got)
	}

	wantEnroll := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if !wantEnroll.Equal(trait.GetEnrolledAt().AsTime()) {
		t.Errorf("enrolled_at = %v, want %v", trait.GetEnrolledAt().AsTime(), wantEnroll)
	}

	// A resolvable assignee produces a direct grant to the synced Jamf user.
	grants, err := deviceGrants(r, assignee{username: "jappleseed", email: "jappleseed@ex.com"}, testUserIndex())
	if err != nil {
		t.Fatalf("deviceGrants: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("want 1 grant, got %d", len(grants))
	}
	if got, want := grants[0].GetPrincipal().GetId().GetResource(), "42"; got != want {
		t.Errorf("grant principal = %q, want %q", got, want)
	}
	if got, want := grants[0].GetPrincipal().GetId().GetResourceType(), "user"; got != want {
		t.Errorf("grant principal type = %q, want %q", got, want)
	}
	// A directly-granted user carries no ExternalResourceMatch annotation.
	resolvedAnnos := annotations.Annotations(grants[0].GetAnnotations())
	if ok, _ := resolvedAnnos.Pick(&v2.ExternalResourceMatch{}); ok {
		t.Error("resolved grant should not carry an ExternalResourceMatch annotation")
	}
}

func TestComputerResource_UnresolvedOwnerAndNoLastSeen(t *testing.T) {
	c := &jamf.ComputerInventory{
		ID: "9",
		General: &jamf.ComputerGeneral{
			Name: "Orphan Mac",
			// Not MDM managed -> management state stays unspecified.
		},
		Hardware: &jamf.ComputerHardware{ModelIdentifier: "Macmini9,1"},
		UserAndLocation: &jamf.ComputerUserAndLocation{
			Username: "ghost",
		},
		DiskEncryption: &jamf.ComputerDiskEncryption{
			BootPartitionEncryptionDetails: &jamf.BootPartitionEncryptionDetails{
				PartitionFileVault2State: "UNENCRYPTED",
			},
		},
	}

	r, err := computerResource(c, nil)
	if err != nil {
		t.Fatalf("computerResource: %v", err)
	}
	trait := mustDeviceTrait(t, r)

	if got, want := trait.GetDeviceType(), v2.ManagedDeviceTrait_DEVICE_TYPE_DESKTOP; got != want {
		t.Errorf("device type = %v, want DESKTOP", got)
	}
	if trait.GetIsEncrypted() == nil || trait.GetIsEncrypted().GetValue() {
		t.Error("is_encrypted should be explicit false")
	}
	if got, want := trait.GetManagementState(), v2.ManagedDeviceTrait_MANAGEMENT_STATE_UNSPECIFIED; got != want {
		t.Errorf("management state = %v, want UNSPECIFIED", got)
	}
	// No last-seen field should ever be emitted (RFC-C v1). enrolled_at unset here too.
	if trait.GetEnrolledAt() != nil {
		t.Error("enrolled_at should be unset when lastEnrolledDate absent")
	}

	// An assignee that is not a synced Jamf user produces an external-match grant.
	grants, err := deviceGrants(r, assignee{username: "ghost"}, testUserIndex())
	if err != nil {
		t.Fatalf("deviceGrants: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("want 1 grant, got %d", len(grants))
	}
	match := &v2.ExternalResourceMatch{}
	grantAnnos := annotations.Annotations(grants[0].GetAnnotations())
	ok, err := grantAnnos.Pick(match)
	if err != nil {
		t.Fatalf("pick ExternalResourceMatch: %v", err)
	}
	if !ok {
		t.Fatal("unresolved grant should carry an ExternalResourceMatch annotation")
	}
	if got, want := match.GetResourceType(), v2.ResourceType_TRAIT_USER; got != want {
		t.Errorf("match resource type = %v, want %v", got, want)
	}
	if got, want := match.GetKey(), "username"; got != want {
		t.Errorf("match key = %q, want %q", got, want)
	}
	if got, want := match.GetValue(), "ghost"; got != want {
		t.Errorf("match value = %q, want %q", got, want)
	}
}

func TestMobileDeviceResource_Mapping(t *testing.T) {
	m := &jamf.MobileDevice{
		ID:              "3",
		Name:            "Field iPad",
		SerialNumber:    "DMPXXXXXXXXX",
		UDID:            "aaaa-bbbb",
		Model:           "iPad Pro (11-inch)",
		ModelIdentifier: "iPad8,1",
		Username:        "jappleseed",
		Type:            "ios",
		Managed:         true,
		Supervised:      true,
		OSVersion:       "17.5",
		OSBuild:         "21F79",
	}

	r, err := mobileDeviceResource(m, nil)
	if err != nil {
		t.Fatalf("mobileDeviceResource: %v", err)
	}
	if got, want := r.GetId().GetResource(), "mobile:3"; got != want {
		t.Errorf("resource id = %q, want %q", got, want)
	}
	trait := mustDeviceTrait(t, r)

	if got, want := trait.GetDeviceType(), v2.ManagedDeviceTrait_DEVICE_TYPE_TABLET; got != want {
		t.Errorf("device type = %v, want TABLET", got)
	}
	if got, want := trait.GetOs().GetType(), v2.DeviceOS_OS_TYPE_IPADOS; got != want {
		t.Errorf("os type = %v, want IPADOS", got)
	}
	if got, want := trait.GetOs().GetVersion(), "17.5"; got != want {
		t.Errorf("os version = %q, want 17.5", got)
	}
	if got, want := trait.GetManagementState(), v2.ManagedDeviceTrait_MANAGEMENT_STATE_MANAGED; got != want {
		t.Errorf("management state = %v, want MANAGED", got)
	}
	grants, err := deviceGrants(r, assignee{username: "jappleseed"}, testUserIndex())
	if err != nil {
		t.Fatalf("deviceGrants: %v", err)
	}
	if len(grants) != 1 || grants[0].GetPrincipal().GetId().GetResource() != "42" {
		t.Error("assignee should resolve to a direct grant on synced user 42")
	}
}

func deviceEntitlement(t *testing.T, objectID string) *v2.Entitlement {
	t.Helper()
	return ent.NewAssignmentEntitlement(&v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeManagedDevice.Id, Resource: objectID}}, assignedEntitlement, ent.WithGrantableTo(resourceTypeUser))
}

// jamfDeviceAssignHandler serves GET /JSSResource/users/id/{id} (used to
// resolve a "user" principal to a Jamf username) and records the PATCH body
// sent to whichever device-assignment endpoint is hit, so tests can assert
// the resolved username was sent (or cleared, for Revoke). The device's
// CURRENT assignee (as returned by the computers-inventory-detail /
// mobile-devices GET that Revoke uses to check for reassignment) is the same
// as username, so Revoke's current-assignee check always matches.
func jamfDeviceAssignHandler(t *testing.T, username string, gotPATCHBody *[]byte) http.HandlerFunc {
	t.Helper()
	return jamfDeviceAssignHandlerWithCurrent(t, username, username, gotPATCHBody)
}

// jamfDeviceAssignHandlerWithCurrent is jamfDeviceAssignHandler with
// independent control over the principal's resolved username (from
// /JSSResource/users/id/{id}) and the device's CURRENT assignee (from the
// computers-inventory-detail / mobile-devices detail GET), so tests can
// exercise Revoke's stale-assignment check where the two differ.
func jamfDeviceAssignHandlerWithCurrent(t *testing.T, principalUsername, currentUsername string, gotPATCHBody *[]byte) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/JSSResource/users/"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user": map[string]any{"id": 42, "name": "jappleseed", "username": principalUsername},
			})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/api/v4/computers-inventory-detail/"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":              "17",
				"userAndLocation": map[string]any{"username": currentUsername},
			})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/detail") && strings.Contains(r.URL.Path, "/mobile-devices/"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":       "3",
				"location": map[string]any{"username": currentUsername},
			})
		case r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/api/v4/computers-inventory-detail/"):
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read PATCH body: %v", err)
			}
			*gotPATCHBody = body
			// v4 PATCH answers 204 with no body (v1, which v4 replaces,
			// answered 200 with the updated record).
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/api/v2/mobile-devices/"):
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read PATCH body: %v", err)
			}
			*gotPATCHBody = body
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "3"})
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}
}

// jamfDeviceAssignHandlerEmail is jamfDeviceAssignHandlerWithCurrent extended
// with independent control over email on both the principal's resolved Jamf
// user record and the device's current assignee, for exercising Revoke's
// email-based matching and externally-matched principals (which never hit the
// /JSSResource/users/ endpoint, since there is no numeric Jamf user id to resolve).
func jamfDeviceAssignHandlerEmail(t *testing.T, principalUsername, principalEmail, currentUsername, currentEmail string, gotPATCHBody *[]byte) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/users":
			// Grant (GrantReplaced) and Revoke (stale-email check) look up the current assignee here; no match is fine.
			w.Header().Set("Content-Type", "application/json")
			encodeJSON(t, w, map[string]any{"totalCount": 0, "results": []any{}})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/JSSResource/users/"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user": map[string]any{"id": 42, "name": "jappleseed", "username": principalUsername, "email": principalEmail},
			})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/api/v4/computers-inventory-detail/"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":              "17",
				"userAndLocation": map[string]any{"username": currentUsername, "email": currentEmail},
			})
		case r.Method == http.MethodPatch:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read PATCH body: %v", err)
			}
			*gotPATCHBody = body
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}
}

// TestManagedDeviceRevoke_UsernameDiffersButEmailMatches_NoPatch covers the
// username-priority rule: the principal has a username ("old.name"), the device's
// current one ("bob") differs, and a stale email happens to match. When both sides
// have a username, email is not consulted: Jamf never refreshes a computer's email
// when its username changes, so matching it would clear a different, live assignee.
func TestManagedDeviceRevoke_UsernameDiffersButEmailMatches_NoPatch(t *testing.T) {
	var patchBody []byte
	client := newTestJamfClient(t, jamfDeviceAssignHandlerEmail(t, "old.name", "jappleseed@ex.com", "bob", "jappleseed@ex.com", &patchBody))
	d := managedDeviceBuilder(client, false)

	gr := grant.NewGrant(deviceEntitlement(t, "computer:17").Resource, assignedEntitlement, userPrincipal(t, 42).Id)
	annos, err := d.Revoke(context.Background(), gr)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if ok, _ := annos.Pick(&v2.GrantAlreadyRevoked{}); !ok {
		t.Errorf("expected a GrantAlreadyRevoked annotation when the current username differs, got %v", annos)
	}
	if patchBody != nil {
		t.Errorf("expected no PATCH to be sent when the device's current username differs from the principal's, got body %q", string(patchBody))
	}
}

// An email-only grant matches a device with a blank username by email, so Revoke clears it.
func TestManagedDeviceRevoke_ExternalMatchPrincipal_Patches(t *testing.T) {
	var patchBody []byte
	// The /JSSResource/users/ principal fields are deliberately implausible
	// ("unused"/"unused@ex.com"): if Revoke incorrectly fell back to
	// resolvePrincipalUser here, strconv.Atoi("ghost@ex.com") would fail
	// before that endpoint is ever hit, catching the bug either way.
	client := newTestJamfClient(t, jamfDeviceAssignHandlerEmail(t, "unused", "unused@ex.com", "", "ghost@ex.com", &patchBody))
	d := managedDeviceBuilder(client, false)

	principal, err := rs.NewResourceID(resourceTypeUser, "ghost@ex.com")
	if err != nil {
		t.Fatalf("NewResourceID: %v", err)
	}
	match := v2.ExternalResourceMatch_builder{
		ResourceType: v2.ResourceType_TRAIT_USER,
		Key:          matchKeyEmail,
		Value:        "ghost@ex.com",
	}.Build()
	gr := grant.NewGrant(deviceEntitlement(t, "computer:17").Resource, assignedEntitlement, principal, grant.WithAnnotation(match))

	annos, err := d.Revoke(context.Background(), gr)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if hasMarkerAnnotation(annos) {
		t.Errorf("expected no marker annotations (grant should be revoked), got %v", annos)
	}
	if patchBody == nil {
		t.Fatal("expected a PATCH to be sent for an externally-matched principal that matches the current assignee")
	}
	if want := `{"userAndLocation":{"username":"","realname":"","email":"","position":"","phone":""}}` + "\n"; string(patchBody) != want {
		t.Errorf("PATCH body = %q, want %q", string(patchBody), want)
	}
}

// deviceGrants keys an unsynced assignee's grant by email whenever it has one, even if
// the device also has a username, so the ExternalResourceMatch principal carries no
// username. matches must still compare by email then, and with users synced an assignee
// that is not a synced user keeps the email grant live, so Revoke clears the device.
func TestManagedDeviceRevoke_ExternalMatchPrincipal_EmailOnly_DeviceHasUsername_Clears(t *testing.T) {
	var patchBody []byte
	client := newTestJamfClient(t, jamfDeviceAssignHandlerEmail(t, "unused", "unused@ex.com", "bob", "ghost@ex.com", &patchBody))
	d := managedDeviceBuilder(client, true)

	principal, err := rs.NewResourceID(resourceTypeUser, "ghost@ex.com")
	if err != nil {
		t.Fatalf("NewResourceID: %v", err)
	}
	match := v2.ExternalResourceMatch_builder{
		ResourceType: v2.ResourceType_TRAIT_USER,
		Key:          matchKeyEmail,
		Value:        "ghost@ex.com",
	}.Build()
	gr := grant.NewGrant(deviceEntitlement(t, "computer:17").Resource, assignedEntitlement, principal, grant.WithAnnotation(match))

	annos, err := d.Revoke(context.Background(), gr)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if hasMarkerAnnotation(annos) {
		t.Errorf("expected no marker annotations (grant should be revoked), got %v", annos)
	}
	if patchBody == nil {
		t.Fatal("expected a PATCH to be sent: the principal's email matches the device's current assignee even though the device also reports a username")
	}
}

// Jamf never refreshes a computer's email, so the stale-email protection applies only when the device's username
// is a synced user. When only the email names a synced user, or users are not synced, the email grant is the
// live one, so Revoke clears the device.
func TestManagedDeviceRevoke_ExternalMatchPrincipal_EmailOnly_AssigneeNowSyncedUser(t *testing.T) {
	tests := []struct {
		name      string
		syncUsers bool
		scenario  deviceGrantDisplaceScenario
		wantPatch bool
	}{
		{
			name:      "users synced, username is a synced user: already revoked",
			syncUsers: true,
			scenario: deviceGrantDisplaceScenario{
				currentUsername: "bob", currentEmail: "ghost@ex.com",
				oldUserID: 7, oldUsername: "bob", oldEmail: "bob@ex.com",
			},
		},
		{
			name:      "users synced, blank username with a synced user's email: clears the device",
			syncUsers: true,
			scenario: deviceGrantDisplaceScenario{
				currentEmail: "ghost@ex.com",
				oldUserID:    7, oldUsername: "bob", oldEmail: "ghost@ex.com",
			},
			wantPatch: true,
		},
		{
			name:      "users synced, unknown username with a synced user's email: clears the device",
			syncUsers: true,
			scenario: deviceGrantDisplaceScenario{
				currentUsername: "carol", currentEmail: "ghost@ex.com",
				oldUserID: 7, oldUsername: "bob", oldEmail: "ghost@ex.com",
			},
			wantPatch: true,
		},
		{
			name:      "users not synced: clears the device",
			syncUsers: false,
			scenario: deviceGrantDisplaceScenario{
				currentUsername: "bob", currentEmail: "ghost@ex.com",
				oldUserID: 7, oldUsername: "bob", oldEmail: "bob@ex.com",
			},
			wantPatch: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var patchBody []byte
			client := newTestJamfClient(t, jamfDeviceGrantDisplaceHandler(t, tc.scenario, &patchBody))
			d := managedDeviceBuilder(client, tc.syncUsers)

			principal, err := rs.NewResourceID(resourceTypeUser, "ghost@ex.com")
			if err != nil {
				t.Fatalf("NewResourceID: %v", err)
			}
			match := v2.ExternalResourceMatch_builder{
				ResourceType: v2.ResourceType_TRAIT_USER,
				Key:          matchKeyEmail,
				Value:        "ghost@ex.com",
			}.Build()
			gr := grant.NewGrant(deviceEntitlement(t, "computer:17").Resource, assignedEntitlement, principal, grant.WithAnnotation(match))

			annos, err := d.Revoke(context.Background(), gr)
			if err != nil {
				t.Fatalf("Revoke: %v", err)
			}
			if !tc.wantPatch {
				if ok, _ := annos.Pick(&v2.GrantAlreadyRevoked{}); !ok {
					t.Errorf("expected a GrantAlreadyRevoked annotation, got %v", annos)
				}
				if patchBody != nil {
					t.Errorf("expected no PATCH, got body %q", string(patchBody))
				}
				return
			}
			if hasMarkerAnnotation(annos) {
				t.Errorf("expected no marker annotations (grant should be revoked), got %v", annos)
			}
			if want := `{"userAndLocation":{"username":"","realname":"","email":"","position":"","phone":""}}` + "\n"; string(patchBody) != want {
				t.Errorf("PATCH body = %q, want %q", string(patchBody), want)
			}
		})
	}
}

// Granting an unassigned device displaces nobody, so no GrantReplaced. The mock's user record only has a
// username, so the other four userAndLocation keys are sent as empty strings.
func TestManagedDeviceGrant_Computer_PatchesUserAndLocation(t *testing.T) {
	var patchBody []byte
	client := newTestJamfClient(t, jamfDeviceAssignHandlerWithCurrent(t, "jappleseed", "", &patchBody))
	d := managedDeviceBuilder(client, false)

	grants, annos, err := d.Grant(context.Background(), userPrincipal(t, 42), deviceEntitlement(t, "computer:17"))
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("want 1 grant, got %d", len(grants))
	}
	if hasMarkerAnnotation(annos) {
		t.Errorf("expected no marker annotations for a previously-unassigned device, got %v", annos)
	}
	if want := `{"userAndLocation":{"username":"jappleseed","realname":"","email":"","position":"","phone":""}}` + "\n"; string(patchBody) != want {
		t.Errorf("PATCH body = %q, want %q", string(patchBody), want)
	}
}

// TestManagedDeviceGrant_Computer_PopulatesFullAssigneeIdentity covers Grant
// overwriting all five userAndLocation keys with the new assignee's full
// Jamf user record — not just username — so a previous assignee's realname,
// email, position and phone are actually replaced rather than left behind
// (Jamf never auto-populates these for computers the way it does for mobile
// devices).
func TestManagedDeviceGrant_Computer_PopulatesFullAssigneeIdentity(t *testing.T) {
	var patchBody []byte
	client := newTestJamfClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/JSSResource/users/"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user": map[string]any{
					"id": 42, "name": "jappleseed", "username": "jappleseed",
					"full_name": "Johnny Appleseed", "email": "jappleseed@ex.com",
					"position": "Engineer", "phone_number": "555-1234",
				},
			})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/api/v4/computers-inventory-detail/"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "17", "userAndLocation": map[string]any{"username": ""}})
		case r.Method == http.MethodPatch:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read PATCH body: %v", err)
			}
			patchBody = body
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	})
	d := managedDeviceBuilder(client, false)

	_, _, err := d.Grant(context.Background(), userPrincipal(t, 42), deviceEntitlement(t, "computer:17"))
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	want := `{"userAndLocation":{"username":"jappleseed","realname":"Johnny Appleseed","email":"jappleseed@ex.com","position":"Engineer","phone":"555-1234"}}` + "\n"
	if string(patchBody) != want {
		t.Errorf("PATCH body = %q, want %q", string(patchBody), want)
	}
}

// TestManagedDeviceGrant_Mobile_PatchesLocation is the mobile-device
// counterpart of TestManagedDeviceGrant_Computer_PatchesUserAndLocation: a
// previously-unassigned device, so no displacement is expected.
func TestManagedDeviceGrant_Mobile_PatchesLocation(t *testing.T) {
	var patchBody []byte
	client := newTestJamfClient(t, jamfDeviceAssignHandlerWithCurrent(t, "jappleseed", "", &patchBody))
	d := managedDeviceBuilder(client, false)

	grants, annos, err := d.Grant(context.Background(), userPrincipal(t, 42), deviceEntitlement(t, "mobile:3"))
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("want 1 grant, got %d", len(grants))
	}
	if hasMarkerAnnotation(annos) {
		t.Errorf("expected no marker annotations for a previously-unassigned device, got %v", annos)
	}
	if want := `{"location":{"username":"jappleseed"}}` + "\n"; string(patchBody) != want {
		t.Errorf("PATCH body = %q, want %q", string(patchBody), want)
	}
}

// A mobile Grant never sends an empty or email-derived username to Jamf: a principal whose Jamf user
// record has no username is rejected before any PATCH.
func TestManagedDeviceGrant_Mobile_NoUsername_FailedPrecondition(t *testing.T) {
	// Any request beyond the principal's user-detail lookup (in particular a
	// PATCH) fails the test via t.Fatalf in the default case below.
	client := newTestJamfClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/JSSResource/users/") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user": map[string]any{"id": 42, "email": "jappleseed@ex.com"},
			})
			return
		}
		t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
	})
	d := managedDeviceBuilder(client, false)

	_, _, err := d.Grant(context.Background(), userPrincipal(t, 42), deviceEntitlement(t, "mobile:3"))
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("Grant err = %v, want FailedPrecondition", err)
	}
}

// The device's current username ("bob") differs from the principal's ("alice") while a stale email on the
// device equals the principal's: Grant still PATCHes instead of reporting GrantAlreadyExists.
func TestManagedDeviceGrant_UsernameDiffersButEmailMatches_ProceedsToPatch(t *testing.T) {
	var patchBody []byte
	client := newTestJamfClient(t, jamfDeviceAssignHandlerEmail(t, "alice", "alice@ex.com", "bob", "alice@ex.com", &patchBody))
	d := managedDeviceBuilder(client, false)

	grants, annos, err := d.Grant(context.Background(), userPrincipal(t, 42), deviceEntitlement(t, "computer:17"))
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("want 1 grant, got %d", len(grants))
	}
	if ok, _ := annos.Pick(&v2.GrantAlreadyExists{}); ok {
		t.Error("expected the write to proceed, not GrantAlreadyExists, when the current username differs")
	}
	if patchBody == nil {
		t.Fatal("expected a PATCH to be sent when the device's current username differs from the principal's")
	}
	if want := `{"userAndLocation":{"username":"alice","realname":"","email":"alice@ex.com","position":"","phone":""}}` + "\n"; string(patchBody) != want {
		t.Errorf("PATCH body = %q, want %q", string(patchBody), want)
	}
}

// A device with a blank username that carries the principal's email already holds the principal's assignment, so
// Grant reports GrantAlreadyExists without a PATCH.
func TestManagedDeviceGrant_EmptyUsernameMatchesViaEmail_AlreadyExists(t *testing.T) {
	var patchBody []byte
	client := newTestJamfClient(t, jamfDeviceAssignHandlerEmail(t, "alice", "alice@ex.com", "", "alice@ex.com", &patchBody))
	d := managedDeviceBuilder(client, false)

	grants, annos, err := d.Grant(context.Background(), userPrincipal(t, 42), deviceEntitlement(t, "computer:17"))
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if grants != nil {
		t.Errorf("expected no grants returned on the already-exists path, got %v", grants)
	}
	if ok, _ := annos.Pick(&v2.GrantAlreadyExists{}); !ok {
		t.Errorf("expected a GrantAlreadyExists annotation, got %v", annos)
	}
	if patchBody != nil {
		t.Errorf("expected no PATCH when the device's empty username falls back to matching the principal's email, got body %q", string(patchBody))
	}
}

// TestManagedDeviceGrant_DeviceNotFound_ReturnsNotFound covers the Grant side
// of consistent 404 handling: a missing device must surface as codes.NotFound,
// not a raw wrapped error.
func TestManagedDeviceGrant_DeviceNotFound_ReturnsNotFound(t *testing.T) {
	client := newTestJamfClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/JSSResource/users/"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user": map[string]any{"id": 42, "name": "jappleseed", "username": "jappleseed"},
			})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/api/v4/computers-inventory-detail/"):
			w.WriteHeader(http.StatusNotFound)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	})
	d := managedDeviceBuilder(client, false)

	_, _, err := d.Grant(context.Background(), userPrincipal(t, 42), deviceEntitlement(t, "computer:17"))
	if err == nil {
		t.Fatal("expected an error granting assignment on a missing device")
	}
	if status.Code(err) != codes.NotFound {
		t.Errorf("Grant err = %v, want NotFound", err)
	}
}

// TestManagedDeviceRevoke_DeviceNotFound_MapsToGrantAlreadyRevoked covers the
// Revoke side of consistent 404 handling: a missing device must be reported
// as GrantAlreadyRevoked, like group/userGroup/role already do.
func TestManagedDeviceRevoke_DeviceNotFound_MapsToGrantAlreadyRevoked(t *testing.T) {
	client := newTestJamfClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/JSSResource/users/"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user": map[string]any{"id": 42, "name": "jappleseed", "username": "jappleseed"},
			})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/api/v4/computers-inventory-detail/"):
			w.WriteHeader(http.StatusNotFound)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	})
	d := managedDeviceBuilder(client, false)

	gr := grant.NewGrant(deviceEntitlement(t, "computer:17").Resource, assignedEntitlement, userPrincipal(t, 42).Id)
	annos, err := d.Revoke(context.Background(), gr)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if ok, _ := annos.Pick(&v2.GrantAlreadyRevoked{}); !ok {
		t.Errorf("expected a GrantAlreadyRevoked annotation for a missing device, got %v", annos)
	}
}

// TestManagedDeviceGrant_SameAssignee_ReturnsGrantAlreadyExists covers
// granting a device to the user who already holds the assignment: nothing is
// displaced, so Grant must short-circuit to GrantAlreadyExists instead of
// re-sending an identical PATCH.
func TestManagedDeviceGrant_SameAssignee_ReturnsGrantAlreadyExists(t *testing.T) {
	var patchBody []byte
	client := newTestJamfClient(t, jamfDeviceAssignHandlerWithCurrent(t, "jappleseed", "jappleseed", &patchBody))
	d := managedDeviceBuilder(client, false)

	grants, annos, err := d.Grant(context.Background(), userPrincipal(t, 42), deviceEntitlement(t, "computer:17"))
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if grants != nil {
		t.Errorf("expected no grants returned on the already-exists path, got %v", grants)
	}
	if patchBody != nil {
		t.Errorf("expected no PATCH to be sent when principal is already the current assignee, got body %q", string(patchBody))
	}
	if ok, _ := annos.Pick(&v2.GrantAlreadyExists{}); !ok {
		t.Error("expected a GrantAlreadyExists annotation when granting the already-assigned user")
	}
	if ok, _ := annos.Pick(&v2.GrantReplaced{}); ok {
		t.Error("expected no GrantReplaced annotation when nothing was displaced")
	}
}

// deviceGrantDisplaceScenario is the principal being granted (Grant only), the device's current assignee, and the
// synced user that assignee resolves to. oldUserID 0 means the assignee is not a synced user: the owner lookup finds nobody.
type deviceGrantDisplaceScenario struct {
	principalID                       int
	principalUsername, principalEmail string
	currentUsername, currentEmail     string
	oldUserID                         int
	oldUsername, oldEmail             string
}

// jamfDeviceGrantDisplaceHandler extends jamfDeviceAssignHandlerWithCurrent's computer-only endpoints with
// GET /api/v1/users, which replacedGrantID (Grant's GrantReplaced) and syncedUserIndex (Revoke's stale-email check)
// use to resolve the current assignee.
func jamfDeviceGrantDisplaceHandler(t *testing.T, sc deviceGrantDisplaceScenario, gotPATCHBody *[]byte) http.HandlerFunc {
	t.Helper()
	principalID, principalUsername, principalEmail := sc.principalID, sc.principalUsername, sc.principalEmail
	currentUsername, currentEmail := sc.currentUsername, sc.currentEmail
	oldUserID, oldUsername, oldEmail := sc.oldUserID, sc.oldUsername, sc.oldEmail
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/users":
			var wantTerms []string
			for _, key := range assigneeLookupKeys(assignee{username: currentUsername, email: currentEmail}) {
				wantTerms = append(wantTerms, fmt.Sprintf(`username=="%[1]s",email=="%[1]s"`, key))
			}
			if got, want := r.URL.Query().Get("filter"), strings.Join(wantTerms, ","); got != want {
				t.Errorf("users filter = %q, want %q", got, want)
			}
			users := []map[string]any{}
			if oldUserID != 0 {
				users = append(users, map[string]any{"id": strconv.Itoa(oldUserID), "username": oldUsername, "email": oldEmail})
			}
			w.Header().Set("Content-Type", "application/json")
			encodeJSON(t, w, map[string]any{"totalCount": len(users), "results": users})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, fmt.Sprintf("/JSSResource/users/id/%d", principalID)):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user": map[string]any{"id": principalID, "name": principalUsername, "username": principalUsername, "email": principalEmail},
			})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/api/v4/computers-inventory-detail/"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":              "17",
				"userAndLocation": map[string]any{"username": currentUsername, "email": currentEmail},
			})
		case r.Method == http.MethodPatch:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read PATCH body: %v", err)
			}
			*gotPATCHBody = body
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}
}

// Granting a device held by a different synced Jamf user PATCHes the new assignment and reports a GrantReplaced
// naming the displaced user's grant id.
func TestManagedDeviceGrant_DisplacesDifferentUser_ReturnsGrantReplaced(t *testing.T) {
	var patchBody []byte
	client := newTestJamfClient(t, jamfDeviceGrantDisplaceHandler(t, deviceGrantDisplaceScenario{
		principalID: 42, principalUsername: "new.user",
		currentUsername: "old.user", currentEmail: "old.user@ex.com",
		oldUserID: 7, oldUsername: "old.user", oldEmail: "old.user@ex.com",
	}, &patchBody))
	d := managedDeviceBuilder(client, true)

	en := deviceEntitlement(t, "computer:17")
	grants, annos, err := d.Grant(context.Background(), userPrincipal(t, 42), en)
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("want 1 grant, got %d", len(grants))
	}
	if patchBody == nil {
		t.Fatal("expected a PATCH to be sent when displacing a different user")
	}

	oldRid := &v2.ResourceId{}
	oldRid.SetResourceType(resourceTypeUser.Id)
	oldRid.SetResource("7")
	wantReplacedID := grant.NewGrantID(oldRid, en)

	replaced := &v2.GrantReplaced{}
	ok, err := annos.Pick(replaced)
	if err != nil {
		t.Fatalf("pick GrantReplaced: %v", err)
	}
	if !ok {
		t.Fatal("expected a GrantReplaced annotation when displacing a different assigned user")
	}
	if got := replaced.GetReplacedGrantId(); got != wantReplacedID {
		t.Errorf("replaced grant id = %q, want %q", got, wantReplacedID)
	}
}

// TestManagedDeviceGrant_DisplacesUnsyncedUser_ReturnsGrantReplacedExternalMatch
// is the unsynced-assignee counterpart: the outgoing assignee doesn't resolve
// to any synced Jamf user via the owner lookup (oldUserID 0 — the API finds
// nobody), so GrantReplaced must fall back to the same external-match-style
// principal id deviceGrants builds for that case.
func TestManagedDeviceGrant_DisplacesUnsyncedUser_ReturnsGrantReplacedExternalMatch(t *testing.T) {
	var patchBody []byte
	client := newTestJamfClient(t, jamfDeviceGrantDisplaceHandler(t, deviceGrantDisplaceScenario{
		principalID: 42, principalUsername: "new.user",
		currentUsername: "ghost", currentEmail: "ghost@ex.com",
	}, &patchBody))
	d := managedDeviceBuilder(client, true)

	en := deviceEntitlement(t, "computer:17")
	_, annos, err := d.Grant(context.Background(), userPrincipal(t, 42), en)
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if patchBody == nil {
		t.Fatal("expected a PATCH to be sent when displacing an unsynced assignee")
	}

	externalRid, err := rs.NewResourceID(resourceTypeUser, "ghost@ex.com")
	if err != nil {
		t.Fatalf("NewResourceID: %v", err)
	}
	wantReplacedID := grant.NewGrantID(externalRid, en)

	replaced := &v2.GrantReplaced{}
	ok, err := annos.Pick(replaced)
	if err != nil {
		t.Fatalf("pick GrantReplaced: %v", err)
	}
	if !ok {
		t.Fatal("expected a GrantReplaced annotation when displacing an unsynced assignee")
	}
	if got := replaced.GetReplacedGrantId(); got != wantReplacedID {
		t.Errorf("replaced grant id = %q, want %q", got, wantReplacedID)
	}
}

// TestManagedDeviceRevoke_ClearsUsername exercises the clear-value default
// for Revoke: it PATCHes all five userAndLocation keys (username, realname,
// email, position, phone) as empty strings to clear each field — an omitted
// key is a no-op, so every key must be sent explicitly.
func TestManagedDeviceRevoke_ClearsUsername(t *testing.T) {
	var patchBody []byte
	client := newTestJamfClient(t, jamfDeviceAssignHandler(t, "jappleseed", &patchBody))
	d := managedDeviceBuilder(client, false)

	gr := grant.NewGrant(deviceEntitlement(t, "computer:17").Resource, assignedEntitlement, userPrincipal(t, 42).Id)
	annos, err := d.Revoke(context.Background(), gr)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if hasMarkerAnnotation(annos) {
		t.Errorf("expected no marker annotations, got %v", annos)
	}
	if want := `{"userAndLocation":{"username":"","realname":"","email":"","position":"","phone":""}}` + "\n"; string(patchBody) != want {
		t.Errorf("PATCH body = %q, want %q", string(patchBody), want)
	}
}

// A device reassigned to a different user since the grant was synced keeps its live assignment: Revoke skips
// the PATCH and reports the grant as already revoked.
func TestManagedDeviceRevoke_ReassignedToDifferentUser_NoPatch(t *testing.T) {
	var patchBody []byte
	// Grant's principal (Jamf user 42) resolves to "jappleseed", but the
	// device's current live assignee is "someone.else" — reassigned since
	// the grant being revoked was synced.
	client := newTestJamfClient(t, jamfDeviceAssignHandlerWithCurrent(t, "jappleseed", "someone.else", &patchBody))
	d := managedDeviceBuilder(client, false)

	gr := grant.NewGrant(deviceEntitlement(t, "computer:17").Resource, assignedEntitlement, userPrincipal(t, 42).Id)
	annos, err := d.Revoke(context.Background(), gr)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if patchBody != nil {
		t.Errorf("expected no PATCH to be sent when device is assigned to a different user, got body %q", string(patchBody))
	}
	got := annos
	if ok, _ := got.Pick(&v2.GrantAlreadyRevoked{}); !ok {
		t.Error("expected a GrantAlreadyRevoked annotation when the device was reassigned to a different user")
	}
}

// TestManagedDeviceRevoke_AlreadyUnassigned_NoPatch covers the same
// stale-grant check for the "already unassigned" case: the device currently
// has no assignee at all, so revoking this specific grant is a no-op.
func TestManagedDeviceRevoke_AlreadyUnassigned_NoPatch(t *testing.T) {
	var patchBody []byte
	client := newTestJamfClient(t, jamfDeviceAssignHandlerWithCurrent(t, "jappleseed", "", &patchBody))
	d := managedDeviceBuilder(client, false)

	gr := grant.NewGrant(deviceEntitlement(t, "computer:17").Resource, assignedEntitlement, userPrincipal(t, 42).Id)
	annos, err := d.Revoke(context.Background(), gr)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if patchBody != nil {
		t.Errorf("expected no PATCH to be sent when device is already unassigned, got body %q", string(patchBody))
	}
	got := annos
	if ok, _ := got.Pick(&v2.GrantAlreadyRevoked{}); !ok {
		t.Error("expected a GrantAlreadyRevoked annotation when the device was already unassigned")
	}
}

// TestManagedDeviceRevoke_MobileDevice_ReassignedToDifferentUser_NoPatch is
// the mobile-device counterpart of
// TestManagedDeviceRevoke_ReassignedToDifferentUser_NoPatch, exercising
// currentAssignedUser's nested `location.username` read for the
// devicePhaseMobile case.
func TestManagedDeviceRevoke_MobileDevice_ReassignedToDifferentUser_NoPatch(t *testing.T) {
	var patchBody []byte
	// Grant's principal (Jamf user 42) resolves to "jappleseed", but the
	// device's current live assignee is "someone.else" — reassigned since
	// the grant being revoked was synced.
	client := newTestJamfClient(t, jamfDeviceAssignHandlerWithCurrent(t, "jappleseed", "someone.else", &patchBody))
	d := managedDeviceBuilder(client, false)

	gr := grant.NewGrant(deviceEntitlement(t, "mobile:3").Resource, assignedEntitlement, userPrincipal(t, 42).Id)
	annos, err := d.Revoke(context.Background(), gr)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if patchBody != nil {
		t.Errorf("expected no PATCH to be sent when device is assigned to a different user, got body %q", string(patchBody))
	}
	got := annos
	if ok, _ := got.Pick(&v2.GrantAlreadyRevoked{}); !ok {
		t.Error("expected a GrantAlreadyRevoked annotation when the device was reassigned to a different user")
	}
}

// TestManagedDeviceRevoke_MobileDevice_ClearsUsername is the mobile-device
// counterpart of TestManagedDeviceRevoke_ClearsUsername: the grant's
// principal is still the device's current assignee, so Revoke should PATCH
// the assignment clear rather than skip it.
func TestManagedDeviceRevoke_MobileDevice_ClearsUsername(t *testing.T) {
	var patchBody []byte
	client := newTestJamfClient(t, jamfDeviceAssignHandlerWithCurrent(t, "jappleseed", "jappleseed", &patchBody))
	d := managedDeviceBuilder(client, false)

	gr := grant.NewGrant(deviceEntitlement(t, "mobile:3").Resource, assignedEntitlement, userPrincipal(t, 42).Id)
	annos, err := d.Revoke(context.Background(), gr)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if hasMarkerAnnotation(annos) {
		t.Errorf("expected no marker annotations, got %v", annos)
	}
	if want := `{"location":{"username":""}}` + "\n"; string(patchBody) != want {
		t.Errorf("PATCH body = %q, want %q", string(patchBody), want)
	}
}

// An admin-set email unrelated to the principal does not stop Revoke: once the username matches, the whole
// assignee identity is cleared, whatever the device's current email is.
func TestManagedDeviceRevoke_EmailDoesNotMatch_StillClearsEverything(t *testing.T) {
	var patchBody []byte
	// Username matches ("jappleseed") so the grant is still live and Revoke
	// proceeds, even though the device's current email is some unrelated
	// admin-set value that does not match the principal's resolved email
	// (empty, since the mock's /JSSResource/users/ response carries no email).
	client := newTestJamfClient(t, jamfDeviceAssignHandlerEmail(t, "jappleseed", "", "jappleseed", "admin-set@ex.com", &patchBody))
	d := managedDeviceBuilder(client, false)

	gr := grant.NewGrant(deviceEntitlement(t, "computer:17").Resource, assignedEntitlement, userPrincipal(t, 42).Id)
	annos, err := d.Revoke(context.Background(), gr)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if hasMarkerAnnotation(annos) {
		t.Errorf("expected no marker annotations (grant should be revoked), got %v", annos)
	}
	if patchBody == nil {
		t.Fatal("expected a PATCH to be sent to clear the assignee")
	}
	if want := `{"userAndLocation":{"username":"","realname":"","email":"","position":"","phone":""}}` + "\n"; string(patchBody) != want {
		t.Errorf("PATCH body = %q, want %q", string(patchBody), want)
	}
}

// TestManagedDeviceRevoke_ExternalMatchPrincipal_EmailDoesNotMatch_StillClearsEverything
// is the ExternalResourceMatch-principal counterpart: the principal's
// identity comes from the grant annotation (a raw email string) rather than
// GetUserDetails, but the same unconditional clear must still apply.
func TestManagedDeviceRevoke_ExternalMatchPrincipal_EmailDoesNotMatch_StillClearsEverything(t *testing.T) {
	var patchBody []byte
	client := newTestJamfClient(t, jamfDeviceAssignHandlerEmail(t, "unused", "unused@ex.com", "ghost", "admin-set@ex.com", &patchBody))
	d := managedDeviceBuilder(client, false)

	// Keyed on username, not email: the device's current username ("ghost")
	// still matches, so matches succeeds and Revoke proceeds, even
	// though the device's current email ("admin-set@ex.com") has no
	// counterpart on this principal to match against.
	principal, err := rs.NewResourceID(resourceTypeUser, "ghost")
	if err != nil {
		t.Fatalf("NewResourceID: %v", err)
	}
	match := v2.ExternalResourceMatch_builder{
		ResourceType: v2.ResourceType_TRAIT_USER,
		Key:          matchKeyUsername,
		Value:        "ghost",
	}.Build()
	gr := grant.NewGrant(deviceEntitlement(t, "computer:17").Resource, assignedEntitlement, principal, grant.WithAnnotation(match))

	annos, err := d.Revoke(context.Background(), gr)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if hasMarkerAnnotation(annos) {
		t.Errorf("expected no marker annotations (grant should be revoked), got %v", annos)
	}
	if patchBody == nil {
		t.Fatal("expected a PATCH to be sent to clear the assignee")
	}
	if want := `{"userAndLocation":{"username":"","realname":"","email":"","position":"","phone":""}}` + "\n"; string(patchBody) != want {
		t.Errorf("PATCH body = %q, want %q", string(patchBody), want)
	}
}

// TestPrincipalIdentityForRevoke_NoAnnotation_FallsBackOnRawIDShape covers
// the platform not sending back an ExternalResourceMatch
// annotation AND the principal id not being a numeric Jamf user id:
// principalIdentityForRevoke must fall back to treating the raw id string as
// an email (if it contains "@") or a username (otherwise) — mirroring
// deviceGrants' own heuristic — instead of handing a non-numeric string to
// resolvePrincipalUser's strconv.Atoi and failing with InvalidArgument.
func TestPrincipalIdentityForRevoke_NoAnnotation_FallsBackOnRawIDShape(t *testing.T) {
	client := newTestJamfClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("expected no API call for a non-numeric principal id, got %s %s", r.Method, r.URL.Path)
	})

	emailPrincipal, err := rs.NewResourceID(resourceTypeUser, "ghost@ex.com")
	if err != nil {
		t.Fatalf("NewResourceID: %v", err)
	}
	gr := grant.NewGrant(deviceEntitlement(t, "computer:17").Resource, assignedEntitlement, emailPrincipal)
	a, err := principalIdentityForRevoke(context.Background(), client, gr)
	if err != nil {
		t.Fatalf("principalIdentityForRevoke: %v", err)
	}
	if a.username != "" || a.email != "ghost@ex.com" {
		t.Errorf("got (username=%q, email=%q), want (\"\", \"ghost@ex.com\") for an email-shaped raw id", a.username, a.email)
	}

	usernamePrincipal, err := rs.NewResourceID(resourceTypeUser, "ghost")
	if err != nil {
		t.Fatalf("NewResourceID: %v", err)
	}
	gr = grant.NewGrant(deviceEntitlement(t, "computer:17").Resource, assignedEntitlement, usernamePrincipal)
	a, err = principalIdentityForRevoke(context.Background(), client, gr)
	if err != nil {
		t.Fatalf("principalIdentityForRevoke: %v", err)
	}
	if a.username != "ghost" || a.email != "" {
		t.Errorf("got (username=%q, email=%q), want (\"ghost\", \"\") for a non-email-shaped raw id", a.username, a.email)
	}
}

func TestManagedDeviceGrant_NonUserPrincipal_Errors(t *testing.T) {
	d := managedDeviceBuilder(nil, false)
	_, _, err := d.Grant(context.Background(), userGroupPrincipal(t, 7), deviceEntitlement(t, "computer:17"))
	if err == nil {
		t.Fatal("expected an error granting device assignment to a non-user principal")
	}
}

func TestManagedDeviceRevoke_NonUserPrincipal_Errors(t *testing.T) {
	d := managedDeviceBuilder(nil, false)
	gr := grant.NewGrant(deviceEntitlement(t, "computer:17").Resource, assignedEntitlement, userGroupPrincipal(t, 7).Id)
	_, err := d.Revoke(context.Background(), gr)
	if err == nil {
		t.Fatal("expected an error revoking device assignment from a non-user principal")
	}
}

// TestManagedDeviceRevoke_PrincipalDeleted_MapsToGrantAlreadyRevoked covers a
// principal (Jamf user) that has been deleted since this grant was synced:
// the GetUserDetails lookup inside principalIdentityForRevoke 404s. Jamf has
// already cleared the device's assignee when the user was deleted, so this
// must be treated as already revoked rather than propagating the 404 as a
// hard error (and, in particular, without ever sending a PATCH).
func TestManagedDeviceRevoke_PrincipalDeleted_MapsToGrantAlreadyRevoked(t *testing.T) {
	client := newTestJamfClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/JSSResource/users/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
	})
	d := managedDeviceBuilder(client, false)

	gr := grant.NewGrant(deviceEntitlement(t, "computer:17").Resource, assignedEntitlement, userPrincipal(t, 42).Id)
	annos, err := d.Revoke(context.Background(), gr)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if ok, _ := annos.Pick(&v2.GrantAlreadyRevoked{}); !ok {
		t.Errorf("expected a GrantAlreadyRevoked annotation, got %v", annos)
	}
}

func TestManagedDeviceGrant_InvalidResourceID_Errors(t *testing.T) {
	var patchBody []byte
	client := newTestJamfClient(t, jamfDeviceAssignHandler(t, "jappleseed", &patchBody))
	d := managedDeviceBuilder(client, false)
	_, _, err := d.Grant(context.Background(), userPrincipal(t, 42), deviceEntitlement(t, "not-namespaced"))
	if err == nil {
		t.Fatal("expected an error for a device resource id without a phase prefix")
	}
}

func TestParseDeviceObjectID(t *testing.T) {
	phase, id, err := parseDeviceObjectID("computer:17")
	if err != nil || phase != devicePhaseComputer || id != "17" {
		t.Errorf("parseDeviceObjectID(computer:17) = (%q,%q,%v)", phase, id, err)
	}
	if _, _, err := parseDeviceObjectID("bad"); err == nil {
		t.Error("expected an error for a resource id with no phase separator")
	}
}

func TestOSTypeFromName(t *testing.T) {
	cases := map[string]struct {
		want v2.DeviceOS_OsType
		ok   bool
	}{
		"macOS":    {v2.DeviceOS_OS_TYPE_MACOS, true},
		"iOS":      {v2.DeviceOS_OS_TYPE_IOS, true},
		"iPadOS":   {v2.DeviceOS_OS_TYPE_IPADOS, true},
		"Mac OS X": {v2.DeviceOS_OS_TYPE_MACOS, true},
		"Windows":  {v2.DeviceOS_OS_TYPE_UNSPECIFIED, false},
		"":         {v2.DeviceOS_OS_TYPE_UNSPECIFIED, false},
	}
	for name, tc := range cases {
		got, ok := osTypeFromName(name)
		if ok != tc.ok || got != tc.want {
			t.Errorf("osTypeFromName(%q) = (%v,%v), want (%v,%v)", name, got, ok, tc.want, tc.ok)
		}
	}
}

// replacedGrantIDHandler serves GET /api/v1/users with users as the results and counts the requests.
func replacedGrantIDHandler(t *testing.T, users []map[string]any, usersCalls *int) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/users" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		*usersCalls++
		w.Header().Set("Content-Type", "application/json")
		encodeJSON(t, w, map[string]any{"totalCount": len(users), "results": users})
	}
}

// wantReplacedGrantID builds the grant id replacedGrantID should return for a
// synced user with the given numeric id.
func wantReplacedGrantID(t *testing.T, userID string, en *v2.Entitlement) string {
	t.Helper()
	rid := &v2.ResourceId{}
	rid.SetResourceType(resourceTypeUser.Id)
	rid.SetResource(userID)
	return grant.NewGrantID(rid, en)
}

// A synced outgoing assignee resolves to that user's grant ID through the filtered users lookup.
func TestReplacedGrantID_ResolvesViaLookup(t *testing.T) {
	var usersCalls int
	users := []map[string]any{{"id": "7", "username": "old.user", "email": "old.user@ex.com"}}
	client := newTestJamfClient(t, replacedGrantIDHandler(t, users, &usersCalls))
	devices := managedDeviceBuilder(client, true)
	entitlement := deviceEntitlement(t, "computer:17")

	got, err := devices.replacedGrantID(context.Background(), assignee{username: "old.user", email: "old.user@ex.com"}, entitlement)

	if err != nil {
		t.Fatalf("replacedGrantID: %v", err)
	}
	if want := wantReplacedGrantID(t, "7", entitlement); got != want {
		t.Errorf("replacedGrantID = %q, want %q", got, want)
	}
	if usersCalls != 1 {
		t.Errorf("users requests = %d, want 1", usersCalls)
	}
}

// An outgoing assignee that is not a synced user falls back to the external-match user ID deviceGrants emits.
func TestReplacedGrantID_NotFound_ExternalMatch(t *testing.T) {
	var usersCalls int
	client := newTestJamfClient(t, replacedGrantIDHandler(t, nil, &usersCalls))
	devices := managedDeviceBuilder(client, true)
	entitlement := deviceEntitlement(t, "computer:17")

	got, err := devices.replacedGrantID(context.Background(), assignee{email: "ghost@ex.com"}, entitlement)

	if err != nil {
		t.Fatalf("replacedGrantID: %v", err)
	}
	externalUserID, err := rs.NewResourceID(resourceTypeUser, "ghost@ex.com")
	if err != nil {
		t.Fatalf("NewResourceID: %v", err)
	}
	if want := grant.NewGrantID(externalUserID, entitlement); got != want {
		t.Errorf("replacedGrantID = %q, want %q", got, want)
	}
	if usersCalls != 1 {
		t.Errorf("users requests = %d, want 1", usersCalls)
	}
}

// Without a user sync the outgoing assignee is the ExternalResourceMatch user ID sync emits, with no users lookup.
func TestReplacedGrantID_UsersNotSynced_ExternalMatch(t *testing.T) {
	var usersCalls int
	users := []map[string]any{{"id": "7", "username": "old.user", "email": "old.user@ex.com"}}
	client := newTestJamfClient(t, replacedGrantIDHandler(t, users, &usersCalls))
	devices := managedDeviceBuilder(client, false)
	entitlement := deviceEntitlement(t, "computer:17")

	got, err := devices.replacedGrantID(context.Background(), assignee{username: "old.user", email: "old.user@ex.com"}, entitlement)

	if err != nil {
		t.Fatalf("replacedGrantID: %v", err)
	}
	externalUserID, err := rs.NewResourceID(resourceTypeUser, "old.user@ex.com")
	if err != nil {
		t.Fatalf("NewResourceID: %v", err)
	}
	if want := grant.NewGrantID(externalUserID, entitlement); got != want {
		t.Errorf("replacedGrantID = %q, want %q", got, want)
	}
	if usersCalls != 0 {
		t.Errorf("users requests = %d, want 0", usersCalls)
	}
}

// Every device carries the assigned entitlement, assigned or not, grantable to users.
func TestManagedDeviceStaticEntitlements(t *testing.T) {
	entitlements, _, err := managedDeviceBuilder(nil, false).StaticEntitlements(context.Background(), rs.SyncOpAttrs{})
	if err != nil {
		t.Fatalf("StaticEntitlements: %v", err)
	}
	if len(entitlements) != 1 {
		t.Fatalf("want 1 static entitlement, got %d", len(entitlements))
	}
	if got := entitlements[0].GetSlug(); got != "assigned" {
		t.Errorf("slug = %q, want assigned", got)
	}
	grantableTo := entitlements[0].GetGrantableTo()
	if len(grantableTo) != 1 || grantableTo[0].GetId() != resourceTypeUser.Id {
		t.Errorf("grantable to %v, want only %s", grantableTo, resourceTypeUser.Id)
	}
}

// externalResourceMatch returns the grant's ExternalResourceMatch annotation and whether it has one.
func externalResourceMatch(t *testing.T, deviceGrant *v2.Grant) (*v2.ExternalResourceMatch, bool) {
	t.Helper()
	match := &v2.ExternalResourceMatch{}
	grantAnnotations := annotations.Annotations(deviceGrant.GetAnnotations())
	found, err := grantAnnotations.Pick(match)
	if err != nil {
		t.Fatalf("pick ExternalResourceMatch: %v", err)
	}
	return match, found
}

// getManyCountingStore counts the session-store reads of a grants walk.
type getManyCountingStore struct {
	*memorySessionStore
	getManyCalls int
}

func (store *getManyCountingStore) GetMany(ctx context.Context, keys []string, opts ...sessions.SessionStoreOption) (map[string][]byte, []string, error) {
	store.getManyCalls++
	return store.memorySessionStore.GetMany(ctx, keys, opts...)
}

// The grants walk reads the computers' assignee section, then the mobile devices, and resolves each page's
// assignees, by username then email, with one GetManyJSON. Assignees the user sync never saw become an
// ExternalResourceMatch.
func TestManagedDeviceGrantsForResourceType(t *testing.T) {
	type externalMatch struct{ key, value string }

	// One assigned computer on each side of the grants page boundary.
	pagedComputers := make([]jamf.ComputerInventory, 0, deviceGrantsPageSize+1)
	for _, id := range idRange(1, deviceGrantsPageSize+1) {
		pagedComputers = append(pagedComputers, jamf.ComputerInventory{ID: strconv.Itoa(id)})
	}
	pagedComputers[0].UserAndLocation = &jamf.ComputerUserAndLocation{Username: "asmith"}
	pagedComputers[deviceGrantsPageSize].UserAndLocation = &jamf.ComputerUserAndLocation{Username: "jdoe"}

	tests := []struct {
		name             string
		syncUsers        bool
		computers        []jamf.ComputerInventory
		mobileDevices    []jamf.MobileDevice
		wantGrants       map[string]externalMatch // grant ID -> match; the zero value is a direct grant
		wantPages        int
		wantGetManyCalls int
	}{
		{
			name:      "synced users resolved by username before email, one GetManyJSON per page",
			syncUsers: true,
			computers: []jamf.ComputerInventory{
				{ID: "1", UserAndLocation: &jamf.ComputerUserAndLocation{Username: "JDoe", Email: "asmith@example.com"}},
				{ID: "2"},
				{ID: "3", UserAndLocation: &jamf.ComputerUserAndLocation{Username: "asmith"}},
			},
			mobileDevices: []jamf.MobileDevice{{ID: "4", Username: "asmith"}, {ID: "5"}},
			wantGrants: map[string]externalMatch{
				"managedDevice:computer:1:assigned:user:7": {},
				"managedDevice:computer:3:assigned:user:9": {},
				"managedDevice:mobile:4:assigned:user:9":   {},
			},
			wantPages:        2,
			wantGetManyCalls: 2,
		},
		{
			name:      "username equal to a lower-id user's email resolves to the lower id",
			syncUsers: true,
			computers: []jamf.ComputerInventory{
				{ID: "1", UserAndLocation: &jamf.ComputerUserAndLocation{Username: "ops@example.com"}},
			},
			wantGrants:       map[string]externalMatch{"managedDevice:computer:1:assigned:user:10": {}},
			wantPages:        2,
			wantGetManyCalls: 1,
		},
		{
			name:      "unknown username with a synced user's email resolves to that user",
			syncUsers: true,
			computers: []jamf.ComputerInventory{
				{ID: "1", UserAndLocation: &jamf.ComputerUserAndLocation{Username: "jdoe-renamed", Email: "jdoe@example.com"}},
			},
			wantGrants:       map[string]externalMatch{"managedDevice:computer:1:assigned:user:7": {}},
			wantPages:        2,
			wantGetManyCalls: 1,
		},
		{
			name:      "blank username with a synced user's email resolves to that user",
			syncUsers: true,
			computers: []jamf.ComputerInventory{
				{ID: "1", UserAndLocation: &jamf.ComputerUserAndLocation{Email: "jdoe@example.com"}},
			},
			wantGrants:       map[string]externalMatch{"managedDevice:computer:1:assigned:user:7": {}},
			wantPages:        2,
			wantGetManyCalls: 1,
		},
		{
			name:      "blank username with an email is matched externally by email when users are not synced",
			syncUsers: false,
			computers: []jamf.ComputerInventory{
				{ID: "1", UserAndLocation: &jamf.ComputerUserAndLocation{Email: "jdoe@example.com"}},
			},
			wantGrants: map[string]externalMatch{
				"managedDevice:computer:1:assigned:user:jdoe@example.com": {key: "email", value: "jdoe@example.com"},
			},
			wantPages:        2,
			wantGetManyCalls: 0,
		},
		{
			name:      "unsynced assignee matched by email",
			syncUsers: true,
			computers: []jamf.ComputerInventory{
				{ID: "1", UserAndLocation: &jamf.ComputerUserAndLocation{Username: "ghost", Email: "ghost@example.com"}},
			},
			wantGrants: map[string]externalMatch{
				"managedDevice:computer:1:assigned:user:ghost@example.com": {key: "email", value: "ghost@example.com"},
			},
			wantPages:        2,
			wantGetManyCalls: 1,
		},
		{
			name:      "unsynced assignee without an email matched by username",
			syncUsers: true,
			computers: []jamf.ComputerInventory{
				{ID: "1", UserAndLocation: &jamf.ComputerUserAndLocation{Username: "ghost"}},
			},
			mobileDevices: []jamf.MobileDevice{{ID: "2", Username: "ghost-mobile"}},
			wantGrants: map[string]externalMatch{
				"managedDevice:computer:1:assigned:user:ghost":      {key: "username", value: "ghost"},
				"managedDevice:mobile:2:assigned:user:ghost-mobile": {key: "username", value: "ghost-mobile"},
			},
			wantPages:        2,
			wantGetManyCalls: 2,
		},
		{
			name:      "whitespace-only assignee emits no grant",
			syncUsers: true,
			computers: []jamf.ComputerInventory{
				{ID: "1", UserAndLocation: &jamf.ComputerUserAndLocation{Username: " ", Email: "\t"}},
			},
			mobileDevices:    []jamf.MobileDevice{{ID: "2", Username: "  "}},
			wantPages:        2,
			wantGetManyCalls: 0,
		},
		{
			name:      "users not synced: no session read, assignees matched externally",
			syncUsers: false,
			computers: []jamf.ComputerInventory{
				{ID: "1", UserAndLocation: &jamf.ComputerUserAndLocation{Username: "jdoe", Email: "jdoe@example.com"}},
			},
			mobileDevices: []jamf.MobileDevice{{ID: "2", Username: "jdoe"}},
			wantGrants: map[string]externalMatch{
				"managedDevice:computer:1:assigned:user:jdoe@example.com": {key: "email", value: "jdoe@example.com"},
				"managedDevice:mobile:2:assigned:user:jdoe":               {key: "username", value: "jdoe"},
			},
			wantPages:        2,
			wantGetManyCalls: 0,
		},
		{
			name:      "assignees on both sides of a page boundary are granted",
			syncUsers: true,
			computers: pagedComputers,
			wantGrants: map[string]externalMatch{
				"managedDevice:computer:1:assigned:user:9":    {},
				"managedDevice:computer:1001:assigned:user:7": {},
			},
			wantPages:        3,
			wantGetManyCalls: 2,
		},
	}

	const computersPath, mobileDevicesPath = "/api/v4/computers-inventory", "/api/v2/mobile-devices"
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var requests []string
			client := newTestJamfClient(t, func(w http.ResponseWriter, r *http.Request) {
				query := r.URL.Query()
				page, pageErr := strconv.Atoi(query.Get("page"))
				pageSize, sizeErr := strconv.Atoi(query.Get("page-size"))
				if r.Method != http.MethodGet || pageErr != nil || sizeErr != nil || query.Get("sort") != "id:asc" {
					t.Errorf("unexpected request %s %s", r.Method, r.URL)
					http.Error(w, "unexpected request", http.StatusBadRequest)
					return
				}
				requests = append(requests, r.URL.Path)

				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case computersPath:
					if sections := query["section"]; !slices.Equal(sections, []string{"USER_AND_LOCATION"}) {
						t.Errorf("computers sections = %v, want only USER_AND_LOCATION", sections)
					}
					start := min(page*pageSize, len(tc.computers))
					encodeJSON(t, w, jamf.ComputersInventoryResponse{TotalCount: len(tc.computers), Results: tc.computers[start:min(start+pageSize, len(tc.computers))]})
				case mobileDevicesPath:
					start := min(page*pageSize, len(tc.mobileDevices))
					encodeJSON(t, w, jamf.MobileDevicesResponse{TotalCount: len(tc.mobileDevices), Results: tc.mobileDevices[start:min(start+pageSize, len(tc.mobileDevices))]})
				default:
					t.Errorf("unexpected request %s %s", r.Method, r.URL)
					http.Error(w, "unexpected request", http.StatusNotFound)
				}
			})
			memoryStore := newMemorySessionStore()
			syncedUsers := []jamf.ProUser{
				{ID: 7, Username: "jdoe", Email: "jdoe@example.com"},
				{ID: 9, Username: "asmith", Email: "asmith@example.com"},
				{ID: 10, Username: "ops", Email: "ops@example.com"},
				{ID: 11, Username: "ops@example.com", Email: "ops-owner@example.com"},
			}
			if err := cacheUserIDs(context.Background(), memoryStore, syncedUsers); err != nil {
				t.Fatalf("cacheUserIDs: %v", err)
			}
			store := &getManyCountingStore{memorySessionStore: memoryStore}
			devices := managedDeviceBuilder(client, tc.syncUsers)
			walkGrants := func(ctx context.Context, _ *v2.Resource, attrs rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
				return devices.GrantsForResourceType(ctx, resourceTypeManagedDevice.Id, attrs)
			}

			grants, pages := collectGrants(t, walkGrants, nil, store)

			gotGrants := make(map[string]externalMatch, len(grants))
			for _, deviceGrant := range grants {
				var got externalMatch
				if match, found := externalResourceMatch(t, deviceGrant); found {
					got = externalMatch{key: match.GetKey(), value: match.GetValue()}
				}
				gotGrants[deviceGrant.GetId()] = got
			}
			if len(grants) != len(gotGrants) || !maps.Equal(gotGrants, tc.wantGrants) {
				t.Errorf("grants = %v (%d emitted), want %v", gotGrants, len(grants), tc.wantGrants)
			}
			if pages != tc.wantPages {
				t.Errorf("grants pages = %d, want %d", pages, tc.wantPages)
			}
			if store.getManyCalls != tc.wantGetManyCalls {
				t.Errorf("session-store reads = %d, want %d", store.getManyCalls, tc.wantGetManyCalls)
			}
			mobileDevicesStarted := false
			for _, path := range requests {
				if path == mobileDevicesPath {
					mobileDevicesStarted = true
				} else if mobileDevicesStarted {
					t.Errorf("computers were read after the mobile devices started: %v", requests)
					break
				}
			}
		})
	}
}

// List walks every computer page, then the mobile devices, without dropping a device at a page boundary.
func TestManagedDeviceList_WalksEveryPage(t *testing.T) {
	computers := make([]jamf.ComputerInventory, 0, devicePageSize+1)
	wantIDs := make([]string, 0, devicePageSize+2)
	for _, id := range idRange(1, devicePageSize+1) {
		computers = append(computers, jamf.ComputerInventory{ID: strconv.Itoa(id)})
		wantIDs = append(wantIDs, "computer:"+strconv.Itoa(id))
	}
	mobileDevices := []jamf.MobileDevice{{ID: "1"}}
	wantIDs = append(wantIDs, "mobile:1")

	client := newTestJamfClient(t, func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		page, pageErr := strconv.Atoi(query.Get("page"))
		pageSize, pageSizeErr := strconv.Atoi(query.Get("page-size"))
		if r.Method != http.MethodGet || pageErr != nil || pageSizeErr != nil {
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v4/computers-inventory":
			start := min(page*pageSize, len(computers))
			encodeJSON(t, w, jamf.ComputersInventoryResponse{TotalCount: len(computers), Results: computers[start:min(start+pageSize, len(computers))]})
		case "/api/v2/mobile-devices":
			start := min(page*pageSize, len(mobileDevices))
			encodeJSON(t, w, jamf.MobileDevicesResponse{TotalCount: len(mobileDevices), Results: mobileDevices[start:min(start+pageSize, len(mobileDevices))]})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	})
	devices := managedDeviceBuilder(client, true)

	var listedIDs []string
	token := ""
	for calls := 1; ; calls++ {
		if calls > 10 {
			t.Fatalf("List did not end after %d calls", calls-1)
		}
		resources, results, err := devices.List(context.Background(), nil, rs.SyncOpAttrs{PageToken: pagination.Token{Token: token}})
		if err != nil {
			t.Fatalf("List call %d: %v", calls, err)
		}
		for _, resource := range resources {
			listedIDs = append(listedIDs, resource.GetId().GetResource())
		}
		token = results.NextPageToken
		if token == "" {
			break
		}
	}

	if !slices.Equal(listedIDs, wantIDs) {
		t.Errorf("listed %d devices %v, want %d %v", len(listedIDs), listedIDs, len(wantIDs), wantIDs)
	}
}

// The last of UsersPageSize+1 users reuses user 1's email on the second page; the lowest ID keeps it.
func TestDeviceGrants_KeyReusedOnLaterPage_KeepsLowestID(t *testing.T) {
	userCount := jamf.UsersPageSize + 1
	users := make([]map[string]any, 0, userCount)
	for _, id := range idRange(1, userCount) {
		email := fmt.Sprintf("user%d@example.com", id)
		if id == userCount {
			email = "user1@example.com"
		}
		users = append(users, map[string]any{
			"id":       strconv.Itoa(id),
			"username": fmt.Sprintf("user%d", id),
			"realname": fmt.Sprintf("User Number%d", id),
			"email":    email,
		})
	}
	client := newTestJamfClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v4/computers-inventory" {
			w.Header().Set("Content-Type", "application/json")
			encodeJSON(t, w, jamf.ComputersInventoryResponse{TotalCount: 1, Results: []jamf.ComputerInventory{
				{ID: "17", UserAndLocation: &jamf.ComputerUserAndLocation{Email: "user1@example.com"}},
			}})
			return
		}
		query := r.URL.Query()
		page, pageErr := strconv.Atoi(query.Get("page"))
		pageSize, pageSizeErr := strconv.Atoi(query.Get("page-size"))
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/users" || pageErr != nil || pageSizeErr != nil {
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}

		start := min(page*pageSize, len(users))
		end := min(start+pageSize, len(users))
		w.Header().Set("Content-Type", "application/json")
		encodeJSON(t, w, map[string]any{"totalCount": len(users), "results": users[start:end]})
	})
	store := newMemorySessionStore()
	ctx := context.Background()
	userSyncer := userBuilder(client, true)
	_, results, err := userSyncer.List(ctx, nil, rs.SyncOpAttrs{Session: store})
	if err != nil {
		t.Fatalf("user List page 1: %v", err)
	}
	_, _, err = userSyncer.List(ctx, nil, rs.SyncOpAttrs{Session: store, PageToken: pagination.Token{Token: results.NextPageToken}})
	if err != nil {
		t.Fatalf("user List page 2: %v", err)
	}
	devices := managedDeviceBuilder(client, true)

	grants, _, err := devices.GrantsForResourceType(ctx, resourceTypeManagedDevice.Id, rs.SyncOpAttrs{Session: store})

	if err != nil {
		t.Fatalf("device GrantsForResourceType: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("want 1 grant, got %d", len(grants))
	}
	if got := grants[0].GetPrincipal().GetId(); got.GetResourceType() != resourceTypeUser.Id || got.GetResource() != "1" {
		t.Errorf("principal = %s/%s, want user/1", got.GetResourceType(), got.GetResource())
	}
}
