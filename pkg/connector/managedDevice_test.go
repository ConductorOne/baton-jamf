package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	grants, err := deviceGrants(r, "jappleseed", "jappleseed@ex.com", testUserIndex())
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
				PartitionFileVault2State: "NOT_ENCRYPTED",
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
	grants, err := deviceGrants(r, "ghost", "", testUserIndex())
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

func TestComputerResource_NoAssignee(t *testing.T) {
	c := &jamf.ComputerInventory{
		ID:       "5",
		General:  &jamf.ComputerGeneral{Name: "Lab Mac"},
		Hardware: &jamf.ComputerHardware{ModelIdentifier: "Macmini9,1"},
	}

	r, err := computerResource(c, nil)
	if err != nil {
		t.Fatalf("computerResource: %v", err)
	}

	// No assignee -> no entitlement and no grant.
	d := &managedDeviceResourceType{}
	ents, _, err := d.Entitlements(context.Background(), r, rs.SyncOpAttrs{})
	if err != nil {
		t.Fatalf("Entitlements: %v", err)
	}
	if len(ents) != 0 {
		t.Errorf("want 0 entitlements for unassigned device, got %d", len(ents))
	}
	grants, err := deviceGrants(r, "", "", testUserIndex())
	if err != nil {
		t.Fatalf("deviceGrants: %v", err)
	}
	if len(grants) != 0 {
		t.Errorf("want 0 grants for unassigned device, got %d", len(grants))
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
	grants, err := deviceGrants(r, "jappleseed", "", testUserIndex())
	if err != nil {
		t.Fatalf("deviceGrants: %v", err)
	}
	if len(grants) != 1 || grants[0].GetPrincipal().GetId().GetResource() != "42" {
		t.Error("assignee should resolve to a direct grant on synced user 42")
	}
}

func TestHasMorePages(t *testing.T) {
	cases := []struct {
		name                                   string
		seenBefore, pageSize, total, gotOnPage int
		want                                   bool
	}{
		{"empty page stops", 500, 100, 500, 0, false},
		{"more by total", 0, 100, 250, 100, true},
		{"last by total", 200, 100, 250, 50, false},
		{"exact boundary stops", 100, 100, 200, 100, false},
		{"unknown total full page continues", 0, 100, 0, 100, true},
		{"unknown total partial page stops", 0, 100, 0, 40, false},
		// Jamf caps page-size below the requested value: pages return fewer
		// records than pageSize, but cumulative progress keeps paging until
		// totalCount is reached instead of terminating early.
		{"capped first page continues", 0, 1000, 500, 200, true},
		{"capped middle page continues", 200, 1000, 500, 200, true},
		{"capped final page stops", 400, 1000, 500, 100, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasMorePages(tc.seenBefore, tc.pageSize, tc.total, tc.gotOnPage); got != tc.want {
				t.Errorf("hasMorePages(%d,%d,%d,%d) = %v, want %v", tc.seenBefore, tc.pageSize, tc.total, tc.gotOnPage, got, tc.want)
			}
		})
	}
}

func TestParseDevicePageToken(t *testing.T) {
	cases := []struct {
		token              string
		wantPage, wantSeen int
	}{
		{"", 0, 0},
		{"0:0", 0, 0},
		{"3:250", 3, 250},
		{"5", 5, 0}, // bare page number: seen unknown
		{"bad", 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.token, func(t *testing.T) {
			page, seen := parseDevicePageToken(tc.token)
			if page != tc.wantPage || seen != tc.wantSeen {
				t.Errorf("parseDevicePageToken(%q) = (%d,%d), want (%d,%d)", tc.token, page, seen, tc.wantPage, tc.wantSeen)
			}
		})
	}
}

func deviceResourceForTest(t *testing.T, objectID string) *v2.Resource {
	t.Helper()
	return &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeManagedDevice.Id, Resource: objectID}}
}

func deviceEntitlement(t *testing.T, objectID string) *v2.Entitlement {
	t.Helper()
	return ent.NewAssignmentEntitlement(deviceResourceForTest(t, objectID), assignedEntitlement, ent.WithGrantableTo(resourceTypeUser))
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
// email-based matching (Fix 1) and externally-matched principals (Fix 2 —
// which never hits the /JSSResource/users/ endpoint at all, since there is no
// numeric Jamf user id to resolve).
func jamfDeviceAssignHandlerEmail(t *testing.T, principalUsername, principalEmail, currentUsername, currentEmail string, gotPATCHBody *[]byte) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
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
// username-priority rule: the device's current username is non-empty ("bob")
// and differs from the principal's resolved username ("old.name"), even
// though a stale email happens to equal the principal's email. Email must be
// ignored whenever a current username is present — Jamf never auto-populates
// a computer's email when its username changes, so matching on a
// coincidental/stale email here would let Revoke clear a different, live
// assignee's data.
func TestManagedDeviceRevoke_UsernameDiffersButEmailMatches_NoPatch(t *testing.T) {
	var patchBody []byte
	client := newTestJamfClient(t, jamfDeviceAssignHandlerEmail(t, "old.name", "jappleseed@ex.com", "bob", "jappleseed@ex.com", &patchBody))
	d := managedDeviceBuilder(client)

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

// TestManagedDeviceRevoke_ExternalMatchPrincipal_Patches covers Fix 2: a
// grant built by deviceGrants for an assignee that isn't a synced Jamf user
// carries a principal whose ResourceId.Resource is the raw email/username
// string (not a numeric Jamf user id), annotated with an
// ExternalResourceMatch. Revoke must recover that raw value from the
// annotation and compare it directly against the device's current assignee,
// rather than calling resolvePrincipalUser/GetUserDetails — which would fail
// with InvalidArgument on a non-numeric id. The device's current username is
// empty here (requirement (b)): the principal only carries an email (the
// annotation's key is "email"), so matching falls back to comparing emails,
// which only happens when the current username is empty.
func TestManagedDeviceRevoke_ExternalMatchPrincipal_Patches(t *testing.T) {
	var patchBody []byte
	// The /JSSResource/users/ principal fields are deliberately implausible
	// ("unused"/"unused@ex.com"): if Revoke incorrectly fell back to
	// resolvePrincipalUser here, strconv.Atoi("ghost@ex.com") would fail
	// before that endpoint is ever hit, catching the bug either way.
	client := newTestJamfClient(t, jamfDeviceAssignHandlerEmail(t, "unused", "unused@ex.com", "", "ghost@ex.com", &patchBody))
	d := managedDeviceBuilder(client)

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
	if annos != nil {
		t.Errorf("expected no annotations (grant should be revoked), got %v", annos)
	}
	if patchBody == nil {
		t.Fatal("expected a PATCH to be sent for an externally-matched principal that matches the current assignee")
	}
	if want := `{"userAndLocation":{"username":"","realname":"","email":"","position":"","phone":""}}` + "\n"; string(patchBody) != want {
		t.Errorf("PATCH body = %q, want %q", string(patchBody), want)
	}
}

// TestManagedDeviceRevoke_ExternalMatchPrincipal_EmailOnly_DeviceHasUsername_Clears
// covers a bug fix: deviceGrants keys an unsynced assignee's grant by email
// whenever the assignee has one, even if the device also has a username —
// so the resulting ExternalResourceMatch principal here carries no username
// at all. assigneeMatches must still compare by email in that case, even
// though the device's current assignee ALSO reports a username. Before the
// fix, matching was keyed off the device's username being present, so this
// case always fell through to GrantAlreadyRevoked without clearing.
func TestManagedDeviceRevoke_ExternalMatchPrincipal_EmailOnly_DeviceHasUsername_Clears(t *testing.T) {
	var patchBody []byte
	client := newTestJamfClient(t, jamfDeviceAssignHandlerEmail(t, "unused", "unused@ex.com", "bob", "ghost@ex.com", &patchBody))
	d := managedDeviceBuilder(client)

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
	if annos != nil {
		t.Errorf("expected no annotations (grant should be revoked), got %v", annos)
	}
	if patchBody == nil {
		t.Fatal("expected a PATCH to be sent: the principal's email matches the device's current assignee even though the device also reports a username")
	}
}

// TestManagedDeviceGrant_Computer_PatchesUserAndLocation grants a
// previously-unassigned device (current assignee "" from the mock's detail
// GET): no prior assignee means no displacement, so this also covers
// requirement (c) — no GrantReplaced when nothing was displaced. The mock's
// /JSSResource/users/ response only sets username, so this also covers all
// five keys being sent with empty strings for the attributes the new
// assignee lacks (realname, email, position, phone).
func TestManagedDeviceGrant_Computer_PatchesUserAndLocation(t *testing.T) {
	var patchBody []byte
	client := newTestJamfClient(t, jamfDeviceAssignHandlerWithCurrent(t, "jappleseed", "", &patchBody))
	d := managedDeviceBuilder(client)

	grants, annos, err := d.Grant(context.Background(), userPrincipal(t, 42), deviceEntitlement(t, "computer:17"))
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("want 1 grant, got %d", len(grants))
	}
	if annos != nil {
		t.Errorf("expected no annotations for a previously-unassigned device, got %v", annos)
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
	d := managedDeviceBuilder(client)

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
	d := managedDeviceBuilder(client)

	grants, annos, err := d.Grant(context.Background(), userPrincipal(t, 42), deviceEntitlement(t, "mobile:3"))
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("want 1 grant, got %d", len(grants))
	}
	if annos != nil {
		t.Errorf("expected no annotations for a previously-unassigned device, got %v", annos)
	}
	if want := `{"location":{"username":"jappleseed"}}` + "\n"; string(patchBody) != want {
		t.Errorf("PATCH body = %q, want %q", string(patchBody), want)
	}
}

// TestManagedDeviceGrant_Mobile_NoUsername_FailedPrecondition covers the
// requirement that a mobile Grant must never send an empty or
// email-derived username to Jamf: if the principal's Jamf user record has
// no username, Grant must reject the request before issuing any PATCH.
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
	d := managedDeviceBuilder(client)

	_, _, err := d.Grant(context.Background(), userPrincipal(t, 42), deviceEntitlement(t, "mobile:3"))
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("Grant err = %v, want FailedPrecondition", err)
	}
}

// TestManagedDeviceGrant_UsernameDiffersButEmailMatches_ProceedsToPatch
// covers requirement (a) on the Grant side: the device's current username
// ("bob") differs from the principal's resolved username ("alice"), even
// though a stale/coincidental email on the device equals the principal's
// email. Grant must proceed to PATCH the new assignment instead of
// short-circuiting to GrantAlreadyExists on the stale email match.
func TestManagedDeviceGrant_UsernameDiffersButEmailMatches_ProceedsToPatch(t *testing.T) {
	var patchBody []byte
	client := newTestJamfClient(t, jamfDeviceAssignHandlerEmail(t, "alice", "alice@ex.com", "bob", "alice@ex.com", &patchBody))
	d := managedDeviceBuilder(client)

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

// TestManagedDeviceGrant_EmptyUsernameMatchesViaEmail_AlreadyExists covers
// requirement (b): when the device's current username is empty, Grant falls
// back to matching on email, so granting to the principal whose resolved
// email matches the device's current email must short-circuit to
// GrantAlreadyExists without issuing a PATCH.
func TestManagedDeviceGrant_EmptyUsernameMatchesViaEmail_AlreadyExists(t *testing.T) {
	var patchBody []byte
	client := newTestJamfClient(t, jamfDeviceAssignHandlerEmail(t, "alice", "alice@ex.com", "", "alice@ex.com", &patchBody))
	d := managedDeviceBuilder(client)

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
	d := managedDeviceBuilder(client)

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
	d := managedDeviceBuilder(client)

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
	d := managedDeviceBuilder(client)

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

// jamfDeviceGrantDisplaceHandler extends jamfDeviceAssignHandlerWithCurrent's
// computer-only endpoints with GET /JSSResource/users (base user list) and GET
// /JSSResource/users/id/{oldUserID} (outgoing-assignee detail), so
// getUserIndex can resolve the device's outgoing assignee to a synced user's
// ResourceId for Grant's GrantReplaced annotation. oldUserID == 0 models an
// outgoing assignee that isn't a synced Jamf user (GetUsers returns nobody
// matching), exercising the ExternalResourceMatch-style fallback instead.
type deviceGrantDisplaceScenario struct {
	principalID                       int
	principalUsername, principalEmail string
	currentUsername, currentEmail     string
	oldUserID                         int
	oldUsername, oldEmail             string
}

func jamfDeviceGrantDisplaceHandler(t *testing.T, sc deviceGrantDisplaceScenario, gotPATCHBody *[]byte) http.HandlerFunc {
	t.Helper()
	principalID, principalUsername, principalEmail := sc.principalID, sc.principalUsername, sc.principalEmail
	currentUsername, currentEmail := sc.currentUsername, sc.currentEmail
	oldUserID, oldUsername, oldEmail := sc.oldUserID, sc.oldUsername, sc.oldEmail
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/JSSResource/users/name/"):
			// replacedGrantID's direct GetUserByName lookup for the outgoing
			// assignee. oldUserID == 0 models an unsynced assignee: 404, so
			// replacedGrantID falls back to the index below.
			if oldUserID == 0 {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user": map[string]any{"id": oldUserID, "name": oldUsername, "username": oldUsername, "email": oldEmail},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/JSSResource/users":
			w.Header().Set("Content-Type", "application/json")
			var users []map[string]any
			if oldUserID != 0 {
				users = append(users, map[string]any{"id": oldUserID, "name": oldUsername})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"users": users})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, fmt.Sprintf("/JSSResource/users/id/%d", principalID)):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user": map[string]any{"id": principalID, "name": principalUsername, "username": principalUsername, "email": principalEmail},
			})
		case oldUserID != 0 && r.Method == http.MethodGet && strings.Contains(r.URL.Path, fmt.Sprintf("/JSSResource/users/id/%d", oldUserID)):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user": map[string]any{"id": oldUserID, "name": oldUsername, "username": oldUsername, "email": oldEmail},
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

// TestManagedDeviceGrant_DisplacesDifferentUser_ReturnsGrantReplaced covers
// requirement (a): granting a device that is currently assigned to a
// DIFFERENT, synced Jamf user must still PATCH the new assignment, and must
// report a GrantReplaced annotation naming the exact grant id of the assignee
// being displaced.
func TestManagedDeviceGrant_DisplacesDifferentUser_ReturnsGrantReplaced(t *testing.T) {
	var patchBody []byte
	client := newTestJamfClient(t, jamfDeviceGrantDisplaceHandler(t, deviceGrantDisplaceScenario{
		principalID: 42, principalUsername: "new.user",
		currentUsername: "old.user", currentEmail: "old.user@ex.com",
		oldUserID: 7, oldUsername: "old.user", oldEmail: "old.user@ex.com",
	}, &patchBody))
	d := managedDeviceBuilder(client)

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
// to any synced Jamf user via getUserIndex (oldUserID 0 — GetUsers returns
// nobody), so GrantReplaced must fall back to the same external-match-style
// principal id deviceGrants builds for that case.
func TestManagedDeviceGrant_DisplacesUnsyncedUser_ReturnsGrantReplacedExternalMatch(t *testing.T) {
	var patchBody []byte
	client := newTestJamfClient(t, jamfDeviceGrantDisplaceHandler(t, deviceGrantDisplaceScenario{
		principalID: 42, principalUsername: "new.user",
		currentUsername: "ghost", currentEmail: "ghost@ex.com",
	}, &patchBody))
	d := managedDeviceBuilder(client)

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
	d := managedDeviceBuilder(client)

	gr := grant.NewGrant(deviceEntitlement(t, "computer:17").Resource, assignedEntitlement, userPrincipal(t, 42).Id)
	annos, err := d.Revoke(context.Background(), gr)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if annos != nil {
		t.Errorf("expected no annotations, got %v", annos)
	}
	if want := `{"userAndLocation":{"username":"","realname":"","email":"","position":"","phone":""}}` + "\n"; string(patchBody) != want {
		t.Errorf("PATCH body = %q, want %q", string(patchBody), want)
	}
}

// TestManagedDeviceRevoke_ReassignedToDifferentUser_NoPatch covers the
// blocking review finding: if the device has been reassigned to a different
// user since this grant was last synced, Revoke must NOT blindly clear the
// live assignment. It should detect the mismatch, skip the PATCH entirely,
// and report the grant as already revoked.
func TestManagedDeviceRevoke_ReassignedToDifferentUser_NoPatch(t *testing.T) {
	var patchBody []byte
	// Grant's principal (Jamf user 42) resolves to "jappleseed", but the
	// device's current live assignee is "someone.else" — reassigned since
	// the grant being revoked was synced.
	client := newTestJamfClient(t, jamfDeviceAssignHandlerWithCurrent(t, "jappleseed", "someone.else", &patchBody))
	d := managedDeviceBuilder(client)

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
	d := managedDeviceBuilder(client)

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
	d := managedDeviceBuilder(client)

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
	d := managedDeviceBuilder(client)

	gr := grant.NewGrant(deviceEntitlement(t, "mobile:3").Resource, assignedEntitlement, userPrincipal(t, 42).Id)
	annos, err := d.Revoke(context.Background(), gr)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if annos != nil {
		t.Errorf("expected no annotations, got %v", annos)
	}
	if want := `{"location":{"username":""}}` + "\n"; string(patchBody) != want {
		t.Errorf("PATCH body = %q, want %q", string(patchBody), want)
	}
}

// TestManagedDeviceRevoke_EmailDoesNotMatch_StillClearsEverything covers the
// case where an admin set the device's current email to something unrelated
// to the username match that makes this grant "still the current assignee".
// Once assigneeMatches succeeds on username, Revoke clears the whole
// assignee identity unconditionally — it no longer gates email-clearing on
// whether the device's current email happens to match the principal's.
func TestManagedDeviceRevoke_EmailDoesNotMatch_StillClearsEverything(t *testing.T) {
	var patchBody []byte
	// Username matches ("jappleseed") so the grant is still live and Revoke
	// proceeds, even though the device's current email is some unrelated
	// admin-set value that does not match the principal's resolved email
	// (empty, since the mock's /JSSResource/users/ response carries no email).
	client := newTestJamfClient(t, jamfDeviceAssignHandlerEmail(t, "jappleseed", "", "jappleseed", "admin-set@ex.com", &patchBody))
	d := managedDeviceBuilder(client)

	gr := grant.NewGrant(deviceEntitlement(t, "computer:17").Resource, assignedEntitlement, userPrincipal(t, 42).Id)
	annos, err := d.Revoke(context.Background(), gr)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if annos != nil {
		t.Errorf("expected no annotations (grant should be revoked), got %v", annos)
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
	d := managedDeviceBuilder(client)

	// Keyed on username, not email: the device's current username ("ghost")
	// still matches, so assigneeMatches succeeds and Revoke proceeds, even
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
	if annos != nil {
		t.Errorf("expected no annotations (grant should be revoked), got %v", annos)
	}
	if patchBody == nil {
		t.Fatal("expected a PATCH to be sent to clear the assignee")
	}
	if want := `{"userAndLocation":{"username":"","realname":"","email":"","position":"","phone":""}}` + "\n"; string(patchBody) != want {
		t.Errorf("PATCH body = %q, want %q", string(patchBody), want)
	}
}

// TestPrincipalIdentityForRevoke_NoAnnotation_FallsBackOnRawIDShape covers
// Fix 6: when the platform doesn't send back an ExternalResourceMatch
// annotation AND the principal id isn't a numeric Jamf user id,
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
	username, email, err := principalIdentityForRevoke(context.Background(), client, gr)
	if err != nil {
		t.Fatalf("principalIdentityForRevoke: %v", err)
	}
	if username != "" || email != "ghost@ex.com" {
		t.Errorf("got (username=%q, email=%q), want (\"\", \"ghost@ex.com\") for an email-shaped raw id", username, email)
	}

	usernamePrincipal, err := rs.NewResourceID(resourceTypeUser, "ghost")
	if err != nil {
		t.Fatalf("NewResourceID: %v", err)
	}
	gr = grant.NewGrant(deviceEntitlement(t, "computer:17").Resource, assignedEntitlement, usernamePrincipal)
	username, email, err = principalIdentityForRevoke(context.Background(), client, gr)
	if err != nil {
		t.Fatalf("principalIdentityForRevoke: %v", err)
	}
	if username != "ghost" || email != "" {
		t.Errorf("got (username=%q, email=%q), want (\"ghost\", \"\") for a non-email-shaped raw id", username, email)
	}
}

func TestManagedDeviceGrant_NonUserPrincipal_Errors(t *testing.T) {
	d := managedDeviceBuilder(nil)
	_, _, err := d.Grant(context.Background(), userGroupPrincipal(t, 7), deviceEntitlement(t, "computer:17"))
	if err == nil {
		t.Fatal("expected an error granting device assignment to a non-user principal")
	}
}

func TestManagedDeviceRevoke_NonUserPrincipal_Errors(t *testing.T) {
	d := managedDeviceBuilder(nil)
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
	d := managedDeviceBuilder(client)

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
	d := managedDeviceBuilder(client)
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

// replacedGrantIDHandler serves the two endpoints replacedGrantID's
// resolution paths depend on: GET /JSSResource/users/name/{username} (the
// direct outgoing-assignee lookup) and GET /JSSResource/users plus GET
// /JSSResource/users/id/{id} (getUserIndex's full user-scan fallback).
// listCalls counts requests to the bare list endpoint, so tests can assert
// whether the full scan was paid for.
func replacedGrantIDHandler(t *testing.T, byNameStatus int, byNameID int, byNameUsername string, indexUsers []map[string]any, listCalls *int) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/JSSResource/users/name/"):
			if byNameStatus != http.StatusOK {
				w.WriteHeader(byNameStatus)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user": map[string]any{"id": byNameID, "name": byNameUsername, "username": byNameUsername},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/JSSResource/users":
			*listCalls++
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"users": indexUsers})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/JSSResource/users/id/"):
			idStr := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
			id, _ := strconv.Atoi(idStr)
			for _, u := range indexUsers {
				if u["id"] == id {
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{"user": u})
					return
				}
			}
			w.WriteHeader(http.StatusNotFound)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
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

// TestReplacedGrantID_DirectLookupHit_SkipsIndex covers the direct-lookup
// fast path: a non-empty username resolved by GetUserByName must short-circuit
// before ever touching the full user index/scan.
func TestReplacedGrantID_DirectLookupHit_SkipsIndex(t *testing.T) {
	var listCalls int
	client := newTestJamfClient(t, replacedGrantIDHandler(t, http.StatusOK, 7, "old.user", nil, &listCalls))
	d := managedDeviceBuilder(client)

	en := deviceEntitlement(t, "computer:17")
	rid, ok, err := d.replacedGrantID(context.Background(), "old.user", "old.user@ex.com", en)
	if err != nil {
		t.Fatalf("replacedGrantID: %v", err)
	}
	if !ok {
		t.Fatal("expected ok=true")
	}
	if want := wantReplacedGrantID(t, "7", en); rid != want {
		t.Errorf("replacedGrantID = %q, want %q", rid, want)
	}
	if listCalls != 0 {
		t.Errorf("expected the direct lookup to avoid the full user index scan, got %d calls to the users list endpoint", listCalls)
	}
}

// TestReplacedGrantID_DirectLookupNotFound_FallsBackToIndex covers a direct
// lookup 404 (the outgoing assignee isn't a synced Jamf user): replacedGrantID
// must fall back to the full index rather than treating the 404 as fatal.
func TestReplacedGrantID_DirectLookupNotFound_FallsBackToIndex(t *testing.T) {
	var listCalls int
	indexUsers := []map[string]any{{"id": 7, "name": "old.user"}}
	client := newTestJamfClient(t, replacedGrantIDHandler(t, http.StatusNotFound, 0, "", indexUsers, &listCalls))
	d := managedDeviceBuilder(client)

	en := deviceEntitlement(t, "computer:17")
	rid, ok, err := d.replacedGrantID(context.Background(), "old.user", "", en)
	if err != nil {
		t.Fatalf("replacedGrantID: %v", err)
	}
	if !ok {
		t.Fatal("expected ok=true")
	}
	if want := wantReplacedGrantID(t, "7", en); rid != want {
		t.Errorf("replacedGrantID = %q, want %q", rid, want)
	}
	if listCalls != 1 {
		t.Errorf("expected a 404 from the direct lookup to fall back to the full index, got %d calls to the users list endpoint", listCalls)
	}
}

// TestReplacedGrantID_EmptyUsername_GoesStraightToIndex covers an empty
// username (e.g. a device whose assignee was only ever attributed via
// email): replacedGrantID must never call GetUserByName with an empty name
// and should resolve straight through the index.
func TestReplacedGrantID_EmptyUsername_GoesStraightToIndex(t *testing.T) {
	var listCalls int
	indexUsers := []map[string]any{{"id": 7, "name": "old.user", "email": "old.user@ex.com"}}
	client := newTestJamfClient(t, replacedGrantIDHandler(t, http.StatusOK, 0, "", indexUsers, &listCalls))
	d := managedDeviceBuilder(client)

	en := deviceEntitlement(t, "computer:17")
	rid, ok, err := d.replacedGrantID(context.Background(), "", "old.user@ex.com", en)
	if err != nil {
		t.Fatalf("replacedGrantID: %v", err)
	}
	if !ok {
		t.Fatal("expected ok=true")
	}
	if want := wantReplacedGrantID(t, "7", en); rid != want {
		t.Errorf("replacedGrantID = %q, want %q", rid, want)
	}
	if listCalls != 1 {
		t.Errorf("want 1 call to the users list endpoint, got %d", listCalls)
	}
}

// TestReplacedGrantID_DirectLookupOtherError_FallsBackToIndex covers a
// non-404 error from the direct lookup (e.g. a transient 5xx): it must not
// fail the Grant, falling back to the full index exactly like a 404 would.
func TestReplacedGrantID_DirectLookupOtherError_FallsBackToIndex(t *testing.T) {
	var listCalls int
	indexUsers := []map[string]any{{"id": 7, "name": "old.user"}}
	client := newTestJamfClient(t, replacedGrantIDHandler(t, http.StatusInternalServerError, 0, "", indexUsers, &listCalls))
	d := managedDeviceBuilder(client)

	en := deviceEntitlement(t, "computer:17")
	rid, ok, err := d.replacedGrantID(context.Background(), "old.user", "", en)
	if err != nil {
		t.Fatalf("replacedGrantID: %v", err)
	}
	if !ok {
		t.Fatal("expected ok=true")
	}
	if want := wantReplacedGrantID(t, "7", en); rid != want {
		t.Errorf("replacedGrantID = %q, want %q", rid, want)
	}
	if listCalls != 1 {
		t.Errorf("expected a non-404 lookup error to fall back to the full index, got %d calls to the users list endpoint", listCalls)
	}
}

// emptyDevicePagesHandler serves empty computers-inventory and mobile-devices
// pages (ending the sync after one page of each phase), plus the Classic API
// users list endpoint used by getUserIndex, counting calls to the latter.
func emptyDevicePagesHandler(listCalls *int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v4/computers-inventory":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"results": []any{}, "totalCount": 0})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/mobile-devices":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"results": []any{}, "totalCount": 0})
		case r.Method == http.MethodGet && r.URL.Path == "/JSSResource/users":
			*listCalls++
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"users": []any{}})
		}
	}
}

// TestManagedDeviceList_InvalidatesUserIndex_OnNewSyncOnly covers the
// userIndex invalidation requirement: List must drop the cached index at the
// start of a new sync (its first page, carrying no incoming pagination
// cursor) so a long-running process never serves a stale user list across
// syncs, but must leave the cache alone between pages of the SAME sync.
func TestManagedDeviceList_InvalidatesUserIndex_OnNewSyncOnly(t *testing.T) {
	var listCalls int
	client := newTestJamfClient(t, emptyDevicePagesHandler(&listCalls))
	d := managedDeviceBuilder(client)
	ctx := context.Background()
	// getUserIndex's GET benefits from the HTTP client's response cache on
	// sync paths (see jamf.WithFreshReads' doc comment); bypass it here so
	// listCalls observes whether getUserIndex actually re-issued the request
	// rather than the in-process cache being masked by the HTTP-level one.
	indexCtx := jamf.WithFreshReads(ctx)

	// Sync 1, page 1 (no incoming cursor): builds the index for the first time.
	_, results, err := d.List(ctx, nil, rs.SyncOpAttrs{PageToken: pagination.Token{Token: ""}})
	if err != nil {
		t.Fatalf("List (sync 1, page 1): %v", err)
	}
	if _, err := d.getUserIndex(indexCtx); err != nil {
		t.Fatalf("getUserIndex: %v", err)
	}
	if listCalls != 1 {
		t.Fatalf("want 1 call to the users list endpoint after the first index build, got %d", listCalls)
	}
	if results.NextPageToken == "" {
		t.Fatal("expected a non-empty continuation token into the mobile-device phase")
	}

	// Sync 1, page 2 (carries sync 1's cursor): same sync, so the cached
	// index must survive untouched.
	if _, _, err := d.List(ctx, nil, rs.SyncOpAttrs{PageToken: pagination.Token{Token: results.NextPageToken}}); err != nil {
		t.Fatalf("List (sync 1, page 2): %v", err)
	}
	if _, err := d.getUserIndex(indexCtx); err != nil {
		t.Fatalf("getUserIndex: %v", err)
	}
	if listCalls != 1 {
		t.Errorf("want the cached index to survive across pages of the same sync, got %d calls to the users list endpoint", listCalls)
	}

	// Sync 2, page 1 (no incoming cursor again): a new sync must rebuild it.
	if _, _, err := d.List(ctx, nil, rs.SyncOpAttrs{PageToken: pagination.Token{Token: ""}}); err != nil {
		t.Fatalf("List (sync 2, page 1): %v", err)
	}
	if _, err := d.getUserIndex(indexCtx); err != nil {
		t.Fatalf("getUserIndex: %v", err)
	}
	if listCalls != 2 {
		t.Errorf("want a new sync's first page to rebuild the index, got %d calls to the users list endpoint", listCalls)
	}
}

// TestManagedDeviceEntitlements_NeverAssigned_EmitsNothing covers a device
// that has never reported an assignee (no prior sync recorded one): both
// Entitlements and Grants must emit nothing, keeping unassigned assets clean
// rather than advertising a grantable-but-never-granted entitlement.
func TestManagedDeviceEntitlements_NeverAssigned_EmitsNothing(t *testing.T) {
	client := newTestJamfClient(t, failOnCallHandler(t))
	d := managedDeviceBuilder(client)

	resource, err := computerResource(&jamf.ComputerInventory{ID: "99"}, nil)
	if err != nil {
		t.Fatalf("computerResource: %v", err)
	}

	entitlements, _, err := d.Entitlements(context.Background(), resource, rs.SyncOpAttrs{})
	if err != nil {
		t.Fatalf("Entitlements: %v", err)
	}
	if len(entitlements) != 0 {
		t.Errorf("want no entitlements for a never-assigned device, got %d", len(entitlements))
	}
	grants, _, err := d.Grants(context.Background(), resource, rs.SyncOpAttrs{})
	if err != nil {
		t.Fatalf("Grants: %v", err)
	}
	if len(grants) != 0 {
		t.Errorf("want no grants for a never-assigned device, got %d", len(grants))
	}
}
