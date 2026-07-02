package connector

import (
	"context"
	"testing"
	"time"

	"github.com/conductorone/baton-jamf/pkg/jamf"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
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

	// assignee identity is stashed in the profile so Entitlements/Grants can
	// emit the device->user grant.
	if got := trait.GetProfile().GetFields()["assigned_username"].GetStringValue(); got != "jappleseed" {
		t.Errorf("profile.assigned_username = %q, want jappleseed", got)
	}
	if got := trait.GetProfile().GetFields()["assigned_email"].GetStringValue(); got != "jappleseed@ex.com" {
		t.Errorf("profile.assigned_email = %q, want jappleseed@ex.com", got)
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

	// profile long-tail.
	fields := trait.GetProfile().GetFields()
	if fields["site"].GetStringValue() != "HQ" {
		t.Errorf("profile.site = %q, want HQ", fields["site"].GetStringValue())
	}
	if fields["building_id"].GetStringValue() != "3" {
		t.Errorf("profile.building_id = %q, want 3", fields["building_id"].GetStringValue())
	}
	if fields["department_id"].GetStringValue() != "7" {
		t.Errorf("profile.department_id = %q, want 7", fields["department_id"].GetStringValue())
	}
	if !fields["activation_lock_enabled"].GetBoolValue() {
		t.Error("profile.activation_lock_enabled should be true")
	}

	// A resolvable assignee produces a direct grant to the synced Jamf user.
	grants, err := deviceGrants(r, testUserIndex())
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
	if got := trait.GetProfile().GetFields()["assigned_username"].GetStringValue(); got != "ghost" {
		t.Errorf("profile.assigned_username = %q, want ghost", got)
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
	grants, err := deviceGrants(r, testUserIndex())
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
	grants, err := deviceGrants(r, testUserIndex())
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
	if got := trait.GetProfile().GetFields()["assigned_username"].GetStringValue(); got != "jappleseed" {
		t.Errorf("profile.assigned_username = %q, want jappleseed", got)
	}

	grants, err := deviceGrants(r, testUserIndex())
	if err != nil {
		t.Fatalf("deviceGrants: %v", err)
	}
	if len(grants) != 1 || grants[0].GetPrincipal().GetId().GetResource() != "42" {
		t.Error("assignee should resolve to a direct grant on synced user 42")
	}
}

func TestHasMorePages(t *testing.T) {
	cases := []struct {
		name                             string
		page, pageSize, total, gotOnPage int
		want                             bool
	}{
		{"empty page stops", 0, 100, 500, 0, false},
		{"more by total", 0, 100, 250, 100, true},
		{"last by total", 2, 100, 250, 50, false},
		{"exact boundary stops", 1, 100, 200, 100, false},
		{"unknown total full page continues", 0, 100, 0, 100, true},
		{"unknown total partial page stops", 0, 100, 0, 40, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasMorePages(tc.page, tc.pageSize, tc.total, tc.gotOnPage); got != tc.want {
				t.Errorf("hasMorePages(%d,%d,%d,%d) = %v, want %v", tc.page, tc.pageSize, tc.total, tc.gotOnPage, got, tc.want)
			}
		})
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
