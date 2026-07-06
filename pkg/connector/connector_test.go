package connector

import (
	"context"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/cli"
)

// syncedResourceTypeIDs returns the set of resource type IDs the connector
// registers for the given runtime options.
func syncedResourceTypeIDs(t *testing.T, opts *cli.ConnectorOpts) map[string]bool {
	t.Helper()
	j := &Jamf{opts: opts}
	ids := make(map[string]bool)
	for _, rb := range j.ResourceSyncers(context.Background()) {
		ids[rb.ResourceType(context.Background()).GetId()] = true
	}
	return ids
}

// TestManagedDeviceResourceTypeIsOptIn verifies the resource type advertises the
// OptInRequired annotation, which is what surfaces opt_in_required: true in
// baton_capabilities.json for the C1 platform to honor.
func TestManagedDeviceResourceTypeIsOptIn(t *testing.T) {
	annos := annotations.Annotations(resourceTypeManagedDevice.GetAnnotations())
	if !annos.Contains(&v2.OptInRequired{}) {
		t.Fatal("managedDevice resource type must carry the OptInRequired annotation")
	}
}

// TestManagedDeviceOffByDefault_NoFilter proves that a sync with no
// --sync-resource-types filter does NOT register the device syncer, so existing
// installs (whose Jamf role may lack Read Computers / Read Mobile Devices) never
// hit those endpoints unless devices are explicitly enabled.
func TestManagedDeviceOffByDefault_NoFilter(t *testing.T) {
	ids := syncedResourceTypeIDs(t, &cli.ConnectorOpts{})
	if ids[resourceTypeManagedDevice.Id] {
		t.Fatal("managedDevice must not be synced when no resource-type filter is set (opt-in required)")
	}
	// The non-opt-in types must still sync by default.
	for _, id := range []string{resourceTypeUser.Id, resourceTypeGroup.Id, resourceTypeRole.Id, resourceTypeSite.Id} {
		if !ids[id] {
			t.Fatalf("expected %q to sync by default", id)
		}
	}
}

// TestManagedDeviceOffByDefault_OtherTypeExplicit proves that an explicit filter
// that does not name managedDevice leaves it off.
func TestManagedDeviceOffByDefault_OtherTypeExplicit(t *testing.T) {
	ids := syncedResourceTypeIDs(t, &cli.ConnectorOpts{
		SyncResourceTypeIDs: []string{resourceTypeUser.Id},
	})
	if ids[resourceTypeManagedDevice.Id] {
		t.Fatal("managedDevice must not sync when an explicit filter omits it")
	}
	if !ids[resourceTypeUser.Id] {
		t.Fatal("expected user to sync when explicitly selected")
	}
}

// TestManagedDeviceSyncsWhenExplicitlyOptedIn proves that naming managedDevice
// in the filter registers the device syncer.
func TestManagedDeviceSyncsWhenExplicitlyOptedIn(t *testing.T) {
	ids := syncedResourceTypeIDs(t, &cli.ConnectorOpts{
		SyncResourceTypeIDs: []string{resourceTypeManagedDevice.Id},
	})
	if !ids[resourceTypeManagedDevice.Id] {
		t.Fatal("managedDevice must sync when explicitly opted in via the resource-type filter")
	}
}

// TestManagedDeviceAdvertisedForCapabilities proves that the metadata path (nil
// opts, as used by the default capabilities builder) still advertises the
// device type so baton_capabilities.json reports it with opt_in_required: true.
func TestManagedDeviceAdvertisedForCapabilities(t *testing.T) {
	ids := syncedResourceTypeIDs(t, nil)
	if !ids[resourceTypeManagedDevice.Id] {
		t.Fatal("managedDevice must be advertised when emitting capabilities metadata (nil opts)")
	}
}
