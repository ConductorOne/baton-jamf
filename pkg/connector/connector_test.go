package connector

import (
	"context"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
)

func TestManagedDeviceResourceTypeIsOptIn(t *testing.T) {
	annos := annotations.Annotations(resourceTypeManagedDevice.GetAnnotations())
	if !annos.Contains(&v2.OptInRequired{}) {
		t.Fatal("managedDevice resource type must carry the OptInRequired annotation")
	}
}

func TestResourceSyncersIncludeManagedDevice(t *testing.T) {
	j := &Jamf{}
	ids := make(map[string]bool)
	for _, rb := range j.ResourceSyncers(context.Background()) {
		ids[rb.ResourceType(context.Background()).GetId()] = true
	}
	for _, id := range []string{
		resourceTypeUser.Id,
		resourceTypeGroup.Id,
		resourceTypeUserAccount.Id,
		resourceTypeUserGroup.Id,
		resourceTypeRole.Id,
		resourceTypeSite.Id,
		resourceTypeManagedDevice.Id,
	} {
		if !ids[id] {
			t.Fatalf("expected %q to be registered as a resource syncer", id)
		}
	}
}
