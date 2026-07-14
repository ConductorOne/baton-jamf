package connector

import (
	"fmt"
	"strconv"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
)

func annotationsForUserResourceType() annotations.Annotations {
	annos := annotations.Annotations{}
	annos.Update(&v2.SkipEntitlementsAndGrants{})
	return annos
}

// nativeUserID resolves the native Jamf numeric user ID for a principal used in
// provisioning. It prefers the ExternalId set during sync and falls back to the
// resource ID (which already equals the native ID for this connector).
func nativeUserID(principal *v2.Resource) (int, error) {
	raw := principal.Id.Resource
	if externalID := principal.GetExternalId(); externalID != nil && externalID.Id != "" {
		raw = externalID.Id
	}

	id, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("jamf-connector: invalid native user id %q: %w", raw, err)
	}
	return id, nil
}

// annotationsForManagedDeviceResourceType marks the managedDevice resource type
// as opt-in. The OptInRequired annotation is surfaced in baton_capabilities.json
// so the C1 platform leaves device syncing OFF by default; existing installs
// whose Jamf API role lacks "Read Computers" / "Read Mobile Devices" are
// therefore unaffected until an operator explicitly enables the type. See the
// registration gate in (*Jamf).ResourceSyncers for the connector-side
// enforcement that keeps local/CLI syncs off by default too.
func annotationsForManagedDeviceResourceType() annotations.Annotations {
	annos := annotations.Annotations{}
	annos.Update(&v2.OptInRequired{})
	return annos
}
