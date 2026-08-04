package connector

import (
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
)

// stringSliceFromProfile reads a repeated-string field out of an account
// creation profile map (as produced by structpb's AsMap — a []interface{} of
// strings), tolerating an absent or wrongly-typed field by returning nil.
func stringSliceFromProfile(profileMap map[string]interface{}, key string) []string {
	raw, ok := profileMap[key].([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

func annotationsForUserResourceType() annotations.Annotations {
	annos := annotations.Annotations{}
	annos.Update(&v2.SkipEntitlementsAndGrants{})
	return annos
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
