package connector

import (
	"strconv"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
// therefore unaffected until the type is explicitly enabled. See the
// registration gate in (*Jamf).ResourceSyncers for the connector-side
// enforcement that keeps local/CLI syncs off by default too.
func annotationsForManagedDeviceResourceType() annotations.Annotations {
	annos := annotations.Annotations{}
	annos.Update(&v2.OptInRequired{})
	return annos
}

// requirePrincipalType rejects principalType unless it matches want, with the
// same "jamf-connector: <noun> can only be <verb>, got resource type %q"
// wording every Grant/Revoke principal-type guard already used — replacing
// the repeated inline checks.
func requirePrincipalType(principalType string, want *v2.ResourceType, noun, verb string) error {
	if principalType != want.Id {
		return status.Errorf(codes.InvalidArgument, "jamf-connector: %s can only be %s, got resource type %q", noun, verb, principalType)
	}
	return nil
}

// parseResourceID parses idStr as a Jamf numeric id, returning the same
// InvalidArgument error every call site already produced on a parse failure.
// prefix is the full message up to (and not including) the id value, e.g.
// "jamf-connector: grant group member: invalid group id".
func parseResourceID(prefix, idStr string) (int, error) {
	id, err := strconv.Atoi(idStr)
	if err != nil {
		return 0, status.Errorf(codes.InvalidArgument, "%s %q: %s", prefix, idStr, err)
	}
	return id, nil
}

// containsID reports whether any element of items has id as its numeric id,
// as reported by idOf — replacing the repeated identical-shaped membership
// loops used for group/user-group/site membership checks.
func containsID[T any](items []T, id int, idOf func(T) int) bool {
	for _, item := range items {
		if idOf(item) == id {
			return true
		}
	}
	return false
}
