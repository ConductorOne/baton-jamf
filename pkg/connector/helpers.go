package connector

import (
	"fmt"
	"strconv"

	"github.com/conductorone/baton-jamf/pkg/jamf"
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
func parseResourceID(idStr, prefix string) (int, error) {
	id, err := strconv.Atoi(idStr)
	if err != nil {
		return 0, status.Errorf(codes.InvalidArgument, "%s %q: %s", prefix, idStr, err)
	}
	return id, nil
}

// membershipIDs validates principal's resource type against want and parses
// container's and principal's numeric ids — the shared preamble every
// Grant/Revoke in group.go, userGroup.go and site.go repeats. op is the
// action prefix used in every error message here, e.g. "grant group member".
func membershipIDs(op string, want *v2.ResourceType, container, principal *v2.ResourceId) (int, int, error) {
	if principal.ResourceType != want.Id {
		return 0, 0, status.Errorf(codes.InvalidArgument, "jamf-connector: %s: principal must be resource type %q, got %q", op, want.Id, principal.ResourceType)
	}
	containerID, err := parseResourceID(container.Resource, fmt.Sprintf("jamf-connector: %s: invalid container id", op))
	if err != nil {
		return 0, 0, err
	}
	principalID, err := parseResourceID(principal.Resource, fmt.Sprintf("jamf-connector: %s: invalid principal id", op))
	if err != nil {
		return 0, 0, err
	}
	return containerID, principalID, nil
}

// membershipWriteError wraps a failed membership write for op. Jamf answers a
// 409 (mapped to AlreadyExists by the jamf package) for writes it rejects, e.g.
// one naming a user deleted since the pre-write read; that read already ruled
// out an existing membership, so a 409 is reported as FailedPrecondition.
// subject names what may have disappeared, e.g. "the user or group".
func membershipWriteError(op, subject string, err error) error {
	if jamf.IsAlreadyExistsError(err) {
		return status.Errorf(codes.FailedPrecondition, "jamf-connector: %s: Jamf rejected the change with 409 Conflict (%s may no longer exist): %v", op, subject, err)
	}
	return fmt.Errorf("jamf-connector: %s: %w", op, err)
}
