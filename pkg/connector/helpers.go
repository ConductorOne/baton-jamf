package connector

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/conductorone/baton-jamf/pkg/jamf"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// grantsPageSize keeps a Grants response under gRPC's 4 MiB receive limit.
const grantsPageSize = 1000

// pageGrants returns the page of grants after cursor and the cursor of the next page, "" on the last one.
// The cursor is a grant ID and a page starts strictly after it, so the cursor always advances.
func pageGrants(grants []*v2.Grant, cursor string) ([]*v2.Grant, string, error) {
	slices.SortFunc(grants, func(left, right *v2.Grant) int { return strings.Compare(left.GetId(), right.GetId()) })

	start := 0
	if cursor != "" {
		start = sort.Search(len(grants), func(index int) bool { return grants[index].GetId() > cursor })
	}

	end := min(start+grantsPageSize, len(grants))
	page := grants[start:end]
	if end == len(grants) {
		return page, "", nil
	}

	nextCursor := page[len(page)-1].GetId()
	if nextCursor == "" {
		return nil, "", errors.New("jamf-connector: grants page has more items but an empty cursor")
	}
	return page, nextCursor, nil
}

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

// requirePrincipalType rejects principalType unless it matches want, naming
// noun/verb in the InvalidArgument message (e.g. "group membership" /
// "granted to user accounts").
func requirePrincipalType(principalType string, want *v2.ResourceType, noun, verb string) error {
	if principalType != want.Id {
		return status.Errorf(codes.InvalidArgument, "jamf-connector: %s can only be %s, got resource type %q", noun, verb, principalType)
	}
	return nil
}

// parseResourceID parses idStr as a Jamf numeric id. prefix is the message
// up to (not including) the id value, e.g.
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
