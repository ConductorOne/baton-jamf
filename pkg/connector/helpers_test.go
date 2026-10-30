package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/conductorone/baton-sdk/pkg/types/sessions"
)

type grantsFunc func(context.Context, *v2.Resource, rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error)

// collectGrants follows NextPageToken until it is empty and returns every
// grant plus the number of Grants calls it took.
func collectGrants(t *testing.T, grantsFn grantsFunc, resource *v2.Resource, store sessions.SessionStore) ([]*v2.Grant, int) {
	t.Helper()

	var collected []*v2.Grant
	token := ""
	for calls := 1; calls <= 100; calls++ {
		grants, results, err := grantsFn(context.Background(), resource, rs.SyncOpAttrs{
			Session:   store,
			PageToken: pagination.Token{Token: token},
		})
		if err != nil {
			t.Fatalf("Grants call %d: %v", calls, err)
		}
		collected = append(collected, grants...)

		if results == nil || results.NextPageToken == "" {
			return collected, calls
		}
		if results.NextPageToken == token {
			t.Fatalf("Grants call %d returned the same page token %q", calls, token)
		}
		token = results.NextPageToken
	}
	t.Fatal("Grants did not terminate within 100 calls")
	return nil, 0
}

// grantPrincipals returns the sorted "<resourceType>:<id>" of each grant's principal and fails on a duplicate.
func grantPrincipals(t *testing.T, grants []*v2.Grant) []string {
	t.Helper()

	principals := make([]string, 0, len(grants))
	for _, grant := range grants {
		principalID := grant.GetPrincipal().GetId()
		principals = append(principals, principalID.GetResourceType()+":"+principalID.GetResource())
	}
	slices.Sort(principals)
	if len(slices.Compact(slices.Clone(principals))) != len(principals) {
		t.Fatal("grants contain a duplicate principal")
	}
	return principals
}

// encodeJSON writes body as the JSON response; t.Errorf is safe from handler goroutines.
func encodeJSON(t *testing.T, w http.ResponseWriter, body any) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(body); err != nil {
		t.Errorf("encode response: %v", err)
	}
}

// idRange returns count consecutive IDs starting at first.
func idRange(first, count int) []int {
	ids := make([]int, 0, count)
	for id := first; id < first+count; id++ {
		ids = append(ids, id)
	}
	return ids
}

// A cursor whose grant was removed since the previous page still resumes right after its position.
func TestPageGrants_CursorGrantRemovedBetweenPages(t *testing.T) {
	grants := make([]*v2.Grant, 0, 5)
	for i := range 5 {
		grants = append(grants, &v2.Grant{Id: fmt.Sprintf("grant-%d", i)})
	}

	got, nextCursor, err := pageGrants(grants, "grant-1a")
	if err != nil {
		t.Fatalf("pageGrants: %v", err)
	}

	if len(got) != 3 || nextCursor != "" {
		t.Fatalf("page = %d grants, next cursor %q; want 3 grants and no cursor", len(got), nextCursor)
	}
	if got[0].GetId() != "grant-2" {
		t.Errorf("first grant = %q, want grant-2", got[0].GetId())
	}
}
