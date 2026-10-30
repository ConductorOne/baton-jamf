package connector

import (
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/conductorone/baton-jamf/pkg/jamf"
)

// proPrivilegeLevelsByName maps a Classic privilege set to the privilegeLevel the Pro accounts API reports.
var proPrivilegeLevelsByName = map[string]string{
	privilegeSetAdministrator:  "ADMINISTRATOR",
	privilegeSetAuditor:        "AUDITOR",
	privilegeSetEnrollmentOnly: "ENROLLMENT",
	privilegeSetCustom:         "CUSTOM",
}

// adminFixture is a fake Jamf for the role, group and site syncers: the Pro accounts list (privilegeLevel and
// siteId filters, any page size), a site's objects, the Classic account and group details, and the privilege
// catalog. It records every request so tests can assert what the syncers asked for.
type adminFixture struct {
	t        *testing.T
	accounts []jamf.UserAccount
	groups   []jamf.Group
	catalog  []string
	// siteObjects maps "<siteID>/<objectType>" to the object IDs, ascending.
	siteObjects map[string][]int
	// deletedAccountIDs are listed by the Pro accounts API, but their Classic detail answers 404.
	deletedAccountIDs []int

	mu               sync.Mutex
	paths            []string
	accountsRequests []accountsRequest
}

type accountsRequest struct {
	filter   string
	pageSize int
}

func newAdminFixture(t *testing.T, accounts []jamf.UserAccount, groups []jamf.Group) *adminFixture {
	t.Helper()
	return &adminFixture{t: t, accounts: accounts, groups: groups}
}

func (fixture *adminFixture) client() *jamf.Client {
	return newTestJamfClient(fixture.t, fixture.ServeHTTP)
}

// requestCount returns how many requests had a path starting with prefix.
func (fixture *adminFixture) requestCount(prefix string) int {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()

	count := 0
	for _, path := range fixture.paths {
		if strings.HasPrefix(path, prefix) {
			count++
		}
	}
	return count
}

// accountsRequestsSeen returns every GET /api/v1/accounts request, in order.
func (fixture *adminFixture) accountsRequestsSeen() []accountsRequest {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()

	return slices.Clone(fixture.accountsRequests)
}

func (fixture *adminFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fixture.mu.Lock()
	fixture.paths = append(fixture.paths, r.URL.Path)
	fixture.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.URL.Path == "/api/v1/api-role-privileges":
		encodeJSON(fixture.t, w, jamf.PrivilegesResponse{Privileges: fixture.catalog})
	case r.URL.Path == "/api/v1/accounts":
		fixture.serveAccounts(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/v1/sites/"):
		fixture.serveSiteObjects(w, r)
	case strings.HasPrefix(r.URL.Path, "/JSSResource/accounts/userid/"):
		accountID := accountIDFromPath(fixture.t, r.URL.Path)
		for _, account := range fixture.accounts {
			if account.ID == accountID && !slices.Contains(fixture.deletedAccountIDs, accountID) {
				encodeJSON(fixture.t, w, jamf.UserAccountResponse{UserAccount: account})
				return
			}
		}
		http.NotFound(w, r)
	case strings.HasPrefix(r.URL.Path, "/JSSResource/accounts/groupid/"):
		groupID := accountIDFromPath(fixture.t, r.URL.Path)
		for _, group := range fixture.groups {
			if group.ID == groupID {
				encodeJSON(fixture.t, w, jamf.GroupResponse{Group: group})
				return
			}
		}
		http.NotFound(w, r)
	default:
		fixture.t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	}
}

// serveAccounts answers GET /api/v1/accounts. It only knows a single-term privilegeLevel==<ENUM> or siteId==<int> filter.
func (fixture *adminFixture) serveAccounts(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	page, pageErr := strconv.Atoi(query.Get("page"))
	pageSize, pageSizeErr := strconv.Atoi(query.Get("page-size"))
	if pageErr != nil || pageSizeErr != nil || pageSize < 1 || query.Get("sort") != "id:asc" {
		fixture.t.Errorf("unexpected accounts query %q", r.URL.RawQuery)
		http.Error(w, "bad query", http.StatusBadRequest)
		return
	}

	filter := query.Get("filter")
	matching := slices.Clone(fixture.accounts)
	field, value, found := strings.Cut(filter, "==")
	siteID, siteIDErr := strconv.Atoi(value)
	switch {
	case filter == "":
	case found && field == "privilegeLevel":
		matching = slices.DeleteFunc(matching, func(account jamf.UserAccount) bool {
			return proPrivilegeLevelsByName[account.PrivilegeSet] != value
		})
	case found && field == "siteId" && siteIDErr == nil:
		matching = slices.DeleteFunc(matching, func(account jamf.UserAccount) bool { return account.Site.ID != siteID })
	default:
		fixture.t.Errorf("unexpected accounts filter %q", filter)
		http.Error(w, "bad filter", http.StatusBadRequest)
		return
	}
	fixture.mu.Lock()
	fixture.accountsRequests = append(fixture.accountsRequests, accountsRequest{filter: filter, pageSize: pageSize})
	fixture.mu.Unlock()

	slices.SortFunc(matching, func(left, right jamf.UserAccount) int { return left.ID - right.ID })
	start := min(page*pageSize, len(matching))
	end := min(start+pageSize, len(matching))
	results := make([]map[string]any, 0, end-start)
	for _, account := range matching[start:end] {
		results = append(results, map[string]any{
			"id":             strconv.Itoa(account.ID),
			"username":       account.Name,
			"realname":       account.FullName,
			"email":          account.Email,
			"accountStatus":  "Enabled",
			"privilegeLevel": proPrivilegeLevelsByName[account.PrivilegeSet],
		})
	}
	encodeJSON(fixture.t, w, map[string]any{"totalCount": len(matching), "results": results})
}

// serveSiteObjects answers GET /api/v1/sites/{id}/objects with a bare array, filtered by objectType=="<type>".
func (fixture *adminFixture) serveSiteObjects(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	page, pageErr := strconv.Atoi(query.Get("page"))
	pageSize, pageSizeErr := strconv.Atoi(query.Get("page-size"))
	objectType := strings.TrimSuffix(strings.TrimPrefix(query.Get("filter"), `objectType=="`), `"`)
	if pageErr != nil || pageSizeErr != nil || pageSize != jamf.SiteObjectsPageSize || query.Get("sort") != "objectId:asc" || objectType == "" {
		fixture.t.Errorf("unexpected site objects query %q", r.URL.RawQuery)
		http.Error(w, "bad query", http.StatusBadRequest)
		return
	}

	siteID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/sites/"), "/objects")
	objectIDs := fixture.siteObjects[siteID+"/"+objectType]
	start := min(page*pageSize, len(objectIDs))
	end := min(start+pageSize, len(objectIDs))
	results := make([]map[string]string, 0, end-start)
	for _, objectID := range objectIDs[start:end] {
		results = append(results, map[string]string{"siteId": siteID, "objectType": objectType, "objectId": strconv.Itoa(objectID)})
	}
	encodeJSON(fixture.t, w, results)
}

func accountIDFromPath(t *testing.T, path string) int {
	t.Helper()
	parts := strings.Split(path, "/")
	id, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil {
		t.Fatalf("parse id from path %q: %v", path, err)
	}
	return id
}

func testAccount(id int, privilegeSet string) jamf.UserAccount {
	return jamf.UserAccount{
		BaseType:     jamf.BaseType{ID: id, Name: fmt.Sprintf("account%d", id)},
		AccessLevel:  "Full Access",
		PrivilegeSet: privilegeSet,
	}
}
