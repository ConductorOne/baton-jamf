// Package main implements a mock Jamf Pro server (Classic API + the token
// endpoints under /api/v1/auth) for testing the baton-jamf connector without
// a real Jamf Pro tenant.
//
// Environment Variables:
//   - PORT:          Server port (default: 8090, use 0 for a random port)
//   - JAMF_USERNAME: Username the connector must authenticate with (default: "test-user")
//   - JAMF_PASSWORD: Password the connector must authenticate with (default: "test-pass")
//   - JAMF_TOKEN:    Bearer token minted by /api/v1/auth/token (default: "test-bearer-token")
//
// JAMF_-prefixed (rather than bare USERNAME/PASSWORD/TOKEN) to avoid
// colliding with ambient shell/system environment variables of the same name.
//
// Usage:
//
//	go run ./test-server
//
// Connect the connector with:
//
//	./baton-jamf \
//	  --username test-user \
//	  --password test-pass \
//	  --instance-url http://localhost:8090
//
// Seeded data:
//   - Sites: 1 "Headquarters", 2 "Remote"
//   - Directory users (trait: user): john.appleseed (site 1), jane.doe,
//     carol.smith, dave.jones, eve.miller (site 2) — jane and dave overlap in
//     usergroup-sales below.
//   - Admin accounts (trait: user, resource type "userAccount"): admin1
//     (Administrator, Enabled), admin2 (Auditor, Disabled — tests
//     STATUS_DISABLED), admin3 (Custom, Enabled, carries a custom JSSObjects
//     privilege).
//   - Admin groups: group-admins (admin1+admin2), group-auditors
//     (admin2+admin3 — admin2 overlaps two groups), group-custom (admin3,
//     custom privilege).
//   - User groups: usergroup-eng (john+jane), usergroup-sales (jane+dave —
//     jane overlaps two groups), usergroup-empty (no members).
//   - Privileges (surfaced as custom roles): "Read Advanced Computer
//     Searches", "Update Advanced Computer Searches", "Read User", "Update User".
//
// The mock enforces the Classic API's documented content-type contract: GET
// responses are JSON, but POST/PUT request bodies must be XML — a JSON POST
// body is rejected with 415, exactly like the real API (see
// https://developer.jamf.com/jamf-pro/docs/getting-started-2). This is what
// caught baton-jamf's CreateAccount originally sending JSON bodies.
//
// managedDevice (computers / mobile devices) is opt-in in the connector and
// is NOT mocked here — it targets separate v1 inventory endpoints outside
// the scope of this test server. Do not select it against this mock.
package main

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/conductorone/baton-jamf/pkg/jamf"
)

const (
	defaultPort     = "8090"
	defaultUsername = "test-user"
	defaultPassword = "test-pass"
	defaultToken    = "test-bearer-token"

	siteNameHeadquarters = "Headquarters"
	siteNameRemote       = "Remote"

	accessLevelFullAccess     = "Full Access"
	privilegeSetAdministrator = "Administrator"

	privilegeReadAdvancedComputerSearches = "Read Advanced Computer Searches"
)

type server struct {
	mu sync.Mutex

	username string
	password string
	token    string

	users      map[int]*jamf.User
	userList   []*jamf.User
	nextUserID int

	accounts      map[int]*jamf.UserAccount
	accountList   []*jamf.UserAccount
	nextAccountID int

	groups    map[int]*jamf.Group
	groupList []*jamf.Group

	userGroups    map[int]*jamf.UserGroup
	userGroupList []*jamf.UserGroup

	sites      []jamf.Site
	privileges []string
}

func newServer(username, password, token string) *server {
	s := &server{
		username:   username,
		password:   password,
		token:      token,
		users:      make(map[int]*jamf.User),
		accounts:   make(map[int]*jamf.UserAccount),
		groups:     make(map[int]*jamf.Group),
		userGroups: make(map[int]*jamf.UserGroup),
	}
	s.seedData()
	return s
}

// ── Seed data ────────────────────────────────────────────────────────────────

func (s *server) seedData() {
	headquarters := jamf.BaseType{ID: 1, Name: siteNameHeadquarters}
	remote := jamf.BaseType{ID: 2, Name: siteNameRemote}

	s.sites = []jamf.Site{
		{BaseType: headquarters},
		{BaseType: remote},
	}

	users := []*jamf.User{
		{
			BaseType: jamf.BaseType{ID: 1, Name: "john.appleseed"},
			FullName: "John Appleseed", Email: "john.appleseed@example.com",
			Sites: []struct {
				Site jamf.BaseType `json:"site"`
			}{{Site: headquarters}},
		},
		{BaseType: jamf.BaseType{ID: 2, Name: "jane.doe"}, FullName: "Jane Doe", Email: "jane.doe@example.com"},
		{BaseType: jamf.BaseType{ID: 3, Name: "carol.smith"}, FullName: "Carol Smith", Email: "carol.smith@example.com"},
		{BaseType: jamf.BaseType{ID: 4, Name: "dave.jones"}, FullName: "Dave Jones", Email: "dave.jones@example.com"},
		{
			BaseType: jamf.BaseType{ID: 5, Name: "eve.miller"},
			FullName: "Eve Miller", Email: "eve.miller@example.com",
			Sites: []struct {
				Site jamf.BaseType `json:"site"`
			}{{Site: remote}},
		},
	}
	for _, u := range users {
		s.users[u.ID] = u
		s.userList = append(s.userList, u)
	}
	s.nextUserID = len(users)

	admin1 := &jamf.UserAccount{
		BaseType: jamf.BaseType{ID: 101, Name: "admin1"}, FullName: "Admin One", Email: "admin1@example.com",
		Enabled: "Enabled", AccessLevel: accessLevelFullAccess, PrivilegeSet: privilegeSetAdministrator, Site: headquarters,
	}
	admin2 := &jamf.UserAccount{
		BaseType: jamf.BaseType{ID: 102, Name: "admin2"}, FullName: "Admin Two", Email: "admin2@example.com",
		Enabled: "Disabled", AccessLevel: accessLevelFullAccess, PrivilegeSet: "Auditor", Site: headquarters,
	}
	admin3 := &jamf.UserAccount{
		BaseType: jamf.BaseType{ID: 103, Name: "admin3"}, FullName: "Admin Three", Email: "admin3@example.com",
		Enabled: "Enabled", AccessLevel: accessLevelFullAccess, PrivilegeSet: "Custom", Site: remote,
		Privileges: jamf.Privileges{JSSObjects: []string{privilegeReadAdvancedComputerSearches}},
	}
	accounts := []*jamf.UserAccount{admin1, admin2, admin3}
	for _, a := range accounts {
		s.accounts[a.ID] = a
		s.accountList = append(s.accountList, a)
	}
	s.nextAccountID = accounts[len(accounts)-1].ID

	admin1Ref := jamf.BaseType{ID: admin1.ID, Name: admin1.Name}
	admin2Ref := jamf.BaseType{ID: admin2.ID, Name: admin2.Name}
	admin3Ref := jamf.BaseType{ID: admin3.ID, Name: admin3.Name}

	groups := []*jamf.Group{
		{
			BaseType: jamf.BaseType{ID: 201, Name: "group-admins"}, AccessLevel: accessLevelFullAccess, PrivilegeSet: privilegeSetAdministrator, Site: headquarters,
			Members: []jamf.BaseType{admin1Ref, admin2Ref},
		},
		{
			BaseType: jamf.BaseType{ID: 202, Name: "group-auditors"}, AccessLevel: accessLevelFullAccess, PrivilegeSet: "Auditor", Site: headquarters,
			Members: []jamf.BaseType{admin2Ref, admin3Ref},
		},
		{
			BaseType: jamf.BaseType{ID: 203, Name: "group-custom"}, AccessLevel: accessLevelFullAccess, PrivilegeSet: "Custom", Site: remote,
			Privileges: jamf.Privileges{JSSObjects: []string{privilegeReadAdvancedComputerSearches}},
			Members:    []jamf.BaseType{admin3Ref},
		},
	}
	for _, g := range groups {
		s.groups[g.ID] = g
		s.groupList = append(s.groupList, g)
	}

	userGroups := []*jamf.UserGroup{
		{
			BaseType: jamf.BaseType{ID: 301, Name: "usergroup-eng"}, Site: jamf.Site{BaseType: headquarters},
			Users: []jamf.User{*users[0], *users[1]},
		},
		{
			BaseType: jamf.BaseType{ID: 302, Name: "usergroup-sales"}, IsSmart: true, Site: jamf.Site{BaseType: remote},
			Users: []jamf.User{*users[1], *users[3]},
		},
		{
			BaseType: jamf.BaseType{ID: 303, Name: "usergroup-empty"}, Site: jamf.Site{BaseType: headquarters},
		},
	}
	for _, ug := range userGroups {
		s.userGroups[ug.ID] = ug
		s.userGroupList = append(s.userGroupList, ug)
	}

	s.privileges = []string{
		privilegeReadAdvancedComputerSearches,
		"Update Advanced Computer Searches",
		"Read User",
		"Update User",
	}
}

// ── Auth ─────────────────────────────────────────────────────────────────────

// Doc URL: https://developer.jamf.com/jamf-pro/reference/post_v1-auth-token
func (s *server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method must be POST")
		return
	}
	user, pass, ok := r.BasicAuth()
	if !ok || user != s.username || pass != s.password {
		w.Header().Set("WWW-Authenticate", `Basic realm="baton-jamf-test-server"`)
		writeJSONError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	writeJSON(w, http.StatusOK, jamf.TokenResponse{
		Token:   s.token,
		Expires: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	})
}

// Doc URL: https://developer.jamf.com/jamf-pro/reference/post_v1-auth-keep-alive
func (s *server) handleKeepAlive(w http.ResponseWriter, r *http.Request) {
	if !s.requireBearer(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method must be POST")
		return
	}
	writeJSON(w, http.StatusOK, jamf.TokenResponse{
		Token:   s.token,
		Expires: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	})
}

// Doc URL: https://developer.jamf.com/jamf-pro/reference/get_v1-auth
func (s *server) handleTokenDetails(w http.ResponseWriter, r *http.Request) {
	if !s.requireBearer(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, jamf.TokenDetails{
		Account: jamf.Account{
			ID: "1", Username: s.username, RealName: "Test User", Email: "test-user@example.com",
			AccessLevel: accessLevelFullAccess, PrivilegeSet: privilegeSetAdministrator, CurrentSiteID: "-1",
		},
		Sites: []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}{{ID: "1", Name: siteNameHeadquarters}},
		AuthenticationType: "Basic",
	})
}

// requireBearer validates the Authorization header and writes a 401 (with
// the response already sent) when it's missing or wrong. Returns true when
// the caller should proceed.
func (s *server) requireBearer(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("Authorization") != "Bearer "+s.token {
		writeJSONError(w, http.StatusUnauthorized, "missing or invalid bearer token")
		return false
	}
	return true
}

// ── Directory users (/JSSResource/users) ────────────────────────────────────

// Doc URL: https://developer.jamf.com/jamf-pro/reference/findusers
func (s *server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	if !s.requireBearer(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method must be GET")
		return
	}
	s.mu.Lock()
	minimal := make([]jamf.BaseType, 0, len(s.userList))
	for _, u := range s.userList {
		minimal = append(minimal, jamf.BaseType{ID: u.ID, Name: u.Name})
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, jamf.UsersResponse{Users: minimal})
}

// handleUserByID dispatches GET (by numeric ID) / POST (create, ID must be
// 0) / DELETE (by numeric ID) on /JSSResource/users/id/{id}.
//
// Doc URLs:
//   - https://developer.jamf.com/jamf-pro/reference/finduserbyid
//   - https://developer.jamf.com/jamf-pro/reference/createuserbyid
//   - https://developer.jamf.com/jamf-pro/reference/deleteuserbyid
func (s *server) handleUserByID(w http.ResponseWriter, r *http.Request) {
	if !s.requireBearer(w, r) {
		return
	}
	id, err := pathID(r.URL.Path, "/JSSResource/users/id/")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.mu.Lock()
		u, ok := s.users[id]
		var cp jamf.User
		if ok {
			cp = *u
		}
		s.mu.Unlock()
		if !ok {
			writeJSONError(w, http.StatusNotFound, "user not found")
			return
		}
		writeJSON(w, http.StatusOK, jamf.UserResponse{User: cp})

	case http.MethodPost:
		// The Classic API only accepts XML for POST/PUT bodies (JSON is
		// GET-response-only) — see https://developer.jamf.com/jamf-pro/docs/getting-started-2.
		body, ok := decodeXMLBody[jamf.UserCreateBody](w, r)
		if !ok {
			return
		}
		if body.Name == "" {
			writeJSONError(w, http.StatusBadRequest, "name is required")
			return
		}

		s.mu.Lock()
		if existing, dup := s.findUserByNameLocked(body.Name); dup {
			s.mu.Unlock()
			_ = existing
			writeJSONError(w, http.StatusConflict, "user already exists with this name")
			return
		}
		s.nextUserID++
		u := &jamf.User{
			BaseType: jamf.BaseType{ID: s.nextUserID, Name: body.Name},
			FullName: body.FullName,
			Email:    body.Email,
		}
		s.users[u.ID] = u
		s.userList = append(s.userList, u)
		cp := *u
		s.mu.Unlock()

		writeJSON(w, http.StatusCreated, jamf.UserResponse{User: cp})

	case http.MethodDelete:
		s.mu.Lock()
		_, ok := s.users[id]
		if ok {
			delete(s.users, id)
			s.userList = deleteByID(s.userList, id, func(u *jamf.User) int { return u.ID })
		}
		s.mu.Unlock()
		if !ok {
			writeJSONError(w, http.StatusNotFound, "user not found")
			return
		}
		w.WriteHeader(http.StatusOK)

	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// Doc URL: https://developer.jamf.com/jamf-pro/reference/findusersbyname
func (s *server) handleUserByName(w http.ResponseWriter, r *http.Request) {
	if !s.requireBearer(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method must be GET")
		return
	}
	name := pathTail(r.URL.Path, "/JSSResource/users/name/")

	s.mu.Lock()
	u, ok := s.findUserByNameLocked(name)
	s.mu.Unlock()
	if !ok {
		writeJSONError(w, http.StatusNotFound, "user not found")
		return
	}
	writeJSON(w, http.StatusOK, jamf.UserResponse{User: *u})
}

// findUserByNameLocked assumes the caller already holds s.mu.
func (s *server) findUserByNameLocked(name string) (*jamf.User, bool) {
	for _, u := range s.userList {
		if u.Name == name {
			cp := *u
			return &cp, true
		}
	}
	return nil, false
}

// ── Admin accounts & groups (/JSSResource/accounts) ─────────────────────────

// Doc URL: https://developer.jamf.com/jamf-pro/reference/findaccounts
func (s *server) handleListAccounts(w http.ResponseWriter, r *http.Request) {
	if !s.requireBearer(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method must be GET")
		return
	}

	s.mu.Lock()
	users := make([]jamf.User, 0, len(s.accountList))
	for _, a := range s.accountList {
		users = append(users, jamf.User{BaseType: jamf.BaseType{ID: a.ID, Name: a.Name}})
	}
	groups := make([]jamf.Group, 0, len(s.groupList))
	for _, g := range s.groupList {
		groups = append(groups, jamf.Group{BaseType: jamf.BaseType{ID: g.ID, Name: g.Name}})
	}
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, jamf.AccountsResponse{Accounts: jamf.BaseAccount{Users: users, Groups: groups}})
}

// handleAccountByID dispatches GET / POST (create) / DELETE on
// /JSSResource/accounts/userid/{id}.
//
// Doc URLs:
//   - https://developer.jamf.com/jamf-pro/reference/findaccountsbyid
//   - https://developer.jamf.com/jamf-pro/reference/createaccountbyid
//   - https://developer.jamf.com/jamf-pro/reference/deleteaccountbyid
func (s *server) handleAccountByID(w http.ResponseWriter, r *http.Request) {
	if !s.requireBearer(w, r) {
		return
	}
	id, err := pathID(r.URL.Path, "/JSSResource/accounts/userid/")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.mu.Lock()
		a, ok := s.accounts[id]
		var cp jamf.UserAccount
		if ok {
			cp = *a
		}
		s.mu.Unlock()
		if !ok {
			writeJSONError(w, http.StatusNotFound, "account not found")
			return
		}
		writeJSON(w, http.StatusOK, jamf.UserAccountResponse{UserAccount: cp})

	case http.MethodPost:
		body, ok := decodeXMLBody[jamf.UserAccountCreateBody](w, r)
		if !ok {
			return
		}
		if body.Name == "" || body.Password == "" {
			writeJSONError(w, http.StatusBadRequest, "name and password are required")
			return
		}

		s.mu.Lock()
		if existing, dup := s.findAccountByNameLocked(body.Name); dup {
			s.mu.Unlock()
			_ = existing
			writeJSONError(w, http.StatusConflict, "account already exists with this name")
			return
		}
		s.nextAccountID++
		a := &jamf.UserAccount{
			BaseType:     jamf.BaseType{ID: s.nextAccountID, Name: body.Name},
			FullName:     body.FullName,
			Email:        body.Email,
			Enabled:      body.Enabled,
			AccessLevel:  body.AccessLevel,
			PrivilegeSet: body.PrivilegeSet,
		}
		s.accounts[a.ID] = a
		s.accountList = append(s.accountList, a)
		cp := *a
		s.mu.Unlock()

		writeJSON(w, http.StatusCreated, jamf.UserAccountResponse{UserAccount: cp})

	case http.MethodDelete:
		s.mu.Lock()
		_, ok := s.accounts[id]
		if ok {
			delete(s.accounts, id)
			s.accountList = deleteByID(s.accountList, id, func(a *jamf.UserAccount) int { return a.ID })
		}
		s.mu.Unlock()
		if !ok {
			writeJSONError(w, http.StatusNotFound, "account not found")
			return
		}
		w.WriteHeader(http.StatusOK)

	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// Doc URL: https://developer.jamf.com/jamf-pro/reference/accounts
func (s *server) handleAccountByName(w http.ResponseWriter, r *http.Request) {
	if !s.requireBearer(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method must be GET")
		return
	}
	name := pathTail(r.URL.Path, "/JSSResource/accounts/username/")

	s.mu.Lock()
	a, ok := s.findAccountByNameLocked(name)
	s.mu.Unlock()
	if !ok {
		writeJSONError(w, http.StatusNotFound, "account not found")
		return
	}
	writeJSON(w, http.StatusOK, jamf.UserAccountResponse{UserAccount: *a})
}

// findAccountByNameLocked assumes the caller already holds s.mu.
func (s *server) findAccountByNameLocked(name string) (*jamf.UserAccount, bool) {
	for _, a := range s.accountList {
		if a.Name == name {
			cp := *a
			return &cp, true
		}
	}
	return nil, false
}

// Doc URL: https://developer.jamf.com/jamf-pro/reference/findgroupsbyid
func (s *server) handleGroupByID(w http.ResponseWriter, r *http.Request) {
	if !s.requireBearer(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method must be GET")
		return
	}
	id, err := pathID(r.URL.Path, "/JSSResource/accounts/groupid/")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}

	s.mu.Lock()
	g, ok := s.groups[id]
	var cp jamf.Group
	if ok {
		cp = *g
	}
	s.mu.Unlock()
	if !ok {
		writeJSONError(w, http.StatusNotFound, "group not found")
		return
	}
	writeJSON(w, http.StatusOK, jamf.GroupResponse{Group: cp})
}

// ── User groups (/JSSResource/usergroups) ───────────────────────────────────

// Doc URL: https://developer.jamf.com/jamf-pro/reference/findusergroups
func (s *server) handleListUserGroups(w http.ResponseWriter, r *http.Request) {
	if !s.requireBearer(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method must be GET")
		return
	}

	s.mu.Lock()
	minimal := make([]jamf.UserGroup, 0, len(s.userGroupList))
	for _, g := range s.userGroupList {
		minimal = append(minimal, jamf.UserGroup{BaseType: jamf.BaseType{ID: g.ID, Name: g.Name}})
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, jamf.UserGroupsResponse{UserGroups: minimal})
}

// Doc URL: https://developer.jamf.com/jamf-pro/reference/findusergroupsbyid
func (s *server) handleUserGroupByID(w http.ResponseWriter, r *http.Request) {
	if !s.requireBearer(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method must be GET")
		return
	}
	id, err := pathID(r.URL.Path, "/JSSResource/usergroups/id/")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}

	s.mu.Lock()
	g, ok := s.userGroups[id]
	var cp jamf.UserGroup
	if ok {
		cp = *g
	}
	s.mu.Unlock()
	if !ok {
		writeJSONError(w, http.StatusNotFound, "user group not found")
		return
	}
	writeJSON(w, http.StatusOK, jamf.UserGroupResponse{UserGroup: cp})
}

// ── Sites & privileges ───────────────────────────────────────────────────────

// Doc URL: https://developer.jamf.com/jamf-pro/reference/findsites
func (s *server) handleListSites(w http.ResponseWriter, r *http.Request) {
	if !s.requireBearer(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method must be GET")
		return
	}
	s.mu.Lock()
	sites := append([]jamf.Site{}, s.sites...)
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, jamf.SitesResponse{Sites: sites})
}

// Doc URL: https://developer.jamf.com/jamf-pro/reference/get_v1-api-role-privileges
func (s *server) handleListPrivileges(w http.ResponseWriter, r *http.Request) {
	if !s.requireBearer(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method must be GET")
		return
	}
	s.mu.Lock()
	privileges := append([]string{}, s.privileges...)
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, jamf.PrivilegesResponse{Privileges: privileges})
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// decodeXMLBody enforces the Classic API's documented POST/PUT content-type
// contract (XML only — see https://developer.jamf.com/jamf-pro/docs/getting-started-2)
// and decodes the body into T. On any failure it writes the response itself
// and returns ok=false.
func decodeXMLBody[T any](w http.ResponseWriter, r *http.Request) (T, bool) {
	var zero T
	contentType := r.Header.Get("Content-Type")
	if !strings.Contains(strings.ToLower(contentType), "xml") {
		writeJSONError(w, http.StatusUnsupportedMediaType,
			fmt.Sprintf("Classic API POST/PUT requires an XML body; got Content-Type %q", contentType))
		return zero, false
	}

	var body T
	if err := xml.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "malformed XML body: "+err.Error())
		return zero, false
	}
	return body, true
}

// pathID extracts and parses the trailing numeric segment after prefix.
func pathID(path, prefix string) (int, error) {
	return strconv.Atoi(pathTail(path, prefix))
}

// pathTail returns the (already-decoded) path segment following prefix.
func pathTail(path, prefix string) string {
	return strings.TrimPrefix(path, prefix)
}

// deleteByID removes the item whose itemID(item) matches id, returning the
// filtered slice (reuses the input's backing array).
func deleteByID[T any](items []T, id int, itemID func(T) int) []T {
	out := items[:0]
	for _, item := range items {
		if itemID(item) != id {
			out = append(out, item)
		}
	}
	return out
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

type errorBody struct {
	Message string `json:"message"`
}

func writeJSONError(w http.ResponseWriter, code int, message string) {
	writeJSON(w, code, errorBody{Message: message})
}

// ── Entry point ──────────────────────────────────────────────────────────────

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}
	username := os.Getenv("JAMF_USERNAME")
	if username == "" {
		username = defaultUsername
	}
	password := os.Getenv("JAMF_PASSWORD")
	if password == "" {
		password = defaultPassword
	}
	token := os.Getenv("JAMF_TOKEN")
	if token == "" {
		token = defaultToken
	}

	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", ":"+port)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	port = strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	baseURL := "http://localhost:" + port

	s := newServer(username, password, token)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/auth/token", s.handleCreateToken)
	mux.HandleFunc("/api/v1/auth/keep-alive", s.handleKeepAlive)
	mux.HandleFunc("/api/v1/auth", s.handleTokenDetails)
	mux.HandleFunc("/api/v1/api-role-privileges", s.handleListPrivileges)

	mux.HandleFunc("/JSSResource/users", s.handleListUsers)
	mux.HandleFunc("/JSSResource/users/id/", s.handleUserByID)
	mux.HandleFunc("/JSSResource/users/name/", s.handleUserByName)

	mux.HandleFunc("/JSSResource/accounts", s.handleListAccounts)
	mux.HandleFunc("/JSSResource/accounts/userid/", s.handleAccountByID)
	mux.HandleFunc("/JSSResource/accounts/username/", s.handleAccountByName)
	mux.HandleFunc("/JSSResource/accounts/groupid/", s.handleGroupByID)

	mux.HandleFunc("/JSSResource/usergroups", s.handleListUserGroups)
	mux.HandleFunc("/JSSResource/usergroups/id/", s.handleUserGroupByID)

	mux.HandleFunc("/JSSResource/sites", s.handleListSites)

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}

	log.Printf("baton-jamf mock server listening on %s", baseURL)
	log.Printf("Connect with:")
	log.Printf("  ./baton-jamf \\")
	log.Printf("    --username %s \\", username) //nolint:gosec // intentional: test server logs its own config
	log.Printf("    --password %s \\", password) //nolint:gosec // intentional: test server logs its own config
	log.Printf("    --instance-url %s", baseURL)

	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
