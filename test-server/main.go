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
// body is rejected with 415, exactly like the real API.
//
// managedDevice (computers / mobile devices) is opt-in in the connector and
// is NOT mocked here — it targets separate inventory endpoints outside
// the scope of this test server (/api/v4/computers-inventory-detail/{id},
// /api/v2/mobile-devices/{id}). Do not select it against this mock; Managed
// Device Grant/Revoke has unit-test coverage only
// (pkg/connector/managedDevice_test.go), not baton-test-against-this-mock
// coverage.
//
// Grant/Revoke for User Groups (PUT .../usergroups/id/{id} with
// <user_additions>/<user_deletions>) and Sites' `user` principal (PUT
// .../users/id/{id} with <sites>) are both mocked below.
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
	"slices"
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
	accessLevelGroupAccess    = "Group Access"
	privilegeSetAdministrator = "Administrator"
	privilegeSetAuditor       = "Auditor"
	privilegeSetCustom        = "Custom"
	enabledValue              = "Enabled"

	privilegeReadAdvancedComputerSearches   = "Read Advanced Computer Searches"
	privilegeUpdateAdvancedComputerSearches = "Update Advanced Computer Searches"
	privilegeReadUser                       = "Read User"
	privilegeUpdateUser                     = "Update User"

	// privilegeReadLicenseInformation is the one privilege Jamf always keeps
	// on every Custom privilege set and never lets a client remove.
	privilegeReadLicenseInformation = "Read License Information"

	// privilegeReadKnobs is in the Pro privilege catalog but is dropped by
	// Jamf on write — it's seeded into the catalog only, never into
	// knownPrivilegeNames, so writing it is silently stripped.
	privilegeReadKnobs = "Read Knobs"

	// noneSiteID is the Classic API's sentinel for "no site" on a <sites>
	// write — unlike a genuinely unknown id, it clears the list instead of
	// triggering a 409.
	noneSiteID = -1
)

// knownPrivilegeNames is the set of individual privilege names this mock
// recognizes. Mirrors the real API's "unknown privilege names are silently
// dropped" behavior: a <privileges> write for a Custom account/group drops
// anything outside this list (plus privilegeReadLicenseInformation, which is
// always kept) instead of storing it, letting tests exercise the connector's
// post-write verification path.
var knownPrivilegeNames = []string{
	privilegeReadAdvancedComputerSearches,
	privilegeUpdateAdvancedComputerSearches,
	privilegeReadUser,
	privilegeUpdateUser,
}

// copiedFullPrivilegeList simulates the real API's privilege-escalation trap:
// writing privilege_set=Custom with no <privileges> block copies the
// account/group's previous set's entire expanded privilege list rather than
// leaving privileges empty. The actual contents are arbitrary — this is not a
// real expansion of any specific built-in set, just something large and
// non-empty that a correct connector write must never trigger.
var copiedFullPrivilegeList = jamf.Privileges{
	JSSObjects: []string{privilegeReadUser, privilegeUpdateUser, privilegeReadAdvancedComputerSearches, privilegeUpdateAdvancedComputerSearches, privilegeReadLicenseInformation},
}

// expandedBuiltInPrivileges is a fixed, non-empty privilege list a built-in
// privilege_set (Administrator, Auditor, Enrollment Only) reads back as.
// Jamf always expands a built-in set to the privileges it grants rather than
// returning an empty list — the exact contents are arbitrary here, only
// "non-empty" matters, so a connector that incorrectly treated a built-in
// set's privileges as an individual-privilege grant would be caught by tests.
var expandedBuiltInPrivileges = jamf.Privileges{
	JSSObjects: []string{privilegeReadUser, privilegeUpdateUser, privilegeReadAdvancedComputerSearches, privilegeReadLicenseInformation},
}

// privilegesForRead returns the privileges a GET of an account/group holding
// privilegeSet should report: a built-in set always expands to
// expandedBuiltInPrivileges; Custom reports exactly what's stored, with
// privilegeReadLicenseInformation guaranteed present (Jamf never lets it be
// absent from a Custom set).
func privilegesForRead(privilegeSet string, stored jamf.Privileges) jamf.Privileges {
	if privilegeSet != privilegeSetCustom {
		return expandedBuiltInPrivileges
	}
	if stored.Contains(privilegeReadLicenseInformation) {
		return stored
	}
	stored.JSSObjects = append(append([]string{}, stored.JSSObjects...), privilegeReadLicenseInformation)
	return stored
}

// Enums declared on the Classic API "account" schema.
var (
	validAccessLevels  = []string{"Full Access", "Site Access", "Group Access"}
	validPrivilegeSets = []string{privilegeSetAdministrator, privilegeSetAuditor, "Enrollment Only", privilegeSetCustom}
	validEnabledValues = []string{enabledValue, "Disabled"}
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
			Sites: jamf.UserSites{headquarters},
		},
		{BaseType: jamf.BaseType{ID: 2, Name: "jane.doe"}, FullName: "Jane Doe", Email: "jane.doe@example.com"},
		{BaseType: jamf.BaseType{ID: 3, Name: "carol.smith"}, FullName: "Carol Smith", Email: "carol.smith@example.com"},
		{BaseType: jamf.BaseType{ID: 4, Name: "dave.jones"}, FullName: "Dave Jones", Email: "dave.jones@example.com"},
		{
			BaseType: jamf.BaseType{ID: 5, Name: "eve.miller"},
			FullName: "Eve Miller", Email: "eve.miller@example.com",
			Sites: jamf.UserSites{remote},
		},
	}
	for _, u := range users {
		s.users[u.ID] = u
		s.userList = append(s.userList, u)
	}
	s.nextUserID = len(users)

	admin1 := &jamf.UserAccount{
		BaseType: jamf.BaseType{ID: 101, Name: "admin1"}, FullName: "Admin One", Email: "admin1@example.com",
		Enabled: enabledValue, AccessLevel: accessLevelFullAccess, PrivilegeSet: privilegeSetAdministrator, Site: headquarters,
	}
	admin2 := &jamf.UserAccount{
		BaseType: jamf.BaseType{ID: 102, Name: "admin2"}, FullName: "Admin Two", Email: "admin2@example.com",
		Enabled: "Disabled", AccessLevel: accessLevelFullAccess, PrivilegeSet: privilegeSetAuditor, Site: headquarters,
	}
	admin3 := &jamf.UserAccount{
		BaseType: jamf.BaseType{ID: 103, Name: "admin3"}, FullName: "Admin Three", Email: "admin3@example.com",
		Enabled: enabledValue, AccessLevel: accessLevelFullAccess, PrivilegeSet: privilegeSetCustom, Site: remote,
		Privileges: jamf.Privileges{JSSObjects: []string{privilegeReadAdvancedComputerSearches}},
	}
	// admin4 has Group Access: its rights come entirely from group-admins
	// membership below, and PrivilegeSet is a stale leftover from before it
	// was switched to Group Access (see handleUpdateAccountPrivileges).
	admin4 := &jamf.UserAccount{
		BaseType: jamf.BaseType{ID: 104, Name: "admin4"}, FullName: "Admin Four", Email: "admin4@example.com",
		Enabled: enabledValue, AccessLevel: accessLevelGroupAccess, PrivilegeSet: privilegeSetAdministrator, Site: headquarters,
	}
	accounts := []*jamf.UserAccount{admin1, admin2, admin3, admin4}
	for _, a := range accounts {
		s.accounts[a.ID] = a
		s.accountList = append(s.accountList, a)
	}
	s.nextAccountID = accounts[len(accounts)-1].ID

	admin1Ref := jamf.BaseType{ID: admin1.ID, Name: admin1.Name}
	admin2Ref := jamf.BaseType{ID: admin2.ID, Name: admin2.Name}
	admin3Ref := jamf.BaseType{ID: admin3.ID, Name: admin3.Name}
	admin4Ref := jamf.BaseType{ID: admin4.ID, Name: admin4.Name}

	groups := []*jamf.Group{
		{
			BaseType: jamf.BaseType{ID: 201, Name: "group-admins"}, AccessLevel: accessLevelFullAccess, PrivilegeSet: privilegeSetAdministrator, Site: headquarters,
			Members: []jamf.BaseType{admin1Ref, admin2Ref, admin4Ref},
		},
		{
			BaseType: jamf.BaseType{ID: 202, Name: "group-auditors"}, AccessLevel: accessLevelFullAccess, PrivilegeSet: privilegeSetAuditor, Site: headquarters,
			Members: []jamf.BaseType{admin2Ref, admin3Ref},
		},
		{
			BaseType: jamf.BaseType{ID: 203, Name: "group-custom"}, AccessLevel: accessLevelFullAccess, PrivilegeSet: privilegeSetCustom, Site: remote,
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

	// privilegeReadKnobs is in the catalog (matching the Pro catalog carrying
	// names no write path accepts) but deliberately absent from
	// knownPrivilegeNames, so a write naming it is silently dropped.
	s.privileges = []string{
		privilegeReadAdvancedComputerSearches,
		privilegeUpdateAdvancedComputerSearches,
		privilegeReadUser,
		privilegeUpdateUser,
		privilegeReadKnobs,
	}
}

// adminGroupsContainingLocked returns the admin groups accountID belongs to,
// as the {id,name} refs a Group Access account's GET reports under
// <groups>. Assumes the caller already holds s.mu.
func (s *server) adminGroupsContainingLocked(accountID int) []jamf.BaseType {
	var groups []jamf.BaseType
	for _, g := range s.groupList {
		if containsBaseTypeID(g.Members, accountID) {
			groups = append(groups, jamf.BaseType{ID: g.ID, Name: g.Name})
		}
	}
	return groups
}

func containsBaseTypeID(items []jamf.BaseType, id int) bool {
	for _, item := range items {
		if item.ID == id {
			return true
		}
	}
	return false
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

	case http.MethodPut:
		// Site Grant/Revoke: AddUserSite/RemoveUserSite PUT the full desired
		// <sites> list after a read-modify-write in the client. Per Classic
		// API field-level-merge semantics, only <sites> is touched — every
		// other field on the user record is left as-is.
		s.handleUpdateUserSites(w, r, id)

	case http.MethodPost:
		// POST bodies must be XML, not JSON.
		body, ok := decodeXMLBody[jamf.UserCreateBody](w, r)
		if !ok {
			return
		}
		if body.Name == "" {
			writeJSONError(w, http.StatusBadRequest, "name is required")
			return
		}

		s.mu.Lock()
		// This 409 (and the account create path below) is unverified: the
		// duplicate-name POST status has not been confirmed against a live
		// Jamf tenant.
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
		id := u.ID
		s.mu.Unlock()

		// createuserbyid declares 201 with no response body schema; the docs
		// state only that the result includes the created resource's ID.
		writeJSON(w, http.StatusCreated, createResponse{ID: id})

	case http.MethodDelete:
		s.mu.Lock()
		_, ok := s.users[id]
		if ok {
			delete(s.users, id)
			s.userList = deleteByID(s.userList, id, func(u *jamf.User) int { return u.ID })
			s.removeUserFromAllUserGroupsLocked(id)
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

// removeUserFromAllUserGroupsLocked removes userID from every user group's
// member list — a live tenant does this automatically when a directory user
// is deleted. Assumes the caller already holds s.mu.
func (s *server) removeUserFromAllUserGroupsLocked(userID int) {
	for _, ug := range s.userGroupList {
		ug.Users = deleteByID(ug.Users, userID, func(u jamf.User) int { return u.ID })
	}
}

// userSiteRef decodes a single <site> element of a <sites> write.
type userSiteRef struct {
	ID int `xml:"id"`
}

// userSitesPutBody is the write-side counterpart of jamf.UserSitesUpdateBody,
// with <sites> as a pointer so the handler can tell "omitted" (nil: the
// field-level merge leaves the user's current site list untouched) apart
// from "present" (even an empty element: replace it wholesale) — the same
// distinction groupMembersPutBody makes for <members>.
type userSitesPutBody struct {
	XMLName xml.Name `xml:"user"`
	Sites   *struct {
		Items []userSiteRef `xml:"site"`
	} `xml:"sites"`
}

// handleUpdateUserSites implements the write half of Site Grant/Revoke's
// read-modify-write: PUT /JSSResource/users/id/{id} carrying only <sites>.
// There is no distinct "already a member"/"not a member" error status here —
// AddUserSite/RemoveUserSite absorb both cases client-side before ever
// issuing this PUT (see pkg/jamf/client.go), so this handler simply replaces
// the user's Sites wholesale for a known user, delegating validation to
// resolveUserSitesLocked.
func (s *server) handleUpdateUserSites(w http.ResponseWriter, r *http.Request, id int) {
	body, ok := decodeXMLBody[userSitesPutBody](w, r)
	if !ok {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.users[id]
	if !ok {
		writeJSONError(w, http.StatusNotFound, "user not found")
		return
	}

	if body.Sites == nil {
		// <sites> omitted entirely — field-level merge leaves it untouched.
		w.WriteHeader(http.StatusCreated)
		return
	}

	newSites, ok := s.resolveUserSitesLocked(body.Sites.Items)
	if !ok {
		writeJSONError(w, http.StatusConflict, "unknown or invalid site id")
		return
	}
	u.Sites = newSites

	w.WriteHeader(http.StatusCreated)
}

// resolveUserSitesLocked validates and dedupes an explicit <sites> write.
// The sentinel id -1 ("None") is dropped rather than looked up — a list of
// only -1 entries therefore resolves to an empty (cleared) site list, same
// as an explicitly empty <sites></sites>. Any other unrecognized or zero id
// fails the whole write with ok=false, mirroring a live tenant's 409 with
// nothing applied. Assumes the caller already holds s.mu.
func (s *server) resolveUserSitesLocked(items []userSiteRef) (jamf.UserSites, bool) {
	seen := make(map[int]bool, len(items))
	out := make(jamf.UserSites, 0, len(items))
	for _, item := range items {
		if item.ID == noneSiteID {
			continue
		}
		site, found := s.findSiteByIDLocked(item.ID)
		if !found {
			return nil, false
		}
		if seen[site.ID] {
			continue
		}
		seen[site.ID] = true
		out = append(out, site.BaseType)
	}
	return out, true
}

// findSiteByIDLocked assumes the caller already holds s.mu.
func (s *server) findSiteByIDLocked(id int) (jamf.Site, bool) {
	for _, site := range s.sites {
		if site.ID == id {
			return site, true
		}
	}
	return jamf.Site{}, false
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
		var groups []jamf.BaseType
		if ok {
			cp = *a
			if a.AccessLevel == accessLevelGroupAccess {
				groups = s.adminGroupsContainingLocked(a.ID)
			} else {
				cp.Privileges = privilegesForRead(a.PrivilegeSet, a.Privileges)
			}
		}
		s.mu.Unlock()
		if !ok {
			writeJSONError(w, http.StatusNotFound, "account not found")
			return
		}
		if cp.AccessLevel == accessLevelGroupAccess {
			// A Group Access account's rights come entirely from its groups:
			// its GET carries <groups> and omits <privileges> altogether.
			writeJSON(w, http.StatusOK, groupAccessAccountResponse{Account: groupAccessAccount{
				BaseType: cp.BaseType, FullName: cp.FullName, Email: cp.Email, Enabled: cp.Enabled,
				AccessLevel: cp.AccessLevel, PrivilegeSet: cp.PrivilegeSet, Site: cp.Site, Groups: groups,
			}})
			return
		}
		writeJSON(w, http.StatusOK, jamf.UserAccountResponse{UserAccount: cp})

	case http.MethodPut:
		s.handleUpdateAccountPrivileges(w, r, id)

	case http.MethodPost:
		body, ok := decodeXMLBody[jamf.UserAccountCreateBody](w, r)
		if !ok {
			return
		}
		if body.Name == "" || body.Password == "" {
			writeJSONError(w, http.StatusBadRequest, "name and password are required")
			return
		}
		enumChecks := []struct {
			name    string
			value   string
			allowed []string
		}{
			{"access_level", body.AccessLevel, validAccessLevels},
			{"privilege_set", body.PrivilegeSet, validPrivilegeSets},
			{"enabled", body.Enabled, validEnabledValues},
		}
		for _, c := range enumChecks {
			if c.value != "" && !slices.Contains(c.allowed, c.value) {
				writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid %s %q", c.name, c.value))
				return
			}
		}

		s.mu.Lock()
		// Jamf does not document a per-endpoint error code for a name
		// collision on createaccountbyid — 409 only appears in the Classic
		// API Overview's generic response-code table, alongside 400 for a
		// malformed XML body. This status is not confirmed against a live
		// tenant.
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
		if body.Privileges != nil {
			a.Privileges = *body.Privileges
		}
		s.accounts[a.ID] = a
		s.accountList = append(s.accountList, a)
		id := a.ID
		s.mu.Unlock()

		// createaccountbyid declares 201 with no response body schema; the
		// docs state only that the result includes the created resource's ID.
		writeJSON(w, http.StatusCreated, createResponse{ID: id})

	case http.MethodDelete:
		s.mu.Lock()
		_, ok := s.accounts[id]
		if ok {
			delete(s.accounts, id)
			s.accountList = deleteByID(s.accountList, id, func(a *jamf.UserAccount) int { return a.ID })
			s.removeAccountFromAllGroupsLocked(id)
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

// groupAccessAccount is the JSON shape of a Group Access account's GET: it
// carries the admin groups it belongs to and has no privileges field at all
// — a Group Access account's rights come from its groups, never its own
// (possibly stale) privilege_set/privileges.
type groupAccessAccount struct {
	jamf.BaseType
	FullName     string          `json:"full_name"`
	Email        string          `json:"email"`
	Enabled      string          `json:"enabled"`
	AccessLevel  string          `json:"access_level"`
	PrivilegeSet string          `json:"privilege_set"`
	Site         jamf.BaseType   `json:"site"`
	Groups       []jamf.BaseType `json:"groups"`
}

type groupAccessAccountResponse struct {
	Account groupAccessAccount `json:"account"`
}

// removeAccountFromAllGroupsLocked removes accountID from every admin
// group's member list. Mirrors a live tenant: any successful PUT on a Full
// or Site Access account drops it from the admin groups it belonged to
// (membership is inert for those access levels, so nothing is lost), and
// deleting an account removes it from the groups that listed it. Assumes
// the caller already holds s.mu.
func (s *server) removeAccountFromAllGroupsLocked(accountID int) {
	for _, g := range s.groupList {
		g.Members = deleteByID(g.Members, accountID, func(m jamf.BaseType) int { return m.ID })
	}
}

// accountPrivilegesPutBody decodes PUT /JSSResource/accounts/userid/{id} —
// the minimal body Role Grant/Revoke sends (pkg/jamf.AccountPrivilegesUpdateBody).
// Site is included here purely as a defensive 409 guard: the connector never
// sends it for this endpoint, but the mock should reject it exactly like a
// live tenant if it ever appears.
type accountPrivilegesPutBody struct {
	XMLName      xml.Name         `xml:"account"`
	Name         string           `xml:"name"`
	PrivilegeSet string           `xml:"privilege_set"`
	Privileges   *jamf.Privileges `xml:"privileges"`
	Site         *jamf.BaseType   `xml:"site"`
}

// handleUpdateAccountPrivileges implements Role Grant/Revoke for the
// userAccount principal: PUT /JSSResource/accounts/userid/{id}. A 201
// response means success; an invalid privilege_set or a zero site ID is
// rejected with 409. For a Full or Site
// Access account, a <privileges> block is only applied when the resulting
// privilege_set is Custom, writing Custom with the block omitted copies a
// fixed non-empty privilege list rather than leaving privileges empty (see
// applyPrivilegeSetUpdate), and any successful write drops the account from
// every admin group it belonged to (that membership is inert for these
// access levels). A Group Access account instead only has its stored
// privilege_set changed — <privileges> is ignored and group membership is
// left alone, since its rights come from its groups, not its own privileges.
func (s *server) handleUpdateAccountPrivileges(w http.ResponseWriter, r *http.Request, id int) {
	body, ok := decodeXMLBody[accountPrivilegesPutBody](w, r)
	if !ok {
		return
	}

	if body.Site != nil && body.Site.ID == 0 {
		writeJSONError(w, http.StatusConflict, "site id 0 is not a valid site")
		return
	}
	if body.PrivilegeSet != "" && !slices.Contains(validPrivilegeSets, body.PrivilegeSet) {
		writeJSONError(w, http.StatusConflict, fmt.Sprintf("invalid privilege_set %q", body.PrivilegeSet))
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	a, ok := s.accounts[id]
	if !ok {
		writeJSONError(w, http.StatusNotFound, "account not found")
		return
	}

	if body.Name != "" {
		a.Name = body.Name
	}

	if a.AccessLevel == accessLevelGroupAccess {
		if body.PrivilegeSet != "" {
			a.PrivilegeSet = body.PrivilegeSet
		}
	} else {
		applyPrivilegeSetUpdate(&a.PrivilegeSet, &a.Privileges, body.PrivilegeSet, body.Privileges)
		s.removeAccountFromAllGroupsLocked(a.ID)
	}

	w.WriteHeader(http.StatusCreated)
}

// applyPrivilegeSetUpdate applies a PUT's privilege_set/privileges change to
// an account or group's stored fields in place:
//
//   - newSet == "" leaves the current set untouched (field-level merge).
//   - Explicitly setting privilege_set to Custom with newPrivileges == nil
//     (the <privileges> element omitted entirely) copies a fixed full
//     privilege list rather than leaving privileges empty — the
//     privilege-escalation trap a correct write must always avoid by sending
//     an explicit, even empty, block whenever it writes Custom.
//   - Otherwise, a non-nil newPrivileges replaces the stored privileges
//     wholesale, but only takes effect when the resulting set is Custom —
//     it's ignored for any other set. Names this mock doesn't recognize are
//     dropped, and "Read License Information" is always present in the
//     result, mirroring Jamf never letting it be removed.
//   - privilege_set omitted and privileges omitted leaves privileges
//     untouched, regardless of the current stored set.
func applyPrivilegeSetUpdate(set *string, privileges *jamf.Privileges, newSet string, newPrivileges *jamf.Privileges) {
	settingCustomWithNoBlock := newSet == privilegeSetCustom && newPrivileges == nil

	if newSet != "" {
		*set = newSet
	}

	switch {
	case settingCustomWithNoBlock:
		*privileges = copiedFullPrivilegeList
	case newPrivileges != nil && *set == privilegeSetCustom:
		*privileges = jamf.Privileges{
			JSSObjects:    filterKnownPrivileges(newPrivileges.JSSObjects),
			JSSSettings:   filterKnownPrivileges(newPrivileges.JSSSettings),
			JSSActions:    filterKnownPrivileges(newPrivileges.JSSActions),
			Recon:         filterKnownPrivileges(newPrivileges.Recon),
			CasperAdmin:   filterKnownPrivileges(newPrivileges.CasperAdmin),
			CasperRemote:  filterKnownPrivileges(newPrivileges.CasperRemote),
			CasperImaging: filterKnownPrivileges(newPrivileges.CasperImaging),
		}
		if !privileges.Contains(privilegeReadLicenseInformation) {
			privileges.JSSObjects = append(privileges.JSSObjects, privilegeReadLicenseInformation)
		}
	}
}

// filterKnownPrivileges drops any name not in knownPrivilegeNames (and not
// privilegeReadLicenseInformation, handled separately by the caller),
// mirroring Jamf silently dropping privilege names it doesn't recognize.
func filterKnownPrivileges(names []string) []string {
	if len(names) == 0 {
		return nil
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		if slices.Contains(knownPrivilegeNames, n) || n == privilegeReadLicenseInformation {
			out = append(out, n)
		}
	}
	return out
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
	id, err := pathID(r.URL.Path, "/JSSResource/accounts/groupid/")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.mu.Lock()
		g, ok := s.groups[id]
		var cp jamf.Group
		if ok {
			cp = *g
			cp.Privileges = privilegesForRead(g.PrivilegeSet, g.Privileges)
		}
		s.mu.Unlock()
		if !ok {
			writeJSONError(w, http.StatusNotFound, "group not found")
			return
		}
		writeJSON(w, http.StatusOK, jamf.GroupResponse{Group: cp})

	case http.MethodPut:
		s.handleUpdateGroupMembers(w, r, id)

	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// groupMembersPutBody decodes PUT /JSSResource/accounts/groupid/{id}. It is a
// superset of both PUT bodies the connector sends to this endpoint:
// UpdateGroupPrivileges's minimal privilege-only body (name, privilege_set,
// privileges) and UpdateGroupMembers's minimal membership-only body (name,
// members). Site, Members, and Privileges are pointers so the handler can
// tell "the element was present" (even an empty one) apart from "omitted":
// omitting <members> keeps the existing list, an explicit empty element
// clears it; likewise for <privileges> (see applyPrivilegeSetUpdate).
type groupMembersPutBody struct {
	XMLName      xml.Name         `xml:"group"`
	Name         string           `xml:"name"`
	AccessLevel  string           `xml:"access_level"`
	PrivilegeSet string           `xml:"privilege_set"`
	Privileges   *jamf.Privileges `xml:"privileges"`
	Site         *jamf.BaseType   `xml:"site"`
	Members      *struct {
		Users []jamf.BaseType `xml:"user"`
	} `xml:"members"`
}

// handleUpdateGroupMembers implements both admin account Group Grant/Revoke
// (membership changes) and Role Grant/Revoke for the group principal — both
// PUT /JSSResource/accounts/groupid/{id}. A 201 response means success; an
// empty/omitted <name> leaves the stored name untouched (field-level merge);
// omitting <members> keeps the
// group's existing member list; an explicit (possibly empty) <members>
// element replaces it wholesale; member ids this mock doesn't recognize are
// silently dropped rather than rejected, and repeated ids are deduplicated,
// same as a live tenant; an invalid privilege_set or <site><id>0</id></site>
// is rejected with 409; and <privileges> follows applyPrivilegeSetUpdate's
// semantics.
func (s *server) handleUpdateGroupMembers(w http.ResponseWriter, r *http.Request, id int) {
	body, ok := decodeXMLBody[groupMembersPutBody](w, r)
	if !ok {
		return
	}

	if body.Site != nil && body.Site.ID == 0 {
		writeJSONError(w, http.StatusConflict, "site id 0 is not a valid site")
		return
	}
	if body.PrivilegeSet != "" && !slices.Contains(validPrivilegeSets, body.PrivilegeSet) {
		writeJSONError(w, http.StatusConflict, fmt.Sprintf("invalid privilege_set %q", body.PrivilegeSet))
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	g, ok := s.groups[id]
	if !ok {
		writeJSONError(w, http.StatusNotFound, "group not found")
		return
	}

	if body.Name != "" {
		g.Name = body.Name
	}
	if body.AccessLevel != "" {
		g.AccessLevel = body.AccessLevel
	}
	applyPrivilegeSetUpdate(&g.PrivilegeSet, &g.Privileges, body.PrivilegeSet, body.Privileges)
	if body.Site != nil {
		g.Site = *body.Site
	}

	if body.Members != nil {
		seen := make(map[int]bool, len(body.Members.Users))
		members := make([]jamf.BaseType, 0, len(body.Members.Users))
		for _, u := range body.Members.Users {
			account, ok := s.accounts[u.ID]
			if !ok {
				continue // unknown member id — silently dropped, same as a live tenant
			}
			if seen[account.ID] {
				continue // duplicate — deduplicated, same as a live tenant
			}
			seen[account.ID] = true
			members = append(members, jamf.BaseType{ID: account.ID, Name: account.Name})
		}
		g.Members = members
	}

	w.WriteHeader(http.StatusCreated)
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
	id, err := pathID(r.URL.Path, "/JSSResource/usergroups/id/")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}

	switch r.Method {
	case http.MethodGet:
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

	case http.MethodPut:
		s.handleUpdateUserGroupMembers(w, r, id)

	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleUpdateUserGroupMembers implements User Group Grant/Revoke: PUT
// /JSSResource/usergroups/id/{id} carrying either <user_additions> or
// <user_deletions>. Adding an existing member (or adding to a smart group)
// 201s and changes nothing; adding an unknown user id or removing a
// non-member 409s with "Unable to match user ... in additions/deletions
// list" and applies nothing — every id in the list is validated before any
// mutation happens, so a later invalid id can't leave an earlier valid one
// partially applied.
func (s *server) handleUpdateUserGroupMembers(w http.ResponseWriter, r *http.Request, id int) {
	body, ok := decodeXMLBody[jamf.UserGroupMemberMutation](w, r)
	if !ok {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	g, ok := s.userGroups[id]
	if !ok {
		writeJSONError(w, http.StatusNotFound, "user group not found")
		return
	}

	switch {
	case body.Additions != nil:
		if g.IsSmart {
			w.WriteHeader(http.StatusCreated)
			return
		}
		for _, u := range body.Additions.Users {
			if _, ok := s.users[u.ID]; !ok {
				writeJSONError(w, http.StatusConflict, fmt.Sprintf("Unable to match user in additions list id=%d", u.ID))
				return
			}
		}
		for _, u := range body.Additions.Users {
			if userGroupHasMember(g, u.ID) {
				continue
			}
			g.Users = append(g.Users, *s.users[u.ID])
		}
		w.WriteHeader(http.StatusCreated)
	case body.Deletions != nil:
		for _, u := range body.Deletions.Users {
			if !userGroupHasMember(g, u.ID) {
				writeJSONError(w, http.StatusConflict, fmt.Sprintf("Unable to match user in deletions list id=%d", u.ID))
				return
			}
		}
		for _, u := range body.Deletions.Users {
			g.Users = deleteByID(g.Users, u.ID, func(m jamf.User) int { return m.ID })
		}
		w.WriteHeader(http.StatusCreated)
	default:
		writeJSONError(w, http.StatusBadRequest, "request must set user_additions or user_deletions")
	}
}

func userGroupHasMember(g *jamf.UserGroup, userID int) bool {
	for _, u := range g.Users {
		if u.ID == userID {
			return true
		}
	}
	return false
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
// contract (XML only) and decodes the body into T. On any failure it writes
// the response itself and returns ok=false.
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

// errorBody is JSON for every mocked error, including auth and validation
// failures. A live Jamf Pro tenant instead returns HTML (or an empty body
// for an invalid/expired token) for Classic API errors. Left as JSON here:
// the connector maps errors purely off HTTP status code, via
// vendor/github.com/conductorone/baton-sdk/pkg/uhttp (GrpcCodeFromHTTPStatus)
// — it never parses this body — so this divergence has no functional effect
// on the connector.
type errorBody struct {
	Message string `json:"message"`
}

// createResponse mirrors the only field the Classic API's create endpoints
// actually document returning — the new resource's ID.
type createResponse struct {
	ID int `json:"id"`
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
