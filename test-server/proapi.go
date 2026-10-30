package main

import (
	"cmp"
	"fmt"
	"maps"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/conductorone/baton-jamf/pkg/jamf"
)

const (
	// Documented page-size maximum of GET /api/v1/users.
	proUsersMaxPageSize = 1000

	siteIDLarge   = 3
	siteNameLarge = "Large Site"

	userGroupIDBulk   = 304
	userGroupNameBulk = "usergroup-bulk"

	// The bulk users cross the users page size; the bulk group and the large site
	// hold more members than one grants page and one site objects page (1000 each).
	bulkUserIDBase       = 1000
	bulkUserCount        = 2100
	bulkGroupMemberCount = 1200
	bulkSiteUserCount    = 1100

	siteObjectTypeUser      = "User"
	siteObjectTypeUserGroup = "User Group"

	// Values the Pro accounts schema documents for an unset field.
	proAccessLevelDefault    = "FullAccess"
	proPrivilegeLevelDefault = "ADMINISTRATOR"
	proAccountStatusDefault  = "Enabled"

	// Accounts without a site report -1.
	proNoSiteID = -1
)

// proUser is one entry of GET /api/v1/users results.
type proUser struct {
	ID                   string  `json:"id"`
	Username             string  `json:"username"`
	Realname             string  `json:"realname"`
	Email                string  `json:"email"`
	Phone                *string `json:"phone"`
	Position             *string `json:"position"`
	EnableCustomPhotoURL bool    `json:"enableCustomPhotoUrl"`
	CustomPhotoURL       string  `json:"customPhotoUrl"`
	ManagedAppleID       string  `json:"managedAppleId"`
}

type proPagedUsers struct {
	Page        int       `json:"page"`
	PageSize    int       `json:"pageSize"`
	TotalCount  int       `json:"totalCount"`
	TotalPages  int       `json:"totalPages"`
	HasNext     bool      `json:"hasNext"`
	HasPrevious bool      `json:"hasPrevious"`
	Results     []proUser `json:"results"`
}

// proAccount is one entry of GET /api/v1/accounts results.
type proAccount struct {
	ID             string `json:"id"`
	Username       string `json:"username"`
	Realname       string `json:"realname"`
	Email          string `json:"email"`
	SiteID         int    `json:"siteId"`
	AccessLevel    string `json:"accessLevel"`
	PrivilegeLevel string `json:"privilegeLevel"`
	AccountStatus  string `json:"accountStatus"`
	AccountType    string `json:"accountType"`
}

type proAccountSearchResults struct {
	TotalCount int          `json:"totalCount"`
	Results    []proAccount `json:"results"`
}

// proSiteObject is one entry of the bare array GET /api/v1/sites/{id}/objects returns.
type proSiteObject struct {
	SiteID     string `json:"siteId"`
	ObjectType string `json:"objectType"`
	ObjectID   string `json:"objectId"`
}

// siteObject is an object assigned to a site, before it is written as a proSiteObject.
type siteObject struct {
	objectType string
	objectID   int
}

// seedBulkDirectory adds users past the users page size, a user group with more
// members than one grants page, and a site with more users than one site objects page.
func (s *server) seedBulkDirectory() {
	largeSite := jamf.BaseType{ID: siteIDLarge, Name: siteNameLarge}
	s.sites = append(s.sites, jamf.Site{BaseType: largeSite})

	bulkUsers := make([]*jamf.User, 0, bulkUserCount)
	for i := 1; i <= bulkUserCount; i++ {
		user := &jamf.User{
			BaseType: jamf.BaseType{ID: bulkUserIDBase + i, Name: fmt.Sprintf("bulk.user%04d", i)},
			FullName: fmt.Sprintf("Bulk User %04d", i),
			Email:    fmt.Sprintf("bulk.user%04d@example.com", i),
		}
		if i <= bulkSiteUserCount {
			user.Sites = jamf.UserSites{largeSite}
		}
		bulkUsers = append(bulkUsers, user)
		s.users[user.ID] = user
		s.userList = append(s.userList, user)
	}
	s.nextUserID = bulkUserIDBase + bulkUserCount

	members := make([]jamf.User, 0, bulkGroupMemberCount)
	for _, user := range bulkUsers[:bulkGroupMemberCount] {
		members = append(members, *user)
	}
	bulkGroup := &jamf.UserGroup{
		BaseType: jamf.BaseType{ID: userGroupIDBulk, Name: userGroupNameBulk},
		Site:     jamf.Site{BaseType: largeSite},
		Users:    members,
	}
	s.userGroups[bulkGroup.ID] = bulkGroup
	s.userGroupList = append(s.userGroupList, bulkGroup)
}

// handleProListUsers serves one page of GET /api/v1/users. The only filter it
// accepts is username=="<value>" and email=="<value>" terms joined by ",".
//
// Doc URL: https://developer.jamf.com/jamf-pro/reference/get_v1-users
func (s *server) handleProListUsers(w http.ResponseWriter, r *http.Request) {
	if !s.requireBearer(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method must be GET")
		return
	}

	page, pageSize, ok := parsePaging(w, r)
	if !ok {
		return
	}
	if pageSize > proUsersMaxPageSize {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("page-size must be at most %d", proUsersMaxPageSize))
		return
	}
	matches, err := parseUserFilter(r.URL.Query().Get("filter"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, ok := requestSort(w, r, "id:asc", "id:asc"); !ok {
		return
	}

	s.mu.Lock()
	users := slices.DeleteFunc(slices.Clone(s.userList), func(user *jamf.User) bool { return !matches(user) })
	slices.SortFunc(users, func(left, right *jamf.User) int { return cmp.Compare(left.ID, right.ID) })
	pageUsers := pageOf(users, page, pageSize)
	results := make([]proUser, 0, len(pageUsers))
	for _, user := range pageUsers {
		results = append(results, proUser{
			ID:       strconv.Itoa(user.ID),
			Username: user.Name,
			Realname: user.FullName,
			Email:    user.PrimaryEmail(),
			Phone:    nullableString(user.PhoneNumber),
			Position: nullableString(user.Position),
		})
	}
	s.mu.Unlock()

	totalPages := ceilDiv(len(users), pageSize)
	writeJSON(w, http.StatusOK, proPagedUsers{
		Page:        page,
		PageSize:    pageSize,
		TotalCount:  len(users),
		TotalPages:  totalPages,
		HasNext:     page+1 < totalPages,
		HasPrevious: page > 0,
		Results:     results,
	})
}

// handleProListAccounts serves one page of GET /api/v1/accounts. The only filter
// it accepts is a single privilegeLevel==<ENUM> or siteId==<int> term.
//
// Doc URL: https://developer.jamf.com/jamf-pro/reference/get_v1-accounts
func (s *server) handleProListAccounts(w http.ResponseWriter, r *http.Request) {
	if !s.requireBearer(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method must be GET")
		return
	}

	page, pageSize, ok := parsePaging(w, r)
	if !ok {
		return
	}
	matches, err := parseAccountsFilter(r.URL.Query().Get("filter"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	sortValue, ok := requestSort(w, r, "username:asc", "username:asc", "id:asc")
	if !ok {
		return
	}

	s.mu.Lock()
	accounts := slices.DeleteFunc(slices.Clone(s.accountList), func(account *jamf.UserAccount) bool { return !matches(account) })
	if sortValue == "id:asc" {
		slices.SortFunc(accounts, func(left, right *jamf.UserAccount) int { return cmp.Compare(left.ID, right.ID) })
	} else {
		slices.SortFunc(accounts, func(left, right *jamf.UserAccount) int {
			return cmp.Or(strings.Compare(left.Name, right.Name), cmp.Compare(left.ID, right.ID))
		})
	}
	pageAccounts := pageOf(accounts, page, pageSize)
	results := make([]proAccount, 0, len(pageAccounts))
	for _, account := range pageAccounts {
		results = append(results, proAccount{
			ID:             strconv.Itoa(account.ID),
			Username:       account.Name,
			Realname:       account.FullName,
			Email:          account.Email,
			SiteID:         proAccountSiteID(account),
			AccessLevel:    cmp.Or(proAccessLevels[account.AccessLevel], proAccessLevelDefault),
			PrivilegeLevel: proAccountPrivilegeLevel(account),
			AccountStatus:  cmp.Or(account.Enabled, proAccountStatusDefault),
			AccountType:    "DEFAULT",
		})
	}
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, proAccountSearchResults{TotalCount: len(accounts), Results: results})
}

// handleProSiteObjects serves one page of GET /api/v1/sites/{id}/objects as a bare
// array. An unknown site answers an empty array, as Jamf does; no filter returns every object.
//
// Doc URL: https://developer.jamf.com/jamf-pro/reference/get_v1-sites-id-objects
func (s *server) handleProSiteObjects(w http.ResponseWriter, r *http.Request) {
	if !s.requireBearer(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method must be GET")
		return
	}

	siteID, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid site id")
		return
	}
	page, pageSize, ok := parsePaging(w, r)
	if !ok {
		return
	}
	sortValue, ok := requestSort(w, r, "objectType:asc", "objectType:asc", "objectId:asc")
	if !ok {
		return
	}
	matches, err := parseObjectTypeFilter(r.URL.Query().Get("filter"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.mu.Lock()
	objects := s.siteObjectsLocked(siteID)
	s.mu.Unlock()

	objects = slices.DeleteFunc(objects, func(object siteObject) bool { return !matches(object) })
	slices.SortFunc(objects, func(left, right siteObject) int {
		if sortValue == "objectId:asc" {
			return cmp.Or(cmp.Compare(left.objectID, right.objectID), strings.Compare(left.objectType, right.objectType))
		}
		return cmp.Or(strings.Compare(left.objectType, right.objectType), cmp.Compare(left.objectID, right.objectID))
	})
	pageObjects := pageOf(objects, page, pageSize)
	results := make([]proSiteObject, 0, len(pageObjects))
	for _, object := range pageObjects {
		results = append(results, proSiteObject{
			SiteID:     strconv.Itoa(siteID),
			ObjectType: object.objectType,
			ObjectID:   strconv.Itoa(object.objectID),
		})
	}
	writeJSON(w, http.StatusOK, results)
}

// siteObjectsLocked returns the users of a site and the user groups it owns, none
// for an unknown site. Assumes the caller already holds s.mu.
func (s *server) siteObjectsLocked(siteID int) []siteObject {
	if _, found := s.findSiteByIDLocked(siteID); !found {
		return nil
	}

	var objects []siteObject
	for _, user := range s.userList {
		if containsBaseTypeID(user.Sites, siteID) {
			objects = append(objects, siteObject{objectType: siteObjectTypeUser, objectID: user.ID})
		}
	}
	for _, userGroup := range s.userGroupList {
		if userGroup.Site.ID == siteID {
			objects = append(objects, siteObject{objectType: siteObjectTypeUserGroup, objectID: userGroup.ID})
		}
	}
	return objects
}

var (
	userFilterTermPattern = regexp.MustCompile(`^(username|email)=="((?:[^"\\]|\\.)*)"(?:,|$)`)
	userFilterUnescaper   = strings.NewReplacer(`\"`, `"`, `\\`, `\`)
)

// userFilterTerm is one username=="<value>" or email=="<value>" term of a users filter.
type userFilterTerm struct {
	field string
	value string
}

// parseUserFilter reads username=="<value>" / email=="<value>" terms joined by ",".
// The predicate matches a user equal to any term, ignoring case; no filter matches every user.
func parseUserFilter(filter string) (func(*jamf.User) bool, error) {
	if filter == "" {
		return func(*jamf.User) bool { return true }, nil
	}

	var terms []userFilterTerm
	for rest := filter; rest != ""; {
		match := userFilterTermPattern.FindStringSubmatch(rest)
		if match == nil {
			return nil, fmt.Errorf("unsupported filter %q: the mock only accepts username==\"<v>\" and email==\"<v>\" terms joined by \",\"", filter)
		}
		terms = append(terms, userFilterTerm{field: match[1], value: userFilterUnescaper.Replace(match[2])})
		rest = rest[len(match[0]):]
	}

	return func(user *jamf.User) bool {
		return slices.ContainsFunc(terms, func(term userFilterTerm) bool {
			if term.field == "username" {
				return strings.EqualFold(user.Name, term.value)
			}
			return strings.EqualFold(user.PrimaryEmail(), term.value)
		})
	}, nil
}

var (
	// Classic access_level / privilege_set values and their Pro enums.
	proAccessLevels = map[string]string{
		accessLevelFullAccess:  "FullAccess",
		"Site Access":          "SiteAccess",
		accessLevelGroupAccess: "GroupBasedAccess",
	}
	proPrivilegeLevels = map[string]string{
		privilegeSetAdministrator: "ADMINISTRATOR",
		privilegeSetAuditor:       "AUDITOR",
		"Enrollment Only":         "ENROLLMENT",
		privilegeSetCustom:        "CUSTOM",
	}

	accountsFilterPattern = regexp.MustCompile(`^\s*(privilegeLevel|siteId)\s*==\s*(?:"([^"]*)"|([^\s"]+))\s*$`)
)

// parseAccountsFilter reads privilegeLevel==<ENUM> (the enum may be quoted) or siteId==<int>.
// The predicate matches the accounts that satisfy it; no filter matches every account.
func parseAccountsFilter(filter string) (func(*jamf.UserAccount) bool, error) {
	if filter == "" {
		return func(*jamf.UserAccount) bool { return true }, nil
	}

	match := accountsFilterPattern.FindStringSubmatch(filter)
	if match == nil {
		return nil, fmt.Errorf("unsupported filter %q: the mock only accepts privilegeLevel==<ENUM> and siteId==<int>", filter)
	}
	field, value := match[1], cmp.Or(match[2], match[3])

	if field == "siteId" {
		siteID, err := strconv.Atoi(value)
		if err != nil {
			return nil, fmt.Errorf("invalid siteId %q: %w", value, err)
		}
		return func(account *jamf.UserAccount) bool { return proAccountSiteID(account) == siteID }, nil
	}

	if !slices.Contains(slices.Collect(maps.Values(proPrivilegeLevels)), value) {
		return nil, fmt.Errorf("invalid privilegeLevel %q", value)
	}
	return func(account *jamf.UserAccount) bool { return proAccountPrivilegeLevel(account) == value }, nil
}

func proAccountSiteID(account *jamf.UserAccount) int {
	if account.Site.ID == 0 {
		return proNoSiteID
	}
	return account.Site.ID
}

func proAccountPrivilegeLevel(account *jamf.UserAccount) string {
	return cmp.Or(proPrivilegeLevels[account.PrivilegeSet], proPrivilegeLevelDefault)
}

var (
	// objectType values the sites objects filter accepts, matched case-insensitively.
	siteObjectTypes = []string{
		"Computer", "Peripheral", "Licensed Software", "Licensed Software Template", "Policy",
		"macOS Configuration Profile", "Restricted Software", "Managed Preference Profile", "Computer Group",
		"Mobile Device", "Apple TV", "Android Device", siteObjectTypeUserGroup, "iOS Configuration Profile",
		"Mobile Device App", "E-book", "Mobile Device Group", "Classroom", "Advanced Computer Search",
		"Advanced Mobile Search", "Advanced User Search", "Advanced User Content Search", "Computer Invitation",
		"Mobile Device Invitation", "Mobile Device Enrollment Profile", "Device Enrollment Program Instance",
		"Mobile Device Prestage", "Computer DEP Prestage", "Enrollment Customization", "VPP Location",
		"VPP Subscription", "VPP Invitation", "VPP Assignment", siteObjectTypeUser, "Network Integration",
		"Mac App", "App Installer", "Self Service Plugin", "Software Title", "Patch Software Title Summary",
		"Patch Policy", "Patch Software Title Configuration", "Change Password", "Mobile Device Inventory",
		"Computer Inventory", "Change Management", "Licensed Software License",
	}

	objectTypeFilterPattern = regexp.MustCompile(`^\s*objectType\s*==\s*(?:"([^"]*)"|([^\s"]+))\s*$`)
)

// parseObjectTypeFilter reads objectType=="<type>". The predicate matches the objects of
// that type; no filter matches every object.
func parseObjectTypeFilter(filter string) (func(siteObject) bool, error) {
	if filter == "" {
		return func(siteObject) bool { return true }, nil
	}

	match := objectTypeFilterPattern.FindStringSubmatch(filter)
	if match == nil {
		return nil, fmt.Errorf("unsupported filter %q: the mock only accepts objectType==\"<type>\"", filter)
	}
	value := cmp.Or(match[1], match[2])
	index := slices.IndexFunc(siteObjectTypes, func(candidate string) bool { return strings.EqualFold(candidate, value) })
	if index < 0 {
		return nil, fmt.Errorf("invalid objectType %q", value)
	}
	objectType := siteObjectTypes[index]

	return func(object siteObject) bool { return object.objectType == objectType }, nil
}

// requestSort returns the request's sort, or defaultSort when absent. A value
// outside supported answers 400.
func requestSort(w http.ResponseWriter, r *http.Request, defaultSort string, supported ...string) (string, bool) {
	sortValue := cmp.Or(r.URL.Query().Get("sort"), defaultSort)
	if !slices.Contains(supported, sortValue) {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("unsupported sort %q: the mock supports %s", sortValue, strings.Join(supported, ", ")))
		return "", false
	}
	return sortValue, true
}

// nullableString maps an empty value to JSON null, as the nullable phone and position fields allow.
func nullableString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func ceilDiv(total, pageSize int) int {
	pages := total / pageSize
	if total%pageSize != 0 {
		pages++
	}
	return pages
}
