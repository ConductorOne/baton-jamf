package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/conductorone/baton-jamf/pkg/jamf"
)

// computerSections are the section= values accepted by GET
// /api/v4/computers-inventory. Any other value is a 400.
var computerSections = []string{
	"GENERAL", "HARDWARE", "OPERATING_SYSTEM", "USER_AND_LOCATION", "DISK_ENCRYPTION", "SECURITY",
}

// mobileLocation is a mobile device's location block as the v2 detail
// endpoint reports it. Jamf fills every field but username from the
// matching directory user when only username is written.
type mobileLocation struct {
	Username     string `json:"username"`
	RealName     string `json:"realName"`
	EmailAddress string `json:"emailAddress"`
	Position     string `json:"position"`
	PhoneNumber  string `json:"phoneNumber"`
}

type mockMobileDevice struct {
	jamf.MobileDevice
	location mobileLocation
}

// mobileDeviceDetailResponse is the subset of GET
// /api/v2/mobile-devices/{id}/detail the connector reads.
type mobileDeviceDetailResponse struct {
	ID       string         `json:"id"`
	Name     string         `json:"name"`
	Location mobileLocation `json:"location"`
}

// computerPatchBody is the PATCH /api/v4/computers-inventory-detail/{id}
// body. Decoded with DisallowUnknownFields: Jamf rejects a key it doesn't
// know with 400 instead of ignoring it.
type computerPatchBody struct {
	UserAndLocation *struct {
		Username     *string `json:"username"`
		Realname     *string `json:"realname"`
		Email        *string `json:"email"`
		Position     *string `json:"position"`
		Phone        *string `json:"phone"`
		DepartmentID *string `json:"departmentId"`
		BuildingID   *string `json:"buildingId"`
		Room         *string `json:"room"`
	} `json:"userAndLocation"`
}

// mobilePatchBody is the PATCH /api/v2/mobile-devices/{id} body, decoded
// the same strict way as computerPatchBody.
type mobilePatchBody struct {
	Name     *string `json:"name"`
	AssetTag *string `json:"assetTag"`
	SiteID   *string `json:"siteId"`
	Location *struct {
		Username     *string `json:"username"`
		RealName     *string `json:"realName"`
		EmailAddress *string `json:"emailAddress"`
		Position     *string `json:"position"`
		PhoneNumber  *string `json:"phoneNumber"`
	} `json:"location"`
}

func (s *server) seedDevices() {
	site := &jamf.NamedRef{ID: "1", Name: siteNameHeadquarters}
	s.computers = []*jamf.ComputerInventory{
		{
			ID: "1", UDID: "8E3C1F4A-0001-4B6E-9C1D-000000000001",
			General: &jamf.ComputerGeneral{
				Name: "John's MacBook Pro", LastEnrolledDate: "2026-01-15T10:00:00Z", Supervised: true,
				MDMCapable: &jamf.ComputerMDMCapable{Capable: true}, RemoteManagement: &jamf.ComputerRemoteManagement{Managed: true},
				Site: site,
			},
			Hardware:        &jamf.ComputerHardware{Make: "Apple", Model: "MacBook Pro (14-inch, 2024)", ModelIdentifier: "Mac16,1", SerialNumber: "C02JAMF0001"},
			OperatingSystem: &jamf.ComputerOperatingSystem{Name: "macOS", Version: "15.4", Build: "24E248"},
			UserAndLocation: &jamf.ComputerUserAndLocation{Username: "john.appleseed", Realname: "John Appleseed", Email: "john.appleseed@example.com"},
			DiskEncryption: &jamf.ComputerDiskEncryption{
				BootPartitionEncryptionDetails: &jamf.BootPartitionEncryptionDetails{PartitionName: "Macintosh HD", PartitionFileVault2State: "ENCRYPTED"},
			},
			Security: &jamf.ComputerSecurity{SipStatus: "ENABLED", GatekeeperStatus: "APP_STORE_AND_IDENTIFIED_DEVELOPERS", FirewallEnabled: true},
		},
		{
			ID: "2", UDID: "8E3C1F4A-0002-4B6E-9C1D-000000000002",
			General: &jamf.ComputerGeneral{
				Name: "Eve's iMac", LastEnrolledDate: "2026-02-03T09:30:00Z",
				MDMCapable: &jamf.ComputerMDMCapable{Capable: true}, RemoteManagement: &jamf.ComputerRemoteManagement{Managed: true},
				Site: site,
			},
			Hardware:        &jamf.ComputerHardware{Make: "Apple", Model: "iMac (24-inch, 2024)", ModelIdentifier: "Mac16,2", SerialNumber: "C02JAMF0002"},
			OperatingSystem: &jamf.ComputerOperatingSystem{Name: "macOS", Version: "15.3", Build: "24D60"},
			UserAndLocation: &jamf.ComputerUserAndLocation{Username: "eve.miller", Realname: "Eve Miller", Email: "eve.miller@example.com"},
			DiskEncryption: &jamf.ComputerDiskEncryption{
				BootPartitionEncryptionDetails: &jamf.BootPartitionEncryptionDetails{PartitionName: "Macintosh HD", PartitionFileVault2State: "NOT_ENCRYPTED"},
			},
		},
		{
			ID: "3", UDID: "8E3C1F4A-0003-4B6E-9C1D-000000000003",
			General:         &jamf.ComputerGeneral{Name: "Lab Mac mini", Site: site},
			Hardware:        &jamf.ComputerHardware{Make: "Apple", Model: "Mac mini (2024)", ModelIdentifier: "Mac16,10", SerialNumber: "C02JAMF0003"},
			OperatingSystem: &jamf.ComputerOperatingSystem{Name: "macOS", Version: "15.4", Build: "24E248"},
			UserAndLocation: &jamf.ComputerUserAndLocation{},
		},
	}

	s.mobileDevices = []*mockMobileDevice{
		{
			MobileDevice: jamf.MobileDevice{
				ID: "1", Name: "Jane's iPhone", SerialNumber: "F2JAMF0001", UDID: "00008110-000000000001",
				Model: "iPhone 16", ModelIdentifier: "iPhone17,3", Type: "ios", Managed: true, Supervised: true,
				OSVersion: "18.4", OSBuild: "22E240", WifiMacAddress: "aa:bb:cc:00:00:01", PhoneNumber: "+15550000001",
			},
		},
		{
			MobileDevice: jamf.MobileDevice{
				ID: "2", Name: "Shared iPad", SerialNumber: "F2JAMF0002", UDID: "00008110-000000000002",
				Model: "iPad Air (M2)", ModelIdentifier: "iPad14,8", Type: "ios", Managed: true,
				OSVersion: "18.3", OSBuild: "22D63",
			},
		},
	}
	s.setMobileLocationLocked(s.mobileDevices[0], "jane.doe")
}

// ── Computers (/api/v4/computers-inventory) ─────────────────────────────────

// Doc URL: https://developer.jamf.com/jamf-pro/reference/get_v4-computers-inventory
func (s *server) handleListComputers(w http.ResponseWriter, r *http.Request) {
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
	sections := r.URL.Query()["section"]
	for _, section := range sections {
		if !slices.Contains(computerSections, section) {
			writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid section %q", section))
			return
		}
	}

	s.mu.Lock()
	total := len(s.computers)
	var results []jamf.ComputerInventory
	for _, c := range pageOf(s.computers, page, pageSize) {
		results = append(results, computerWithSections(c, sections))
	}
	s.mu.Unlock()
	if results == nil {
		results = []jamf.ComputerInventory{}
	}
	writeJSON(w, http.StatusOK, jamf.ComputersInventoryResponse{TotalCount: total, Results: results})
}

// handleComputerDetail dispatches GET and PATCH on
// /api/v4/computers-inventory-detail/{id}.
//
// Doc URLs:
//   - https://developer.jamf.com/jamf-pro/reference/get_v4-computers-inventory-detail-id
//   - https://developer.jamf.com/jamf-pro/reference/patch_v4-computers-inventory-detail-id
func (s *server) handleComputerDetail(w http.ResponseWriter, r *http.Request) {
	if !s.requireBearer(w, r) {
		return
	}
	id := pathTail(r.URL.Path, "/api/v4/computers-inventory-detail/")

	switch r.Method {
	case http.MethodGet:
		s.mu.Lock()
		c := s.findComputerLocked(id)
		var cp jamf.ComputerInventory
		if c != nil {
			cp = computerWithSections(c, computerSections)
		}
		s.mu.Unlock()
		if c == nil {
			writeJSONError(w, http.StatusNotFound, "computer not found")
			return
		}
		writeJSON(w, http.StatusOK, cp)

	case http.MethodPatch:
		s.handlePatchComputer(w, r, id)

	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handlePatchComputer applies a userAndLocation update. Only the keys present
// in the body change. Writing a username with no matching directory user
// creates that user, as Jamf does. v4 answers 204 with no body.
func (s *server) handlePatchComputer(w http.ResponseWriter, r *http.Request, id string) {
	body, ok := decodeStrictJSONBody[computerPatchBody](w, r)
	if !ok {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	c := s.findComputerLocked(id)
	if c == nil {
		writeJSONError(w, http.StatusNotFound, "computer not found")
		return
	}

	if u := body.UserAndLocation; u != nil {
		if c.UserAndLocation == nil {
			c.UserAndLocation = &jamf.ComputerUserAndLocation{}
		}
		loc := c.UserAndLocation
		for _, f := range []struct {
			src *string
			dst *string
		}{
			{u.Username, &loc.Username}, {u.Realname, &loc.Realname}, {u.Email, &loc.Email},
			{u.Position, &loc.Position}, {u.Phone, &loc.Phone}, {u.DepartmentID, &loc.DepartmentID},
			{u.BuildingID, &loc.BuildingID}, {u.Room, &loc.Room},
		} {
			if f.src != nil {
				*f.dst = *f.src
			}
		}
		if loc.Username != "" {
			s.ensureDirectoryUserLocked(loc.Username, loc.Realname, loc.Email)
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *server) findComputerLocked(id string) *jamf.ComputerInventory {
	for _, c := range s.computers {
		if c.ID == id {
			return c
		}
	}
	return nil
}

// computerWithSections returns a copy of c carrying only the requested
// sections. id and udid are always present.
func computerWithSections(c *jamf.ComputerInventory, sections []string) jamf.ComputerInventory {
	out := jamf.ComputerInventory{ID: c.ID, UDID: c.UDID}
	for _, section := range sections {
		switch section {
		case "GENERAL":
			out.General = c.General
		case "HARDWARE":
			out.Hardware = c.Hardware
		case "OPERATING_SYSTEM":
			out.OperatingSystem = c.OperatingSystem
		case "USER_AND_LOCATION":
			if c.UserAndLocation != nil {
				loc := *c.UserAndLocation
				out.UserAndLocation = &loc
			}
		case "DISK_ENCRYPTION":
			out.DiskEncryption = c.DiskEncryption
		case "SECURITY":
			out.Security = c.Security
		}
	}
	return out
}

// ── Mobile devices (/api/v2/mobile-devices) ─────────────────────────────────

// Doc URL: https://developer.jamf.com/jamf-pro/reference/get_v2-mobile-devices
func (s *server) handleListMobileDevices(w http.ResponseWriter, r *http.Request) {
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

	s.mu.Lock()
	total := len(s.mobileDevices)
	results := []jamf.MobileDevice{}
	for _, m := range pageOf(s.mobileDevices, page, pageSize) {
		results = append(results, m.MobileDevice)
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, jamf.MobileDevicesResponse{TotalCount: total, Results: results})
}

// handleMobileDevice dispatches GET /api/v2/mobile-devices/{id}/detail and
// PATCH /api/v2/mobile-devices/{id}.
//
// Doc URLs:
//   - https://developer.jamf.com/jamf-pro/reference/get_v2-mobile-devices-id-detail
//   - https://developer.jamf.com/jamf-pro/reference/patch_v2-mobile-devices-id
func (s *server) handleMobileDevice(w http.ResponseWriter, r *http.Request) {
	if !s.requireBearer(w, r) {
		return
	}
	rest := pathTail(r.URL.Path, "/api/v2/mobile-devices/")
	id, suffix, _ := strings.Cut(rest, "/")

	switch {
	case suffix == "detail" && r.Method == http.MethodGet:
		s.mu.Lock()
		m := s.findMobileDeviceLocked(id)
		var resp mobileDeviceDetailResponse
		if m != nil {
			resp = mobileDeviceDetailResponse{ID: m.ID, Name: m.Name, Location: m.location}
		}
		s.mu.Unlock()
		if m == nil {
			writeJSONError(w, http.StatusNotFound, "mobile device not found")
			return
		}
		writeJSON(w, http.StatusOK, resp)

	case suffix == "" && r.Method == http.MethodPatch:
		s.handlePatchMobileDevice(w, r, id)

	case suffix == "" || suffix == "detail":
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")

	default:
		writeJSONError(w, http.StatusNotFound, "not found")
	}
}

// handlePatchMobileDevice applies a location update. Writing location.username
// alone fills the rest of the location from the matching directory user,
// creating that user first if none exists. An empty username clears the
// whole location.
func (s *server) handlePatchMobileDevice(w http.ResponseWriter, r *http.Request, id string) {
	body, ok := decodeStrictJSONBody[mobilePatchBody](w, r)
	if !ok {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	m := s.findMobileDeviceLocked(id)
	if m == nil {
		writeJSONError(w, http.StatusNotFound, "mobile device not found")
		return
	}

	if body.Name != nil {
		m.Name = *body.Name
	}
	if loc := body.Location; loc != nil {
		if loc.Username != nil {
			s.setMobileLocationLocked(m, *loc.Username)
		}
		for _, f := range []struct {
			src *string
			dst *string
		}{
			{loc.RealName, &m.location.RealName}, {loc.EmailAddress, &m.location.EmailAddress},
			{loc.Position, &m.location.Position}, {loc.PhoneNumber, &m.location.PhoneNumber},
		} {
			if f.src != nil {
				*f.dst = *f.src
			}
		}
	}

	writeJSON(w, http.StatusOK, mobileDeviceDetailResponse{ID: m.ID, Name: m.Name, Location: m.location})
}

// setMobileLocationLocked assigns username to m and auto-populates the rest
// of the location from the directory user. Assumes the caller holds s.mu.
func (s *server) setMobileLocationLocked(m *mockMobileDevice, username string) {
	m.Username = username
	if username == "" {
		m.location = mobileLocation{}
		return
	}
	u := s.ensureDirectoryUserLocked(username, "", "")
	m.location = mobileLocation{
		Username:     username,
		RealName:     u.FullName,
		EmailAddress: u.PrimaryEmail(),
		Position:     u.Position,
		PhoneNumber:  u.PhoneNumber,
	}
}

func (s *server) findMobileDeviceLocked(id string) *mockMobileDevice {
	for _, m := range s.mobileDevices {
		if m.ID == id {
			return m
		}
	}
	return nil
}

// ensureDirectoryUserLocked returns the directory user named username,
// creating it when missing: assigning a device to an unknown username makes
// Jamf add that user to /JSSResource/users. Assumes the caller holds s.mu.
func (s *server) ensureDirectoryUserLocked(username, fullName, email string) *jamf.User {
	if u, ok := s.findUserByNameLocked(username); ok {
		return u
	}
	s.nextUserID++
	u := &jamf.User{
		BaseType: jamf.BaseType{ID: s.nextUserID, Name: username},
		FullName: fullName,
		Email:    email,
	}
	s.users[u.ID] = u
	s.userList = append(s.userList, u)
	return u
}

// ── Device helpers ──────────────────────────────────────────────────────────

// parsePaging reads the Pro API's zero-based page and page-size query
// parameters (defaults 0 and 100).
func parsePaging(w http.ResponseWriter, r *http.Request) (int, int, bool) {
	page, pageSize := 0, 100
	q := r.URL.Query()
	if v := q.Get("page"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeJSONError(w, http.StatusBadRequest, "invalid page")
			return 0, 0, false
		}
		page = n
	}
	if v := q.Get("page-size"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeJSONError(w, http.StatusBadRequest, "invalid page-size")
			return 0, 0, false
		}
		pageSize = n
	}
	return page, pageSize, true
}

func pageOf[T any](items []T, page, pageSize int) []T {
	// Compare page counts, not page*pageSize, so a huge page cannot overflow.
	if pageSize <= 0 || page >= ceilDiv(len(items), pageSize) {
		return nil
	}
	start := page * pageSize
	return items[start:min(start+pageSize, len(items))]
}

// decodeStrictJSONBody decodes a Pro API JSON body, rejecting unknown keys
// with 400 as Jamf does. On failure it writes the response and returns
// ok=false.
func decodeStrictJSONBody[T any](w http.ResponseWriter, r *http.Request) (T, bool) {
	var body T
	if ct := r.Header.Get("Content-Type"); !strings.Contains(strings.ToLower(ct), "json") {
		writeJSONError(w, http.StatusUnsupportedMediaType, fmt.Sprintf("Pro API PATCH requires a JSON body; got Content-Type %q", ct))
		return body, false
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return body, false
	}
	return body, true
}
