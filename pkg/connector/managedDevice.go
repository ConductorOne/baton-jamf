package connector

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/structpb"

	"github.com/conductorone/baton-jamf/pkg/jamf"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
)

const (
	// Sync phases, tracked in the pagination bag so the single ManagedDevice
	// resource type can walk two Jamf endpoints (computers, then mobile devices)
	// across many paginated List calls.
	devicePhaseComputer = "computer"
	devicePhaseMobile   = "mobile"

	// defaultDevicePageSize is used when the SDK does not supply a page size.
	defaultDevicePageSize = 100
)

type managedDeviceResourceType struct {
	resourceType *v2.ResourceType
	client       *jamf.Client

	// userIndex maps lowercased username / email keys to the ResourceId of the
	// synced Jamf user resource, so devices can cross-link their assigned owner.
	// It is built lazily once per sync and cached.
	mu        sync.Mutex
	userIndex map[string]*v2.ResourceId
}

func (d *managedDeviceResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return d.resourceType
}

func (d *managedDeviceResourceType) List(ctx context.Context, parentId *v2.ResourceId, attrs rs.SyncOpAttrs) ([]*v2.Resource, *rs.SyncOpResults, error) {
	bag := &pagination.Bag{}
	if err := bag.Unmarshal(attrs.PageToken.Token); err != nil {
		return nil, nil, fmt.Errorf("jamf-connector: failed to parse device page token: %w", err)
	}
	if bag.Current() == nil {
		bag.Push(pagination.PageState{ResourceTypeID: devicePhaseComputer, Token: "0"})
	}

	pageSize := attrs.PageToken.Size
	if pageSize <= 0 {
		pageSize = defaultDevicePageSize
	}

	userIndex, err := d.getUserIndex(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("jamf-connector: failed to build user index for device owner resolution: %w", err)
	}

	current := bag.Current()
	page, err := strconv.Atoi(current.Token)
	if err != nil {
		page = 0
	}

	var resources []*v2.Resource

	switch current.ResourceTypeID {
	case devicePhaseComputer:
		resp, err := d.client.GetComputersInventory(ctx, page, pageSize, jamf.ComputerInventorySections)
		if err != nil {
			return nil, nil, fmt.Errorf("jamf-connector: failed to list computers inventory: %w", err)
		}
		for i := range resp.Results {
			r, err := computerResource(&resp.Results[i], userIndex, parentId)
			if err != nil {
				return nil, nil, fmt.Errorf("jamf-connector: failed to build computer resource: %w", err)
			}
			resources = append(resources, r)
		}
		if hasMorePages(page, pageSize, resp.TotalCount, len(resp.Results)) {
			if err := bag.Next(strconv.Itoa(page + 1)); err != nil {
				return nil, nil, err
			}
		} else {
			// Computers exhausted; advance to the mobile-device phase.
			bag.Pop()
			bag.Push(pagination.PageState{ResourceTypeID: devicePhaseMobile, Token: "0"})
		}

	case devicePhaseMobile:
		resp, err := d.client.GetMobileDevices(ctx, page, pageSize)
		if err != nil {
			return nil, nil, fmt.Errorf("jamf-connector: failed to list mobile devices: %w", err)
		}
		for i := range resp.Results {
			r, err := mobileDeviceResource(&resp.Results[i], userIndex, parentId)
			if err != nil {
				return nil, nil, fmt.Errorf("jamf-connector: failed to build mobile device resource: %w", err)
			}
			resources = append(resources, r)
		}
		if hasMorePages(page, pageSize, resp.TotalCount, len(resp.Results)) {
			if err := bag.Next(strconv.Itoa(page + 1)); err != nil {
				return nil, nil, err
			}
		} else {
			// Both phases exhausted; popping the last state ends the sync.
			bag.Pop()
		}

	default:
		return nil, nil, fmt.Errorf("jamf-connector: unknown device sync phase %q", current.ResourceTypeID)
	}

	nextToken, err := bag.Marshal()
	if err != nil {
		return nil, nil, err
	}

	return resources, &rs.SyncOpResults{NextPageToken: nextToken}, nil
}

func (d *managedDeviceResourceType) Entitlements(_ context.Context, _ *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	return nil, nil, nil
}

func (d *managedDeviceResourceType) Grants(_ context.Context, _ *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	return nil, nil, nil
}

func managedDeviceBuilder(client *jamf.Client) *managedDeviceResourceType {
	return &managedDeviceResourceType{
		resourceType: resourceTypeManagedDevice,
		client:       client,
	}
}

// getUserIndex lazily builds (and caches) the username/email -> user ResourceId
// lookup used to cross-link a device to its assigned owner. On error nothing is
// cached, so a subsequent call retries.
func (d *managedDeviceResourceType) getUserIndex(ctx context.Context) (map[string]*v2.ResourceId, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.userIndex != nil {
		return d.userIndex, nil
	}

	users, err := d.client.GetUsers(ctx)
	if err != nil {
		return nil, err
	}

	idx := make(map[string]*v2.ResourceId, len(users))
	for _, u := range users {
		if u == nil {
			continue
		}
		rid := &v2.ResourceId{}
		rid.SetResourceType(resourceTypeUser.Id)
		rid.SetResource(strconv.Itoa(u.ID))

		for _, key := range []string{u.Name, u.Username, u.Email, u.EmailAddress} {
			key = strings.ToLower(strings.TrimSpace(key))
			if key == "" {
				continue
			}
			// First writer wins so a stable user keeps the key on collisions.
			if _, exists := idx[key]; !exists {
				idx[key] = rid
			}
		}
	}

	d.userIndex = idx
	return d.userIndex, nil
}

// computerResource maps a Jamf computer-inventory record onto a ManagedDevice
// resource carrying a ManagedDeviceTrait.
func computerResource(c *jamf.ComputerInventory, userIndex map[string]*v2.ResourceId, parentResourceID *v2.ResourceId) (*v2.Resource, error) {
	var opts []rs.ManagedDeviceTraitOption
	profile := map[string]interface{}{}

	name := c.ID
	if c.General != nil && c.General.Name != "" {
		name = c.General.Name
	}

	if c.Hardware != nil && c.Hardware.SerialNumber != "" {
		opts = append(opts, rs.WithManagedDeviceSerial(c.Hardware.SerialNumber))
	}
	if c.UDID != "" {
		opts = append(opts, rs.WithManagedDeviceUDID(c.UDID))
	}

	if dt, ok := computerDeviceType(c.Hardware); ok {
		opts = append(opts, rs.WithManagedDeviceType(dt))
	}

	if c.Hardware != nil {
		if model := computerModel(c.Hardware); model != "" {
			opts = append(opts, rs.WithManagedDeviceModel(model))
		}
		if c.Hardware.Make != "" {
			opts = append(opts, rs.WithManagedDeviceVendor(c.Hardware.Make))
		}
	}

	if os := computerOS(c.OperatingSystem); os != nil {
		opts = append(opts, rs.WithManagedDeviceOS(os))
	}

	if c.UserAndLocation != nil {
		if rid, ok := resolveUser(userIndex, c.UserAndLocation.Username, c.UserAndLocation.EmailAddr()); ok {
			opts = append(opts, rs.WithManagedDeviceAssignedUser(rid))
		} else if raw := unresolvedOwner(c.UserAndLocation.Username, c.UserAndLocation.EmailAddr()); raw != "" {
			profile["unresolved_owner"] = raw
		}
	}

	if enc, ok := isEncrypted(c.DiskEncryption); ok {
		opts = append(opts, rs.WithManagedDeviceEncrypted(enc))
	}

	if c.General != nil {
		opts = append(opts, rs.WithManagedDeviceSupervised(c.General.Supervised))
	}

	if managementStateManaged(c.General) {
		opts = append(opts, rs.WithManagedDeviceManagementState(v2.ManagedDeviceTrait_MANAGEMENT_STATE_MANAGED))
	}

	if c.General != nil {
		if t, ok := parseJamfTime(c.General.LastEnrolledDate); ok {
			opts = append(opts, rs.WithManagedDeviceEnrolledAt(t))
		}
	}

	addComputerProfile(profile, c)

	if len(profile) > 0 {
		pb, err := structpb.NewStruct(profile)
		if err != nil {
			return nil, err
		}
		opts = append(opts, rs.WithManagedDeviceProfile(pb))
	}

	return rs.NewManagedDeviceResource(
		name,
		resourceTypeManagedDevice,
		deviceObjectID(devicePhaseComputer, c.ID),
		opts,
		rs.WithParentResourceID(parentResourceID),
	)
}

// mobileDeviceResource maps a Jamf mobile-device record onto a ManagedDevice
// resource. The v2 list endpoint exposes a flatter field set than the computers
// inventory, so fewer trait fields are populated.
func mobileDeviceResource(m *jamf.MobileDevice, userIndex map[string]*v2.ResourceId, parentResourceID *v2.ResourceId) (*v2.Resource, error) {
	var opts []rs.ManagedDeviceTraitOption
	profile := map[string]interface{}{}

	name := m.Name
	if name == "" {
		name = m.ID
	}

	if m.SerialNumber != "" {
		opts = append(opts, rs.WithManagedDeviceSerial(m.SerialNumber))
	}
	if m.UDID != "" {
		opts = append(opts, rs.WithManagedDeviceUDID(m.UDID))
	}

	if dt, ok := mobileDeviceType(m); ok {
		opts = append(opts, rs.WithManagedDeviceType(dt))
	}

	if model := mobileModel(m); model != "" {
		opts = append(opts, rs.WithManagedDeviceModel(model))
	}

	if os := mobileOS(m); os != nil {
		opts = append(opts, rs.WithManagedDeviceOS(os))
	}

	if rid, ok := resolveUser(userIndex, m.Username, ""); ok {
		opts = append(opts, rs.WithManagedDeviceAssignedUser(rid))
	} else if m.Username != "" {
		profile["unresolved_owner"] = m.Username
	}

	opts = append(opts, rs.WithManagedDeviceSupervised(m.Supervised))

	if m.Managed {
		opts = append(opts, rs.WithManagedDeviceManagementState(v2.ManagedDeviceTrait_MANAGEMENT_STATE_MANAGED))
	}

	setIfNotEmpty(profile, "phone_number", m.PhoneNumber)
	setIfNotEmpty(profile, "wifi_mac_address", m.WifiMacAddress)

	if len(profile) > 0 {
		pb, err := structpb.NewStruct(profile)
		if err != nil {
			return nil, err
		}
		opts = append(opts, rs.WithManagedDeviceProfile(pb))
	}

	return rs.NewManagedDeviceResource(
		name,
		resourceTypeManagedDevice,
		deviceObjectID(devicePhaseMobile, m.ID),
		opts,
		rs.WithParentResourceID(parentResourceID),
	)
}

// deviceObjectID namespaces device IDs by source so a computer and a mobile
// device that happen to share a numeric ID do not collide.
func deviceObjectID(phase, id string) string {
	return fmt.Sprintf("%s:%s", phase, id)
}

// hasMorePages reports whether another page should be fetched. It relies on the
// API's totalCount when present, and otherwise falls back to "a full page means
// there is probably more".
func hasMorePages(page, pageSize, totalCount, gotThisPage int) bool {
	if gotThisPage == 0 {
		return false
	}
	if totalCount > 0 {
		return (page+1)*pageSize < totalCount
	}
	return gotThisPage >= pageSize
}

// computerDeviceType derives LAPTOP vs DESKTOP from the Apple model identifier.
// Every Mac is one or the other, so once a model string exists the only
// ambiguity is laptop vs desktop, which "book" (MacBook / MacBook Pro / Air)
// resolves cleanly.
func computerDeviceType(hw *jamf.ComputerHardware) (v2.ManagedDeviceTrait_DeviceType, bool) {
	if hw == nil {
		return 0, false
	}
	id := strings.ToLower(hw.ModelIdentifier)
	if id == "" {
		id = strings.ToLower(hw.Model)
	}
	if id == "" {
		return 0, false
	}
	if strings.Contains(id, "book") {
		return v2.ManagedDeviceTrait_DEVICE_TYPE_LAPTOP, true
	}
	return v2.ManagedDeviceTrait_DEVICE_TYPE_DESKTOP, true
}

// computerModel prefers the human-friendly model name, falling back to the
// model identifier.
func computerModel(hw *jamf.ComputerHardware) string {
	if hw.Model != "" {
		return hw.Model
	}
	return hw.ModelIdentifier
}

// computerOS builds a DeviceOS from the operating-system section. Returns nil
// when there is nothing to report.
func computerOS(os *jamf.ComputerOperatingSystem) *v2.DeviceOS {
	if os == nil {
		return nil
	}
	if os.Name == "" && os.Version == "" && os.Build == "" {
		return nil
	}
	d := &v2.DeviceOS{}
	if t, ok := osTypeFromName(os.Name); ok {
		d.SetType(t)
	}
	if os.Name != "" {
		d.SetName(os.Name)
	}
	if os.Version != "" {
		d.SetVersion(os.Version)
	}
	if os.Build != "" {
		d.SetBuild_(os.Build)
	}
	return d
}

// osTypeFromName maps a Jamf OS name string onto a DeviceOS_OsType. Unknown
// names leave the type unset rather than guessing.
func osTypeFromName(name string) (v2.DeviceOS_OsType, bool) {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "ipados"):
		return v2.DeviceOS_OS_TYPE_IPADOS, true
	case strings.Contains(n, "ios"):
		return v2.DeviceOS_OS_TYPE_IOS, true
	case strings.Contains(n, "mac"): // "macOS", "Mac OS X"
		return v2.DeviceOS_OS_TYPE_MACOS, true
	}
	return 0, false
}

// isEncrypted derives a tri-state disk-encryption flag from the boot partition
// FileVault 2 state. Only definitive states assert a value; transitional or
// unknown states leave it unset.
func isEncrypted(de *jamf.ComputerDiskEncryption) (bool, bool) {
	if de == nil || de.BootPartitionEncryptionDetails == nil {
		return false, false
	}
	switch strings.ToUpper(strings.TrimSpace(de.BootPartitionEncryptionDetails.PartitionFileVault2State)) {
	case "ENCRYPTED", "VALID":
		return true, true
	case "NOT_ENCRYPTED", "DECRYPTED":
		return false, true
	default:
		return false, false
	}
}

// managementStateManaged reports whether a computer should be considered MANAGED:
// it must be MDM-capable and actively remotely managed.
func managementStateManaged(g *jamf.ComputerGeneral) bool {
	if g == nil {
		return false
	}
	mdm := g.MDMCapable != nil && g.MDMCapable.Capable
	remote := g.RemoteManagement != nil && g.RemoteManagement.Managed
	return mdm && remote
}

// addComputerProfile fills the free-form profile with the long-tail fields that
// have no dedicated trait slot.
func addComputerProfile(profile map[string]interface{}, c *jamf.ComputerInventory) {
	if c.General != nil && c.General.Site != nil && c.General.Site.Name != "" {
		profile["site"] = c.General.Site.Name
	}
	if ul := c.UserAndLocation; ul != nil {
		setIfNotEmpty(profile, "building_id", ul.BuildingID)
		setIfNotEmpty(profile, "department_id", ul.DepartmentID)
		setIfNotEmpty(profile, "room", ul.Room)
		setIfNotEmpty(profile, "position", ul.Position)
	}
	if s := c.Security; s != nil {
		profile["activation_lock_enabled"] = s.ActivationLockEnabled
		profile["recovery_lock_enabled"] = s.RecoveryLockEnabled
		profile["firewall_enabled"] = s.FirewallEnabled
		setIfNotEmpty(profile, "sip_status", s.SipStatus)
		setIfNotEmpty(profile, "gatekeeper_status", s.GatekeeperStatus)
		setIfNotEmpty(profile, "secure_boot_level", s.SecureBootLevel)
	}
}

// mobileDeviceType derives the device form factor for a mobile device. iPads map
// to TABLET; iPhones and other iOS devices map to MOBILE.
func mobileDeviceType(m *jamf.MobileDevice) (v2.ManagedDeviceTrait_DeviceType, bool) {
	id := strings.ToLower(strings.Join([]string{m.ModelIdentifier, m.Model, m.Type}, " "))
	switch {
	case strings.Contains(id, "ipad"):
		return v2.ManagedDeviceTrait_DEVICE_TYPE_TABLET, true
	case strings.Contains(id, "iphone"), strings.Contains(id, "ios"):
		return v2.ManagedDeviceTrait_DEVICE_TYPE_MOBILE, true
	}
	return 0, false
}

// mobileModel prefers the model name, falling back to the model identifier.
func mobileModel(m *jamf.MobileDevice) string {
	if m.Model != "" {
		return m.Model
	}
	return m.ModelIdentifier
}

// mobileOS builds a DeviceOS for a mobile device from the type / model hints and
// the reported OS version/build.
func mobileOS(m *jamf.MobileDevice) *v2.DeviceOS {
	d := &v2.DeviceOS{}
	id := strings.ToLower(strings.Join([]string{m.ModelIdentifier, m.Model}, " "))
	switch {
	case strings.Contains(id, "ipad"):
		d.SetType(v2.DeviceOS_OS_TYPE_IPADOS)
		d.SetName("iPadOS")
	case strings.Contains(id, "iphone"), strings.Contains(strings.ToLower(m.Type), "ios"):
		d.SetType(v2.DeviceOS_OS_TYPE_IOS)
		d.SetName("iOS")
	}
	if m.OSVersion != "" {
		d.SetVersion(m.OSVersion)
	}
	if m.OSBuild != "" {
		d.SetBuild_(m.OSBuild)
	}
	if d.GetType() == v2.DeviceOS_OS_TYPE_UNSPECIFIED && d.GetName() == "" && d.GetVersion() == "" && d.GetBuild_() == "" {
		return nil
	}
	return d
}

// resolveUser looks up a synced user ResourceId by username then email.
func resolveUser(idx map[string]*v2.ResourceId, username, email string) (*v2.ResourceId, bool) {
	for _, key := range []string{username, email} {
		key = strings.ToLower(strings.TrimSpace(key))
		if key == "" {
			continue
		}
		if rid, ok := idx[key]; ok {
			return rid, true
		}
	}
	return nil, false
}

// unresolvedOwner returns the raw owner value to stash when it cannot be
// resolved to a synced user, preferring the username.
func unresolvedOwner(username, email string) string {
	if strings.TrimSpace(username) != "" {
		return username
	}
	return email
}

// setIfNotEmpty adds a string value to the profile only when non-empty.
func setIfNotEmpty(profile map[string]interface{}, key, value string) {
	if value != "" {
		profile[key] = value
	}
}

// parseJamfTime parses the ISO-8601 timestamps Jamf returns. Returns ok=false
// on empty or unparseable input so callers leave the field unset.
func parseJamfTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.000-0700",
		"2006-01-02T15:04:05-0700",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
