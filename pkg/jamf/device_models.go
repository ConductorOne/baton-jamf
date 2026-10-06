package jamf

// This file models the subset of the Jamf Pro API device-inventory payloads the
// connector consumes. Only fields that map onto the baton-sdk ManagedDeviceTrait
// (or feed its free-form profile) are declared; the Jamf responses carry many
// more fields that are intentionally omitted.

// ComputersInventoryResponse is the paginated envelope returned by
// GET /api/v4/computers-inventory.
type ComputersInventoryResponse struct {
	TotalCount int                 `json:"totalCount"`
	Results    []ComputerInventory `json:"results"`
}

// ComputerInventory is a single computer record. Each section is a pointer
// since it may be absent from a given response.
type ComputerInventory struct {
	ID              string                   `json:"id"`
	UDID            string                   `json:"udid"`
	General         *ComputerGeneral         `json:"general"`
	Hardware        *ComputerHardware        `json:"hardware"`
	OperatingSystem *ComputerOperatingSystem `json:"operatingSystem"`
	UserAndLocation *ComputerUserAndLocation `json:"userAndLocation"`
	DiskEncryption  *ComputerDiskEncryption  `json:"diskEncryption"`
	Security        *ComputerSecurity        `json:"security"`
}

// ComputerGeneral holds the GENERAL section.
type ComputerGeneral struct {
	Name             string                    `json:"name"`
	LastEnrolledDate string                    `json:"lastEnrolledDate"`
	Supervised       bool                      `json:"supervised"`
	MDMCapable       *ComputerMDMCapable       `json:"mdmCapable"`
	RemoteManagement *ComputerRemoteManagement `json:"remoteManagement"`
	Site             *NamedRef                 `json:"site"`
}

// ComputerMDMCapable reports whether the device can be managed via MDM.
type ComputerMDMCapable struct {
	Capable bool `json:"capable"`
}

// ComputerRemoteManagement reports whether the device is currently managed.
type ComputerRemoteManagement struct {
	Managed bool `json:"managed"`
}

// ComputerHardware holds the HARDWARE section.
type ComputerHardware struct {
	Make            string `json:"make"`
	Model           string `json:"model"`
	ModelIdentifier string `json:"modelIdentifier"`
	SerialNumber    string `json:"serialNumber"`
}

// ComputerOperatingSystem holds the OPERATING_SYSTEM section.
type ComputerOperatingSystem struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Build   string `json:"build"`
}

// ComputerUserAndLocation holds the USER_AND_LOCATION section. v4 only
// returns `email`; EmailAddress has no v4 key but is kept for EmailAddr's
// fallback.
type ComputerUserAndLocation struct {
	Username     string `json:"username"`
	Realname     string `json:"realname"`
	Email        string `json:"email"`
	EmailAddress string `json:"emailAddress"`
	Position     string `json:"position"`
	Phone        string `json:"phone"`
	DepartmentID string `json:"departmentId"`
	BuildingID   string `json:"buildingId"`
	Room         string `json:"room"`
}

// EmailAddr returns whichever email field Jamf populated.
func (u *ComputerUserAndLocation) EmailAddr() string {
	if u == nil {
		return ""
	}
	if u.Email != "" {
		return u.Email
	}
	return u.EmailAddress
}

// ComputerDiskEncryption holds the DISK_ENCRYPTION section.
type ComputerDiskEncryption struct {
	BootPartitionEncryptionDetails *BootPartitionEncryptionDetails `json:"bootPartitionEncryptionDetails"`
}

// BootPartitionEncryptionDetails reports the FileVault 2 state of the boot
// partition. partitionFileVault2State is an enum string
// (e.g. ENCRYPTED / NOT_ENCRYPTED / DECRYPTED / ...).
type BootPartitionEncryptionDetails struct {
	PartitionName            string `json:"partitionName"`
	PartitionFileVault2State string `json:"partitionFileVault2State"`
}

// ComputerSecurity holds the SECURITY section.
type ComputerSecurity struct {
	SipStatus             string `json:"sipStatus"`
	GatekeeperStatus      string `json:"gatekeeperStatus"`
	ActivationLockEnabled bool   `json:"activationLockEnabled"`
	RecoveryLockEnabled   bool   `json:"recoveryLockEnabled"`
	FirewallEnabled       bool   `json:"firewallEnabled"`
	SecureBootLevel       string `json:"secureBootLevel"`
	ExternalBootLevel     string `json:"externalBootLevel"`
}

// NamedRef is a generic {id,name} reference used by several Jamf sections.
type NamedRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// MobileDevicesResponse is the paginated envelope returned by
// GET /api/v2/mobile-devices.
type MobileDevicesResponse struct {
	TotalCount int            `json:"totalCount"`
	Results    []MobileDevice `json:"results"`
}

// MobileDevice is a single mobile-device record from the v2 list endpoint.
// The list endpoint returns a flat, limited field set (the per-device detail
// endpoint carries more); only the flat fields are modeled here.
type MobileDevice struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	SerialNumber    string `json:"serialNumber"`
	UDID            string `json:"udid"`
	Model           string `json:"model"`
	ModelIdentifier string `json:"modelIdentifier"`
	Username        string `json:"username"`
	Type            string `json:"type"`
	Managed         bool   `json:"managed"`
	Supervised      bool   `json:"supervised"`
	OSVersion       string `json:"osVersion"`
	OSBuild         string `json:"osBuild"`
	WifiMacAddress  string `json:"wifiMacAddress"`
	PhoneNumber     string `json:"phoneNumber"`
}

// MobileDeviceDetail is a single mobile-device record from the v2 detail
// endpoint. Only the location section needed to resolve the device's
// current assignee is modeled here.
type MobileDeviceDetail struct {
	ID       string                      `json:"id"`
	Location *MobileDeviceDetailLocation `json:"location"`
}

// MobileDeviceDetailLocation holds the `location` section of a mobile-device
// detail record.
type MobileDeviceDetailLocation struct {
	Username string `json:"username"`
}

// ComputerAssignedUserUpdate is the PATCH body for
// /api/v4/computers-inventory-detail/{id} that sets (Grant) or clears
// (Revoke) the assigned user's identity via userAndLocation.
type ComputerAssignedUserUpdate struct {
	UserAndLocation ComputerAssignedUserFields `json:"userAndLocation"`
}

// ComputerAssignedUserFields is the assignee-identity subset of a computer's
// userAndLocation that Grant/Revoke write: username, realname, email,
// position and phone. "" clears a field, an omitted key is a no-op, and the
// keys are independent, so all five are always sent as plain strings (no
// `omitempty`). Grant populates every field from the new assignee's Jamf
// user record, overwriting whatever the previous assignee left behind since
// Jamf never auto-populates these for computers; Revoke sends the zero
// value of this struct to clear all five.
type ComputerAssignedUserFields struct {
	Username string `json:"username"`
	Realname string `json:"realname"`
	Email    string `json:"email"`
	Position string `json:"position"`
	Phone    string `json:"phone"`
}

// MobileDeviceAssignedUserUpdate is the PATCH body for
// /api/v2/mobile-devices/{id} that sets (Grant) or clears (Revoke) the
// assigned user via location.username.
type MobileDeviceAssignedUserUpdate struct {
	Location MobileDeviceAssignedUserUpdateLocation `json:"location"`
}

// MobileDeviceAssignedUserUpdateLocation carries only username: setting it
// makes Jamf auto-populate realname/email/position/phone from the directory
// user, and a nonexistent username is accepted by auto-creating a directory
// user, so the connector never has (or needs) those fields to send here. ""
// clears the username and every auto-populated field together; null/{} are
// silent no-ops, so Revoke must always send an explicit "" rather than
// omitting the field.
type MobileDeviceAssignedUserUpdateLocation struct {
	Username string `json:"username"`
}
