package jamf

import (
	"encoding/xml"
	"slices"
)

type BaseType struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// User - end user in Jamf.
type User struct {
	BaseType
	FullName     string `json:"full_name"`
	Email        string `json:"email"`
	EmailAddress string `json:"email_address"`
	Username     string `json:"username"`
	Sites        []struct {
		Site BaseType `json:"site"`
	} `json:"sites"`
}

type BaseAccount struct {
	Users  []User  `json:"users"`
	Groups []Group `json:"groups"`
}

// UserAccount - user that has access to their system and can be granted permissions.
type UserAccount struct {
	BaseType
	FullName     string     `json:"full_name"`
	Email        string     `json:"email"`
	EmailAddress string     `json:"email_address"`
	Enabled      string     `json:"enabled"`
	AccessLevel  string     `json:"access_level"`
	PrivilegeSet string     `json:"privilege_set"`
	Privileges   Privileges `json:"privileges"`
	Site         BaseType   `json:"site"`
}

// Privileges models the Classic API's <privileges> block, which gives a
// Custom privilege_set its actual meaning. Each category is a list of
// privilege names. See
// https://developer.jamf.com/jamf-pro/reference/createaccountbyid and
// https://developer.jamf.com/jamf-pro/reference/findaccountsbyid.
type Privileges struct {
	JSSObjects    []string `json:"jss_objects" xml:"jss_objects>privilege,omitempty"`
	JSSSettings   []string `json:"jss_settings" xml:"jss_settings>privilege,omitempty"`
	JSSActions    []string `json:"jss_actions" xml:"jss_actions>privilege,omitempty"`
	Recon         []string `json:"recon" xml:"recon>privilege,omitempty"`
	CasperAdmin   []string `json:"casper_admin" xml:"casper_admin>privilege,omitempty"`
	CasperRemote  []string `json:"casper_remote" xml:"casper_remote>privilege,omitempty"`
	CasperImaging []string `json:"casper_imaging" xml:"casper_imaging>privilege,omitempty"`
}

// IsEmpty reports whether every privilege category is empty — i.e. this
// Privileges value grants nothing.
func (p *Privileges) IsEmpty() bool {
	if p == nil {
		return true
	}
	return len(p.JSSObjects) == 0 &&
		len(p.JSSSettings) == 0 &&
		len(p.JSSActions) == 0 &&
		len(p.Recon) == 0 &&
		len(p.CasperAdmin) == 0 &&
		len(p.CasperRemote) == 0 &&
		len(p.CasperImaging) == 0
}

// Contains reports whether privilege appears in any of p's 7 categories.
func (p *Privileges) Contains(privilege string) bool {
	if p == nil {
		return false
	}
	return slices.Contains(p.JSSObjects, privilege) ||
		slices.Contains(p.JSSSettings, privilege) ||
		slices.Contains(p.JSSActions, privilege) ||
		slices.Contains(p.Recon, privilege) ||
		slices.Contains(p.CasperAdmin, privilege) ||
		slices.Contains(p.CasperRemote, privilege) ||
		slices.Contains(p.CasperImaging, privilege)
}

// MarshalXML emits only the privilege categories that are populated.
// encoding/xml's built-in "omitempty" does not apply to a nil/empty slice
// nested behind a ">"-chained struct tag (e.g. "jss_objects>privilege") — it
// always emits the empty wrapper element regardless. This method replaces
// that reflection-based encoding for the write path so an unset category is
// actually omitted from the XML sent to Jamf, rather than sent as
// "<jss_settings></jss_settings>". The struct field xml tags remain in place
// for decoding (test-server's XML unmarshal still uses them).
func (p Privileges) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	if err := e.EncodeToken(start); err != nil {
		return err
	}
	categories := []struct {
		name  string
		items []string
	}{
		{"jss_objects", p.JSSObjects},
		{"jss_settings", p.JSSSettings},
		{"jss_actions", p.JSSActions},
		{"recon", p.Recon},
		{"casper_admin", p.CasperAdmin},
		{"casper_remote", p.CasperRemote},
		{"casper_imaging", p.CasperImaging},
	}
	for _, c := range categories {
		if len(c.items) == 0 {
			continue
		}
		element := struct {
			Items []string `xml:"privilege"`
		}{Items: c.items}
		if err := e.EncodeElement(element, xml.StartElement{Name: xml.Name{Local: c.name}}); err != nil {
			return err
		}
	}
	return e.EncodeToken(start.End())
}

type Group struct {
	BaseType
	AccessLevel string `json:"access_level"`
	// PrivilegeSet can take the following values:
	//
	//	- "Administrator"
	//
	//	- "Auditor"
	//
	//	- "Enrollment Only"
	//
	//	- "Custom"
	PrivilegeSet string     `json:"privilege_set"`
	Privileges   Privileges `json:"privileges"`
	Site         BaseType   `json:"site"`
	Members      []BaseType `json:"members"`
}

type Site struct {
	BaseType
}

type UserGroup struct {
	BaseType
	IsSmart bool   `json:"is_smart"`
	Site    Site   `json:"site"`
	Users   []User `json:"users"`
}

type TokenDetails struct {
	Account Account `json:"account"`
	Sites   []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"sites"`
	AuthenticationType string `json:"authenticationType"`
}

type Account struct {
	ID             string `json:"id"`
	Username       string `json:"username"`
	RealName       string `json:"realName"`
	Email          string `json:"email"`
	MultiSiteAdmin bool   `json:"multiSiteAdmin"`
	AccessLevel    string `json:"accessLevel"`
	PrivilegeSet   string `json:"privilegeSet"`
	CurrentSiteID  string `json:"currentSiteId"`
}

type TokenResponse struct {
	Token   string `json:"token"`
	Expires string `json:"expires"`
}

type UsersResponse struct {
	Users []BaseType `json:"users"`
}

type UserResponse struct {
	User User `json:"user"`
}

type UserAccountResponse struct {
	UserAccount UserAccount `json:"account"`
}

// UserCreateBody is the XML request body for POST /JSSResource/users/id/0.
// The Classic API only accepts XML for POST/PUT requests (JSON is GET-only),
// so this is marshaled with encoding/xml, not encoding/json.
type UserCreateBody struct {
	XMLName  xml.Name `xml:"user"`
	Name     string   `xml:"name"`
	FullName string   `xml:"full_name,omitempty"`
	Email    string   `xml:"email,omitempty"`
}

// UserAccountCreateBody is the XML request body for POST /JSSResource/accounts/userid/0.
// The Classic API only accepts XML for POST/PUT requests (JSON is GET-only),
// so this is marshaled with encoding/xml, not encoding/json.
type UserAccountCreateBody struct {
	XMLName      xml.Name `xml:"account"`
	Name         string   `xml:"name"`
	Password     string   `xml:"password"`
	FullName     string   `xml:"full_name,omitempty"`
	Email        string   `xml:"email,omitempty"`
	Enabled      string   `xml:"enabled,omitempty"`
	AccessLevel  string   `xml:"access_level,omitempty"`
	PrivilegeSet string   `xml:"privilege_set,omitempty"`
	// Privileges is only meaningful (and should only be set) when
	// PrivilegeSet is "Custom" — a pointer so the whole <privileges> element
	// is omitted otherwise.
	Privileges *Privileges `xml:"privileges,omitempty"`
}

type UserGroupsResponse struct {
	UserGroups []UserGroup `json:"user_groups"`
}

type UserGroupResponse struct {
	UserGroup UserGroup `json:"user_group"`
}

type GroupResponse struct {
	Group Group `json:"group"`
}

type AccountsResponse struct {
	Accounts BaseAccount `json:"accounts"`
}

type SitesResponse struct {
	Sites []Site `json:"sites"`
}

type PrivilegesResponse struct {
	Privileges []string `json:"privileges"`
}
