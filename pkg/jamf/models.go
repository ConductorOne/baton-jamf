package jamf

import (
	"encoding/json"
	"encoding/xml"
	"slices"
)

type BaseType struct {
	ID   int    `json:"id" xml:"id"`
	Name string `json:"name" xml:"name,omitempty"`
}

// User - end user in Jamf.
type User struct {
	BaseType
	FullName     string `json:"full_name"`
	Email        string `json:"email"`
	EmailAddress string `json:"email_address"`
	Username     string `json:"username"`
	Position     string `json:"position"`
	// PhoneNumber is the Classic API's key for this field (findusersbyid) -
	// not "phone", which is the unrelated key Jamf uses for a computer's
	// userAndLocation.phone.
	PhoneNumber string    `json:"phone_number"`
	Sites       UserSites `json:"sites"`
}

// LoginName returns the account's login identifier: Username when set,
// falling back to Name.
func (u *User) LoginName() string {
	if u.Username != "" {
		return u.Username
	}
	return u.Name
}

// PrimaryEmail returns the account's email: Email when set, falling back to
// EmailAddress.
func (u *User) PrimaryEmail() string {
	if u.Email != "" {
		return u.Email
	}
	return u.EmailAddress
}

// UserSites is the decoded form of a Jamf user's <sites> list. A live Jamf
// Pro 11.32.1 tenant returns this as a flat list, each entry's id/name at the
// top level (e.g. {"id":5,"name":"Site A"}), while the Classic API's
// documented shape wraps each entry under a "site" key (e.g.
// {"site":{"id":5,"name":"Site A"}}). UnmarshalJSON accepts both so a site's
// real id is always decoded, regardless of which shape the tenant serves.
type UserSites []BaseType

func (s *UserSites) UnmarshalJSON(data []byte) error {
	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	sites := make(UserSites, 0, len(raw))
	for _, item := range raw {
		var entry struct {
			BaseType
			Site *BaseType `json:"site"`
		}
		if err := json.Unmarshal(item, &entry); err != nil {
			return err
		}
		if entry.Site != nil {
			sites = append(sites, *entry.Site)
		} else {
			sites = append(sites, entry.BaseType)
		}
	}

	*s = sites
	return nil
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
// privilege names.
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

// Map returns a copy of p with fn applied to each of its 7 categories.
func (p Privileges) Map(fn func([]string) []string) Privileges {
	return Privileges{
		JSSObjects:    fn(p.JSSObjects),
		JSSSettings:   fn(p.JSSSettings),
		JSSActions:    fn(p.JSSActions),
		Recon:         fn(p.Recon),
		CasperAdmin:   fn(p.CasperAdmin),
		CasperRemote:  fn(p.CasperRemote),
		CasperImaging: fn(p.CasperImaging),
	}
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
// that encoding on the write path so an unset category is omitted rather
// than sent as "<jss_settings></jss_settings>"; the struct's xml tags remain
// for decoding (test-server still uses them).
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

// privilegesUpdateBody is the minimal XML PUT body for
// /JSSResource/accounts/userid/{id} and /JSSResource/accounts/groupid/{id}
// used by Role Grant/Revoke to change an account's or group's
// privilege_set/privileges without touching anything else — XMLName is set
// at runtime to "account" or "group" by the caller. Jamf's field-level merge
// means there is no need to round-trip full_name/email/enabled/access_level
// (or, for a group, members/site). Password and Site are deliberately
// absent — Password because Jamf never returns it on GET so it can't be
// preserved, and Site because Jamf rejects a zero site ID with 409 and there
// is no legitimate non-zero value worth risking here. Deliberately has no
// Members field either: Role Grant/Revoke must never send <members> for a
// group, since that element is exactly what group.go's Grant/Revoke (a
// different entitlement entirely) uses to manage membership, and omitting
// it here preserves whatever membership the group currently has.
//
// Privileges is a pointer so an explicit, possibly-empty
// <privileges></privileges> can be forced: a nil pointer omits the element
// entirely (leaving Jamf's stored privileges untouched), while a non-nil
// pointer — even one wrapping an all-empty Privileges — still emits the
// wrapper element. This is required whenever privilege_set is written as
// Custom: sending Custom without an explicit block copies the account's
// previous set's entire expanded privilege list into it.
type privilegesUpdateBody struct {
	XMLName      xml.Name
	Name         string      `xml:"name"`
	PrivilegeSet string      `xml:"privilege_set,omitempty"`
	Privileges   *Privileges `xml:"privileges,omitempty"`
}

// GroupMembersUpdateBody is the minimal XML PUT body for
// /JSSResource/accounts/groupid/{id} used for membership-only changes (see
// Client.UpdateGroupMembers). It carries only name and members:
// access_level, privilege_set and site are left untouched when omitted, so
// they are deliberately not fields on this type at all. Resending a zero
// site would make Jamf reject the request with a 409, so site is never sent
// here.
//
// Members is a pointer so an explicit empty <members></members> can be
// forced when the last member is being removed: a nil slice under
// `xml:"members>user"` would omit the element entirely, which Jamf
// interprets as "leave members unchanged" rather than "clear members".
type GroupMembersUpdateBody struct {
	XMLName xml.Name     `xml:"group"`
	Name    string       `xml:"name"`
	Members *memberUsers `xml:"members"`
}

// memberUsers is the shared `{Users []BaseType \`xml:"user"\`}` shape used
// for a <members>/<user_additions>/<user_deletions> element — the wrapping
// element name comes from the containing field's own xml tag, not from this
// type.
type memberUsers struct {
	Users []BaseType `xml:"user"`
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

// UserGroupMemberMutation is the PUT body for /usergroups/id/{id} that adds
// or removes individual users from a static group via Jamf's PATCH-like
// additions/deletions verb. Exactly one of Additions/Deletions is set per
// call — Grant uses Additions, Revoke uses Deletions.
type UserGroupMemberMutation struct {
	XMLName   xml.Name     `xml:"user_group"`
	Additions *memberUsers `xml:"user_additions,omitempty"`
	Deletions *memberUsers `xml:"user_deletions,omitempty"`
}

// UserSitesUpdateBody is the PUT body for /users/id/{id} carrying only the
// <sites> block. A Classic API PUT only changes the elements it sends, so the
// rest of the user record (email, full_name, etc.) is left untouched.
type UserSitesUpdateBody struct {
	XMLName xml.Name   `xml:"user"`
	Sites   []BaseType `xml:"sites>site"`
}
