package jamf

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

type Privileges struct {
	// array of privileges the resource has access to
	JSSObjects []string `json:"jss_objects"`
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
