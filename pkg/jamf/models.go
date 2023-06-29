package jamf

type BaseType struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// end user in Jamf.
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

// user that has access to their system and can be granted permissions.
type UserAccount struct {
	BaseType
	FullName     string   `json:"full_name"`
	Email        string   `json:"email"`
	EmailAddress string   `json:"email_address"`
	Enabled      string   `json:"enabled"`
	AccessLevel  string   `json:"access_level"`
	PrivilegeSet string   `json:"privilege_set"`
	Site         BaseType `json:"site"`
}

type Group struct {
	BaseType
	AccessLevel  string   `json:"access_level"`
	PrivilegeSet string   `json:"privilege_set"`
	Site         BaseType `json:"site"`
	Members      []struct {
		User BaseType `json:"user"`
	} `json:"members"`
}

type Acccount struct {
	Name        string      `json:"name"`
	ID          string      `json:"id"`
	UserAccount UserAccount `json:"user_account"`
	Group       Group       `json:"group"`
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
