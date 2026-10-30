package jamf

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	liburl "net/url"
	"strconv"
	"strings"

	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	accountUrlPath         = "/JSSResource/accounts/userid/%d"   // https://developer.jamf.com/jamf-pro/reference/findaccountsbyid
	accountUsernameUrlPath = "/JSSResource/accounts/username/%s" // https://developer.jamf.com/jamf-pro/reference/findaccountsbyname
	accountsUrlPath        = "/JSSResource/accounts"             // https://developer.jamf.com/jamf-pro/reference/findaccounts
	authUrlPath            = "/api/v1/auth"                      // https://developer.jamf.com/jamf-pro/reference/get_v1-auth
	groupUrlPath           = "/JSSResource/accounts/groupid/%d"  // https://developer.jamf.com/jamf-pro/reference/findgroupsbyid
	sitesUrlPath           = "/JSSResource/sites"                // https://developer.jamf.com/jamf-pro/reference/findsites
	tokenUrlPath           = "/api/v1/auth/token"                //nolint:golint,gosec // not a token, https://developer.jamf.com/jamf-pro/reference/post_v1-auth-token
	userGroupUrlPath       = "/JSSResource/usergroups/id/%d"     // https://developer.jamf.com/jamf-pro/reference/findusergroupsbyid
	userGroupsUrlPath      = "/JSSResource/usergroups"           // https://developer.jamf.com/jamf-pro/reference/findusergroups
	userUrlPath            = "/JSSResource/users/id/%d"          // https://developer.jamf.com/jamf-pro/reference/findusersbyid
	userNameUrlPath        = "/JSSResource/users/name/%s"        // https://developer.jamf.com/jamf-pro/reference/findusersbyname
	oauthTokenUrlPath      = "/api/v1/oauth/token"               //nolint:gosec // not a token, https://developer.jamf.com/jamf-pro/docs/client-credentials
	privilegesUrlPath      = "/api/v1/api-role-privileges"       // https://developer.jamf.com/jamf-pro/reference/get_v1-api-role-privileges
	proUsersUrlPath        = "/api/v1/users"                     // https://developer.jamf.com/jamf-pro/reference/get_v1-users
	proAccountsUrlPath     = "/api/v1/accounts"                  // https://developer.jamf.com/jamf-pro/reference/get_v1-accounts
	siteObjectsUrlPath     = "/api/v1/sites/%d/objects"          // https://developer.jamf.com/jamf-pro/reference/get_v1-sites-id-objects

	// UsersPageSize is the documented maximum page-size of GET /api/v1/users.
	UsersPageSize = 1000
	// AccountsPageSize is the documented default page-size of GET /api/v1/accounts; no maximum is documented.
	AccountsPageSize = 100
	// SiteObjectsPageSize is the page-size used for GET /api/v1/sites/{id}/objects; no maximum is documented.
	SiteObjectsPageSize = 1000

	classicAPIPathPrefix = "/JSSResource/"

	// newResourceID is the Jamf Classic API sentinel used in the URL path when
	// creating a new user or account — the server assigns the real ID and
	// returns it in the response.
	newResourceID = 0
)

type Client struct {
	wrapper     *uhttp.BaseHttpClient
	instanceURL string
	tokenSource *TokenSource
}

// freshReadsContextKey marks a context as requiring GET requests to bypass
// the HTTP client's response cache (default TTL: one hour — see uhttp's
// gocache.go cacheTTLDefault). Sync reads benefit from that cache and are
// unaffected; provisioning paths wrap their ctx with WithFreshReads because a
// stale GET there can produce a wrong idempotency decision or a PUT built
// from stale data.
type freshReadsContextKey struct{}

// WithFreshReads returns a context that causes GET requests issued through
// this client to bypass the response cache. Provisioning entry points
// (Grant, Revoke, CreateAccount, Delete) wrap their ctx with this at the top
// of the method; sync code paths (List, Entitlements, Grants) must not, so
// they keep benefiting from the cache.
func WithFreshReads(ctx context.Context) context.Context {
	return context.WithValue(ctx, freshReadsContextKey{}, true)
}

// wantsFreshReads reports whether ctx was wrapped with WithFreshReads.
func wantsFreshReads(ctx context.Context) bool {
	v, _ := ctx.Value(freshReadsContextKey{}).(bool)
	return v
}

// NewClient validates instanceURL and returns a client that authenticates with tokenSource.
func NewClient(wrapper *uhttp.BaseHttpClient, instanceURL string, tokenSource *TokenSource) (*Client, error) {
	if err := validateInstanceURL(instanceURL); err != nil {
		return nil, err
	}
	return &Client{
		wrapper:     wrapper,
		instanceURL: instanceURL,
		tokenSource: tokenSource,
	}, nil
}

// validateInstanceURL fails fast on a URL without a scheme or host instead of an obscure error mid-sync.
func validateInstanceURL(instanceURL string) error {
	parsed, err := liburl.Parse(instanceURL)
	if err != nil || parsed.Host == "" || !allowedScheme(parsed) {
		return status.Errorf(codes.InvalidArgument, "invalid instance URL %q: it must look like https://yourcompany.jamfcloud.com", instanceURL)
	}
	return nil
}

// allowedScheme accepts https, and plain http only on the local machine, so credentials never cross the network in clear text.
func allowedScheme(parsed *liburl.URL) bool {
	if parsed.Scheme == "https" {
		return true
	}
	host := parsed.Hostname()
	ip := net.ParseIP(host)
	return parsed.Scheme == "http" && (host == "localhost" || (ip != nil && ip.IsLoopback()))
}

func (c *Client) getUrl(path string) (*liburl.URL, error) {
	urlString, err := liburl.JoinPath(c.instanceURL, path)
	if err != nil {
		return nil, err
	}
	return liburl.Parse(urlString)
}

// GetTokenDetails gets authorization details associated with the current api token.
func (c *Client) GetTokenDetails(ctx context.Context) (*TokenDetails, error) {
	url, err := c.getUrl(authUrlPath)
	if err != nil {
		return nil, err
	}

	var target TokenDetails
	if err := c.doRequest(ctx, url, &target); err != nil {
		return nil, err
	}

	return &target, nil
}

// GetUserDetails returns Jamf user details for a single directory user.
func (c *Client) GetUserDetails(ctx context.Context, userId int) (*User, error) {
	url, err := c.getUrl(fmt.Sprintf(userUrlPath, userId))
	if err != nil {
		return nil, err
	}

	var target UserResponse
	if err := c.doRequest(ctx, url, &target); err != nil {
		return nil, err
	}

	return &target.User, nil
}

// GetBaseAccounts returns the Classic admin accounts (users and groups, id and name only).
// GET /JSSResource/accounts, not paginated, needs the Read Accounts privilege.
func (c *Client) GetBaseAccounts(ctx context.Context) (*BaseAccount, error) {
	url, err := c.getUrl(accountsUrlPath)
	if err != nil {
		return nil, err
	}

	var target AccountsResponse
	if err := c.doRequest(ctx, url, &target); err != nil {
		return nil, err
	}

	return &target.Accounts, nil
}

// GetGroupDetails returns Jamf group details.
func (c *Client) GetGroupDetails(ctx context.Context, groupId int) (*Group, error) {
	url, err := c.getUrl(fmt.Sprintf(groupUrlPath, groupId))
	if err != nil {
		return nil, err
	}

	var target GroupResponse
	if err := c.doRequest(ctx, url, &target); err != nil {
		return nil, err
	}

	return &target.Group, nil
}

// GetUserAccountDetails returns Jamf user account details; a 404 (IsNotFoundError) means the account does not exist.
func (c *Client) GetUserAccountDetails(ctx context.Context, userId int) (*UserAccount, error) {
	url, err := c.getUrl(fmt.Sprintf(accountUrlPath, userId))
	if err != nil {
		return nil, err
	}

	var target UserAccountResponse
	if err := c.doRequest(ctx, url, &target); err != nil {
		return nil, err
	}

	return &target.UserAccount, nil
}

// GetSites returns all Jamf sites.
func (c *Client) GetSites(ctx context.Context) (*[]Site, error) {
	url, err := c.getUrl(sitesUrlPath)
	if err != nil {
		return nil, err
	}

	var target SitesResponse
	if err := c.doRequest(ctx, url, &target); err != nil {
		return nil, err
	}

	return &target.Sites, nil
}

// GetBaseUserGroups returns the Classic user groups (id and name only).
// GET /JSSResource/usergroups, not paginated, needs the Read Static User Groups privilege.
func (c *Client) GetBaseUserGroups(ctx context.Context) ([]UserGroup, error) {
	url, err := c.getUrl(userGroupsUrlPath)
	if err != nil {
		return nil, err
	}

	var target UserGroupsResponse

	if err := c.doRequest(ctx, url, &target); err != nil {
		return nil, err
	}

	return target.UserGroups, nil
}

// GetUserGroupDetails returns Jamf user group details.
func (c *Client) GetUserGroupDetails(ctx context.Context, userGroupId int) (*UserGroup, error) {
	url, err := c.getUrl(fmt.Sprintf(userGroupUrlPath, userGroupId))
	if err != nil {
		return nil, err
	}

	var target UserGroupResponse
	if err := c.doRequest(ctx, url, &target); err != nil {
		return nil, err
	}

	return &target.UserGroup, nil
}

// GetProUsers returns one page of users ordered by id and the next page token, "" after the last page.
// GET /api/v1/users, needs the Read User privilege.
func (c *Client) GetProUsers(ctx context.Context, pageToken string, pageSize int) ([]ProUser, string, error) {
	page, err := parsePageToken(pageToken)
	if err != nil {
		return nil, "", err
	}

	url, err := c.getUrl(proUsersUrlPath)
	if err != nil {
		return nil, "", err
	}
	query := liburl.Values{}
	query.Set("page", strconv.Itoa(page))
	query.Set("page-size", strconv.Itoa(pageSize))
	query.Set("sort", "id:asc")
	url.RawQuery = query.Encode()

	var response ProUsersResponse
	if err := c.doRequest(ctx, url, &response); err != nil {
		return nil, "", proEndpointError(proUsersUrlPath, err)
	}

	nextPage := nextPageToken(page, pageSize, len(response.Results), response.TotalCount)
	return response.Results, nextPage, nil
}

// rsqlValueEscaper escapes a value placed inside a double-quoted RSQL string.
var rsqlValueEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`)

// GetProUsersByUsernameOrEmail returns up to UsersPageSize users, ordered by id, whose username or email equals
// any of values. GET /api/v1/users with an RSQL filter, needs the Read User privilege.
// RSQL treats `*` as a wildcard, so the caller must re-check each match.
func (c *Client) GetProUsersByUsernameOrEmail(ctx context.Context, values []string) ([]ProUser, error) {
	url, err := c.getUrl(proUsersUrlPath)
	if err != nil {
		return nil, err
	}

	terms := make([]string, 0, len(values)*2)
	for _, value := range values {
		quoted := `"` + rsqlValueEscaper.Replace(value) + `"`
		terms = append(terms, "username=="+quoted, "email=="+quoted)
	}
	query := liburl.Values{}
	query.Set("filter", strings.Join(terms, ","))
	query.Set("page", "0")
	query.Set("page-size", strconv.Itoa(UsersPageSize))
	query.Set("sort", "id:asc")
	url.RawQuery = query.Encode()

	var response ProUsersResponse
	if err := c.doRequest(ctx, url, &response); err != nil {
		return nil, proEndpointError(proUsersUrlPath, err)
	}

	return response.Results, nil
}

// GetProAccounts returns one page of admin accounts ordered by id and the next page token, "" after the last page.
// filter is an optional RSQL expression. GET /api/v1/accounts, needs the Read Accounts privilege.
func (c *Client) GetProAccounts(ctx context.Context, filter, pageToken string, pageSize int) ([]ProAccount, string, error) {
	page, err := parsePageToken(pageToken)
	if err != nil {
		return nil, "", err
	}

	url, err := c.getUrl(proAccountsUrlPath)
	if err != nil {
		return nil, "", err
	}
	query := liburl.Values{}
	if filter != "" {
		query.Set("filter", filter)
	}
	query.Set("page", strconv.Itoa(page))
	query.Set("page-size", strconv.Itoa(pageSize))
	query.Set("sort", "id:asc")
	url.RawQuery = query.Encode()

	var response ProAccountsResponse
	if err := c.doRequest(ctx, url, &response); err != nil {
		return nil, "", proEndpointError(proAccountsUrlPath, err)
	}

	nextPage := nextPageToken(page, pageSize, len(response.Results), response.TotalCount)
	return response.Results, nextPage, nil
}

// GetSiteObjects returns one page of the site's objects of objectType (for example "User") and the next page
// token, "" after the last page. GET /api/v1/sites/{id}/objects, needs the Read Sites privilege.
// An unknown site answers an empty list, so a 404 means the instance lacks the endpoint.
func (c *Client) GetSiteObjects(ctx context.Context, siteID int, objectType, pageToken string) ([]SiteObject, string, error) {
	page, err := parsePageToken(pageToken)
	if err != nil {
		return nil, "", err
	}

	url, err := c.getUrl(fmt.Sprintf(siteObjectsUrlPath, siteID))
	if err != nil {
		return nil, "", err
	}
	query := liburl.Values{}
	query.Set("filter", `objectType=="`+rsqlValueEscaper.Replace(objectType)+`"`)
	query.Set("page", strconv.Itoa(page))
	query.Set("page-size", strconv.Itoa(SiteObjectsPageSize))
	query.Set("sort", "objectId:asc")
	url.RawQuery = query.Encode()

	var objects []SiteObject
	if err := c.doRequest(ctx, url, &objects); err != nil {
		return nil, "", proEndpointError(url.Path, err)
	}

	// The response has no total count: a full page may be followed by another.
	if len(objects) == SiteObjectsPageSize {
		return objects, strconv.Itoa(page + 1), nil
	}
	return objects, "", nil
}

// AddUserGroupMembers adds the given user IDs to a static Jamf user group via
// the additions verb (PUT .../usergroups/id/{id} <user_group><user_additions>).
// Atomic — no read-modify-write. Returns a gRPC NotFound error if the group
// doesn't exist (surfaced via IsNotFoundError).
func (c *Client) AddUserGroupMembers(ctx context.Context, groupID int, userIDs []int) error {
	url, err := c.getUrl(fmt.Sprintf(userGroupUrlPath, groupID))
	if err != nil {
		return err
	}

	reqBody := UserGroupMemberMutation{Additions: &memberUsers{Users: baseTypesFromIDs(userIDs)}}
	return c.doRequestWithMethod(ctx, http.MethodPut, url, reqBody, nil)
}

// RemoveUserGroupMembers removes the given user IDs from a static Jamf user
// group via the deletions verb (<user_group><user_deletions>). Atomic.
// Returns a gRPC NotFound error if the group doesn't exist (surfaced via
// IsNotFoundError).
func (c *Client) RemoveUserGroupMembers(ctx context.Context, groupID int, userIDs []int) error {
	url, err := c.getUrl(fmt.Sprintf(userGroupUrlPath, groupID))
	if err != nil {
		return err
	}

	reqBody := UserGroupMemberMutation{Deletions: &memberUsers{Users: baseTypesFromIDs(userIDs)}}
	return c.doRequestWithMethod(ctx, http.MethodPut, url, reqBody, nil)
}

// baseTypesFromIDs wraps each id as a BaseType with only ID set, the shape
// the Classic API's <user_additions>/<user_deletions> verbs expect for each
// <user> element.
func baseTypesFromIDs(ids []int) []BaseType {
	out := make([]BaseType, 0, len(ids))
	for _, id := range ids {
		out = append(out, BaseType{ID: id})
	}
	return out
}

// GetUserByName returns the Jamf user with the given username (login name).
func (c *Client) GetUserByName(ctx context.Context, name string) (*User, error) {
	url, err := c.getUrl(fmt.Sprintf(userNameUrlPath, liburl.PathEscape(name)))
	if err != nil {
		return nil, err
	}

	var target UserResponse
	if err := c.doRequest(ctx, url, &target); err != nil {
		return nil, err
	}

	return &target.User, nil
}

// CreateUser creates a new Jamf user. Returns a gRPC AlreadyExists error
// (surfaced via IsAlreadyExistsError) if a user with this name already exists.
func (c *Client) CreateUser(ctx context.Context, name, fullName, email string) error {
	url, err := c.getUrl(fmt.Sprintf(userUrlPath, newResourceID))
	if err != nil {
		return err
	}

	reqBody := UserCreateBody{
		Name:     name,
		FullName: fullName,
		Email:    email,
	}

	return c.doRequestWithMethod(ctx, http.MethodPost, url, reqBody, nil)
}

// DeleteUser deletes the Jamf user with the given ID. Returns a gRPC NotFound
// error (surfaced via IsNotFoundError) if the user doesn't exist.
func (c *Client) DeleteUser(ctx context.Context, userID int) error {
	url, err := c.getUrl(fmt.Sprintf(userUrlPath, userID))
	if err != nil {
		return err
	}

	return c.doRequestWithMethod(ctx, http.MethodDelete, url, nil, nil)
}

// GetUserAccountByName returns the Jamf admin account with the given username.
func (c *Client) GetUserAccountByName(ctx context.Context, name string) (*UserAccount, error) {
	url, err := c.getUrl(fmt.Sprintf(accountUsernameUrlPath, liburl.PathEscape(name)))
	if err != nil {
		return nil, err
	}

	var target UserAccountResponse
	if err := c.doRequest(ctx, url, &target); err != nil {
		return nil, err
	}

	return &target.UserAccount, nil
}

// CreateUserAccount creates a new Jamf Pro console admin account. Returns a
// gRPC AlreadyExists error (surfaced via IsAlreadyExistsError) if an account
// with this name already exists.
func (c *Client) CreateUserAccount(ctx context.Context, account UserAccountCreateBody) error {
	url, err := c.getUrl(fmt.Sprintf(accountUrlPath, newResourceID))
	if err != nil {
		return err
	}

	return c.doRequestWithMethod(ctx, http.MethodPost, url, account, nil)
}

// DeleteUserAccount deletes the Jamf admin account with the given ID. Returns
// a gRPC NotFound error (surfaced via IsNotFoundError) if the account doesn't exist.
func (c *Client) DeleteUserAccount(ctx context.Context, accountID int) error {
	url, err := c.getUrl(fmt.Sprintf(accountUrlPath, accountID))
	if err != nil {
		return err
	}

	return c.doRequestWithMethod(ctx, http.MethodDelete, url, nil, nil)
}

// updatePrivileges backs both UpdateAccountPrivileges and
// UpdateGroupPrivileges: a minimal PUT carrying <name> and, optionally,
// <privilege_set>/<privileges>, with root as the XML root element name
// ("account" or "group") — see privilegesUpdateBody for the body shape and
// the Custom-write caveat.
func (c *Client) updatePrivileges(ctx context.Context, path, root string, id int, name, privilegeSet string, privileges *Privileges) error {
	url, err := c.getUrl(fmt.Sprintf(path, id))
	if err != nil {
		return err
	}

	reqBody := privilegesUpdateBody{
		XMLName:      xml.Name{Local: root},
		Name:         name,
		PrivilegeSet: privilegeSet,
		Privileges:   privileges,
	}
	return c.doRequestWithMethod(ctx, http.MethodPut, url, reqBody, nil)
}

// UpdateAccountPrivileges updates a Jamf admin account's privilege_set
// and/or individual privileges. See
// https://developer.jamf.com/jamf-pro/reference/updateaccountbyid.
func (c *Client) UpdateAccountPrivileges(ctx context.Context, accountID int, name, privilegeSet string, privileges *Privileges) error {
	return c.updatePrivileges(ctx, accountUrlPath, "account", accountID, name, privilegeSet, privileges)
}

// UpdateGroupPrivileges is UpdateAccountPrivileges's counterpart for an
// admin account group. See
// https://developer.jamf.com/jamf-pro/reference/updategroupbyid.
func (c *Client) UpdateGroupPrivileges(ctx context.Context, groupID int, name, privilegeSet string, privileges *Privileges) error {
	return c.updatePrivileges(ctx, groupUrlPath, "group", groupID, name, privilegeSet, privileges)
}

// UpdateGroupMembers updates a Jamf access-level group's membership via a
// minimal PUT carrying only <name> and <members> — see
// GroupMembersUpdateBody. members is the complete desired list; pass an
// empty slice to clear the last member. Returns a gRPC NotFound error
// (IsNotFoundError) if the group doesn't exist. See
// https://developer.jamf.com/jamf-pro/reference/updategroupbyid.
func (c *Client) UpdateGroupMembers(ctx context.Context, groupID int, name string, members []BaseType) error {
	url, err := c.getUrl(fmt.Sprintf(groupUrlPath, groupID))
	if err != nil {
		return err
	}

	reqBody := GroupMembersUpdateBody{
		Name:    name,
		Members: &memberUsers{Users: members},
	}
	return c.doRequestWithMethod(ctx, http.MethodPut, url, reqBody, nil)
}

// UpdateUserSites PUTs the full desired <sites> list for a user, leaving
// the rest of the user record untouched (Classic API field-level merge).
// Callers own the read-modify-write and idempotency checks (see site.go).
//
// Concurrency note: no locking/versioning guard — concurrent calls for the
// same userID can race and silently drop one side's change; serialize calls
// per user if that matters.
func (c *Client) UpdateUserSites(ctx context.Context, userID int, sites UserSites) error {
	url, err := c.getUrl(fmt.Sprintf(userUrlPath, userID))
	if err != nil {
		return err
	}

	ids := make([]int, 0, len(sites))
	for _, s := range sites {
		ids = append(ids, s.ID)
	}
	reqBody := UserSitesUpdateBody{Sites: baseTypesFromIDs(ids)}
	return c.doRequestWithMethod(ctx, http.MethodPut, url, reqBody, nil)
}

// doRequest performs an authenticated GET request to the Jamf API.
func (c *Client) doRequest(
	ctx context.Context,
	url *liburl.URL,
	target interface{},
) error {
	return c.doRequestWithMethod(ctx, http.MethodGet, url, nil, target)
}

// doRequestWithMethod performs an authenticated request to the Jamf Classic
// API for any HTTP method, optionally sending reqBody as an XML request body
// (the only format the Classic API accepts for POST/PUT). Passing a nil
// target skips decoding the response body (used for DELETE and other
// no-content responses).
func (c *Client) doRequestWithMethod(
	ctx context.Context,
	method string,
	url *liburl.URL,
	reqBody interface{},
	target interface{},
) error {
	// The Classic API only accepts XML for POST/PUT request bodies (JSON is
	// GET-response-only); see
	// https://developer.jamf.com/jamf-pro/docs/getting-started-2.
	return c.doRequestWithMethodAndBodyEncoding(ctx, method, url, reqBody, target, uhttp.WithXMLBody)
}

// doRequestWithJSONMethod performs an authenticated request to the Jamf Pro
// API (unlike the Classic API, it accepts JSON request bodies) for any HTTP
// method, optionally sending reqBody as a JSON request body. Passing a nil
// target skips decoding the response body.
func (c *Client) doRequestWithJSONMethod(
	ctx context.Context,
	method string,
	url *liburl.URL,
	reqBody interface{},
	target interface{},
) error {
	return c.doRequestWithMethodAndBodyEncoding(ctx, method, url, reqBody, target, uhttp.WithJSONBody)
}

// doRequestWithMethodAndBodyEncoding is the shared implementation behind
// doRequestWithMethod (XML, Classic API) and doRequestWithJSONMethod (JSON,
// Pro API) — same auth/retry/decode behavior, differing only in how reqBody
// is encoded onto the wire.
//
// GET requests made with a ctx wrapped by WithFreshReads bypass the HTTP
// wrapper's response cache (uhttp.WithNoCache) — see WithFreshReads.
func (c *Client) doRequestWithMethodAndBodyEncoding(
	ctx context.Context,
	method string,
	url *liburl.URL,
	reqBody interface{},
	target interface{},
	bodyEncoding func(interface{}) uhttp.RequestOption,
) error {
	l := ctxzap.Extract(ctx)

	token, err := c.token()
	if err != nil {
		return err
	}

	requestOpts := []uhttp.RequestOption{
		uhttp.WithAcceptJSONHeader(),
		uhttp.WithBearerToken(token.AccessToken),
	}
	if method == http.MethodGet && wantsFreshReads(ctx) {
		requestOpts = append(requestOpts, uhttp.WithNoCache())
	}
	if reqBody != nil {
		requestOpts = append(requestOpts, bodyEncoding(reqBody))
	}

	request, err := c.wrapper.NewRequest(
		ctx,
		method,
		url,
		requestOpts...,
	)
	if err != nil {
		return err
	}
	response, err := c.wrapper.Do(request)
	if response != nil && response.StatusCode == http.StatusUnauthorized && !missingPrivilege(response, url.Path) {
		// Jamf can reject a token before it expires, so get a new one and retry once.
		response, err = c.retryWithNewToken(request, token.AccessToken)
	}
	if err != nil {
		// uhttp already logs the underlying HTTP failure at the appropriate
		// level (Warn for 4xx, Error for 5xx) — this is just a debug trace of
		// where it surfaced. Callers routinely treat 404/409 here as success
		// (CreateAccount already-exists, Delete not-found), so logging at
		// Error would misrepresent expected idempotent outcomes as failures.
		l.Debug("failed to perform request", zap.Error(err))
		if missingPrivilege(response, url.Path) {
			return uhttp.WrapErrors(codes.PermissionDenied,
				fmt.Sprintf("jamf rejected %s %s with 401: the account or API client lacks the Jamf privilege this operation needs", method, url.Path), err)
		}
		return err
	}

	defer response.Body.Close()
	if target == nil {
		return nil
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}
	err = json.Unmarshal(body, target)
	if err != nil {
		return fmt.Errorf("failed to unmarshal json response: %w. status code: %d. content type: %q. body omitted (%d bytes)",
			err, response.StatusCode, response.Header.Get("Content-Type"), len(body))
	}

	return nil
}

func (c *Client) token() (*oauth2.Token, error) {
	token, err := c.tokenSource.Token()
	if err != nil {
		// A token endpoint 404 is a wrong instance URL; as NotFound, Revoke and Delete would report success.
		if status.Code(err) == codes.NotFound {
			return nil, uhttp.WrapErrors(codes.InvalidArgument, "jamf token endpoint not found: check the instance URL", err)
		}
		return nil, fmt.Errorf("failed to get a Jamf token: %w", err)
	}
	return token, nil
}

// missingPrivilege reports the Classic API's answer to a missing privilege: a 401 with an HTML status page.
// A rejected token gets a JSON 401 instead, and the Jamf Pro API answers a missing privilege with 403.
func missingPrivilege(response *http.Response, path string) bool {
	return response != nil && response.StatusCode == http.StatusUnauthorized &&
		strings.Contains(path, classicAPIPathPrefix) &&
		strings.HasPrefix(response.Header.Get("Content-Type"), "text/html")
}

// retryWithNewToken drops the rejected token and resends the request with a new one.
func (c *Client) retryWithNewToken(request *http.Request, rejected string) (*http.Response, error) {
	c.tokenSource.Renew(rejected)
	token, err := c.token()
	if err != nil {
		return nil, err
	}

	retry := request.Clone(request.Context())
	// Clone shares the body the first attempt already read, and HTTP/2 doesn't rewind it.
	if request.GetBody != nil {
		if retry.Body, err = request.GetBody(); err != nil {
			return nil, fmt.Errorf("failed to rewind request body: %w", err)
		}
	}
	retry.Header.Set("Authorization", "Bearer "+token.AccessToken)
	return c.wrapper.Do(retry)
}

func (c *Client) GetPrivileges(ctx context.Context) (*PrivilegesResponse, error) {
	url, err := c.getUrl(privilegesUrlPath)
	if err != nil {
		return nil, err
	}

	var target PrivilegesResponse
	if err := c.doRequest(ctx, url, &target); err != nil {
		return nil, proEndpointError(privilegesUrlPath, err)
	}

	return &target, nil
}
