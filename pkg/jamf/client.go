package jamf

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	liburl "net/url"
	"time"

	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	accountUrlPath    = "/JSSResource/accounts/userid/%d"
	accountsUrlPath   = "/JSSResource/accounts"
	authUrlPath       = "/api/v1/auth"
	groupUrlPath      = "/JSSResource/accounts/groupid/%d"
	sitesUrlPath      = "/JSSResource/sites"
	tokenUrlPath      = "/api/v1/auth/token" //nolint:golint,gosec // not a token
	userGroupUrlPath  = "/JSSResource/usergroups/id/%d"
	userGroupsUrlPath = "/JSSResource/usergroups"
	userUrlPath       = "/JSSResource/users/id/%d"
	usersUrlPath      = "/JSSResource/users"
	keepAliveUrlPath  = "/api/v1/auth/keep-alive"
	privilegesUrlPath = "/api/v1/api-role-privileges"
)

type Client struct {
	wrapper       *uhttp.BaseHttpClient
	token         string
	instanceURL   string
	lastKeepAlive time.Time

	userName string
	password string
}

func NewClient(
	wrapper *uhttp.BaseHttpClient,
	userName string,
	password string,
	token string,
	instanceURL string,
) *Client {
	return &Client{
		wrapper:       wrapper,
		token:         token,
		instanceURL:   instanceURL,
		lastKeepAlive: time.Now(),
		userName:      userName,
		password:      password,
	}
}

func (c *Client) SetBearerToken(token string) {
	c.lastKeepAlive = time.Now()
	c.token = token
}

func (c *Client) getUrl(path string) (*liburl.URL, error) {
	urlString, err := liburl.JoinPath(c.instanceURL, path)
	if err != nil {
		return nil, err
	}
	return liburl.Parse(urlString)
}

func (c *Client) keepAliveToken(
	ctx context.Context,
) error {
	l := ctxzap.Extract(ctx)

	if c.token == "" {
		return fmt.Errorf("token is empty")
	}

	if time.Since(c.lastKeepAlive) < 5*time.Minute {
		return nil
	}

	l.Debug("Refreshing token")

	url, err := c.getUrl(keepAliveUrlPath)
	if err != nil {
		return err
	}

	request, err := c.wrapper.NewRequest(
		ctx,
		http.MethodPost,
		url,
		uhttp.WithAcceptJSONHeader(),
		uhttp.WithContentTypeJSONHeader(),
		uhttp.WithHeader(
			"Authorization",
			fmt.Sprintf("Bearer %s", c.token),
		),
	)
	if err != nil {
		return err
	}

	var target TokenResponse
	response, err := c.wrapper.Do(request, uhttp.WithJSONResponse(&target))
	if err != nil {
		return err
	}
	err = response.Body.Close()
	if err != nil {
		return err
	}

	c.token = target.Token
	c.lastKeepAlive = time.Now()

	return nil
}

// CreateBearerToken creates bearer token needed to use the Jamf API.
func (c *Client) CreateBearerToken(
	ctx context.Context,
	username string,
	password string,
) (string, error) {
	l := ctxzap.Extract(ctx)

	l.Debug("Creating bearer token")
	url, err := c.getUrl(tokenUrlPath)
	if err != nil {
		return "", err
	}

	request, err := c.wrapper.NewRequest(
		ctx,
		http.MethodPost,
		url,
		uhttp.WithAcceptJSONHeader(),
		uhttp.WithContentTypeJSONHeader(),
	)
	if err != nil {
		return "", err
	}
	request.SetBasicAuth(username, password)

	var target TokenResponse
	response, err := c.wrapper.Do(request, uhttp.WithJSONResponse(&target))
	if err != nil {
		return "", err
	}
	err = response.Body.Close()
	if err != nil {
		return "", err
	}
	return target.Token, nil
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

func (c *Client) getBaseUsers(ctx context.Context) ([]BaseType, error) {
	url, err := c.getUrl(usersUrlPath)
	if err != nil {
		return nil, err
	}

	var target UsersResponse
	if err := c.doRequest(ctx, url, &target); err != nil {
		return nil, err
	}

	return target.Users, nil
}

func (c *Client) getUserDetails(ctx context.Context, userId int) (*User, error) {
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

func (c *Client) getBaseAccounts(ctx context.Context) (*BaseAccount, error) {
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

// GetUserAccountDetails returns Jamf user account details.
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

func (c *Client) getBaseUserGroups(ctx context.Context) ([]UserGroup, error) {
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

// GetUsers returns all Jamf users.
func (c *Client) GetUsers(ctx context.Context) ([]*User, error) {
	var users []*User
	baseUsers, err := c.getBaseUsers(ctx)
	if err != nil {
		return nil, err
	}

	for _, baseUser := range baseUsers {
		user, err := c.getUserDetails(ctx, baseUser.ID)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	return users, nil
}

// GetUserGroups returns all Jamf user groups.
func (c *Client) GetUserGroups(ctx context.Context) ([]*UserGroup, error) {
	var userGroups []*UserGroup
	baseUserGroup, err := c.getBaseUserGroups(ctx)
	if err != nil {
		return nil, err
	}

	for _, userGroup := range baseUserGroup {
		userGroupInfo, err := c.GetUserGroupDetails(ctx, userGroup.ID)
		if err != nil {
			return nil, err
		}
		userGroups = append(userGroups, userGroupInfo)
	}

	return userGroups, nil
}

// GetAccounts returns all Jamf accounts.
// TODO(marcos): The Jamf API doesn't have pagination, but this method could
// benefit from parallelization.
func (c *Client) GetAccounts(ctx context.Context) ([]*UserAccount, []*Group, error) {
	var userAccounts []*UserAccount
	var groups []*Group
	baseAccounts, err := c.getBaseAccounts(ctx)
	if err != nil {
		return nil, nil, err
	}

	for _, user := range baseAccounts.Users {
		userAccountInfo, err := c.GetUserAccountDetails(ctx, user.ID)
		if err != nil {
			return nil, nil, err
		}
		userAccounts = append(userAccounts, userAccountInfo)
	}

	for _, group := range baseAccounts.Groups {
		groupInfo, err := c.GetGroupDetails(ctx, group.ID)
		if err != nil {
			return nil, nil, err
		}
		groups = append(groups, groupInfo)
	}

	return userAccounts, groups, nil
}

// doRequest performs an authenticated request to the Jamf API.
func (c *Client) doRequest(
	ctx context.Context,
	url *liburl.URL,
	target interface{},
) error {
	l := ctxzap.Extract(ctx)

	err := c.keepAliveToken(ctx)
	if err != nil {
		return err
	}

	firstTry := true

GotoRetry:
	request, err := c.wrapper.NewRequest(
		ctx,
		http.MethodGet,
		url,
		uhttp.WithAcceptJSONHeader(),
		uhttp.WithHeader(
			"Authorization",
			fmt.Sprintf("Bearer %s", c.token),
		),
	)
	if err != nil {
		return err
	}
	response, err := c.wrapper.Do(request)
	if err != nil {
		l.Error("failed to perform request", zap.Error(err))
		if status.Code(err) == codes.Unauthenticated && firstTry {
			l.Debug("retrying request with new token")
			token, err := c.CreateBearerToken(ctx, c.userName, c.password)
			if err != nil {
				return err
			}

			c.SetBearerToken(token)
			firstTry = false

			l.Debug("retrying request with new token")
			goto GotoRetry
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
		return fmt.Errorf("failed to unmarshal json response: %w. status code: %d. body %v", err, response.StatusCode, logBody(body, 2048))
	}

	return nil
}

func logBody(body []byte, size int) string {
	if len(body) > size {
		return string(body[:size]) + " ..."
	}
	return string(body)
}

func (c *Client) GetPrivileges(ctx context.Context) (*PrivilegesResponse, error) {
	url, err := c.getUrl(privilegesUrlPath)
	if err != nil {
		return nil, err
	}

	var target PrivilegesResponse
	if err := c.doRequest(ctx, url, &target); err != nil {
		return nil, err
	}

	return &target, nil
}
