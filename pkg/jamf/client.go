package jamf

import (
	"context"
	"fmt"
	"net/http"
	liburl "net/url"

	"github.com/conductorone/baton-sdk/pkg/uhttp"
)

const (
	accountUrlPath    = "/JSSResource/accounts/userid/%d"
	accountsUrlPath   = "/JSSResource/accounts"
	authUrlPath       = "/api/v1/auth"
	groupUrlPath      = "/JSSResource/accounts/groupid/%d"
	sitesUrlPath      = "/JSSResource/sites"
	tokenUrlPath      = "/api/v1/auth/token"
	userGroupUrlPath  = "/JSSResource/usergroups/id/%d"
	userGroupsUrlPath = "/JSSResource/usergroups"
	userUrlPath       = "/JSSResource/users/id/%d"
	usersUrlPath      = "/JSSResource/users"
)

type Client struct {
	wrapper     *uhttp.BaseHttpClient
	token       string
	instanceURL string
}

func NewClient(
	wrapper *uhttp.BaseHttpClient,
	token string,
	instanceURL string,
) *Client {
	return &Client{
		wrapper:     wrapper,
		token:       token,
		instanceURL: instanceURL,
	}
}

func (c *Client) SetBearerToken(token string) {
	c.token = token
}

func (c *Client) getUrl(path string) (*liburl.URL, error) {
	urlString, err := liburl.JoinPath(c.instanceURL, path)
	if err != nil {
		return nil, err
	}
	return liburl.Parse(urlString)
}

// CreateBearerToken creates bearer token needed to use the Jamf API.
func (c *Client) CreateBearerToken(
	ctx context.Context,
	username string,
	password string,
) (string, error) {
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
	if _, err = c.wrapper.Do(request, uhttp.WithJSONResponse(target)); err != nil {
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

func (c *Client) doRequest(
	ctx context.Context,
	url *liburl.URL,
	target interface{},
) error {
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

	if _, err := c.wrapper.Do(request, uhttp.WithJSONResponse(target)); err != nil {
		return err
	}
	return nil
}
