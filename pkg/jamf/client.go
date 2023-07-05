package jamf

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
)

type Client struct {
	httpClient  *http.Client
	token       string
	baseUrl     string
	instanceURL string
}

func NewClient(httpClient *http.Client, token string, baseUrl string, instanceURL string) *Client {
	return &Client{
		httpClient:  httpClient,
		token:       token,
		baseUrl:     baseUrl,
		instanceURL: instanceURL,
	}
}

// CreateBearerToken creates bearer token needed to use the Jamf API.
func CreateBearerToken(ctx context.Context, username string, password string, serverInstance string) (string, error) {
	httpClient, err := uhttp.NewClient(ctx, uhttp.WithLogger(true, ctxzap.Extract(ctx)))
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("%s/api/v1/auth/token", serverInstance)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Add("accept", "application/json")
	req.Header.Add("content-type", "application/json")
	req.SetBasicAuth(username, password)
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	var res struct {
		Token   string `json:"token"`
		Expires string `json:"expires"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", err
	}

	return res.Token, nil
}

// GetTokenDetails gets authorization details associated with the current api token.
func (c *Client) GetTokenDetails(ctx context.Context) (TokenDetails, error) {
	url := fmt.Sprintf("%s/api/v1/auth", c.instanceURL)

	var res TokenDetails
	if err := c.doRequest(ctx, url, &res); err != nil {
		return TokenDetails{}, err
	}

	return res, nil
}

func (c *Client) getBaseUsers(ctx context.Context) ([]BaseType, error) {
	usersUrl, err := url.JoinPath(c.baseUrl, "/users")
	if err != nil {
		return nil, err
	}

	var res struct {
		Users []BaseType `json:"users"`
	}

	if err := c.doRequest(ctx, usersUrl, &res); err != nil {
		return nil, err
	}

	return res.Users, nil
}

func (c *Client) getUserDetails(ctx context.Context, userId int) (User, error) {
	userIdString := strconv.Itoa(userId)
	usersUrl, err := url.JoinPath(c.baseUrl, "/users/id/", userIdString)
	if err != nil {
		return User{}, err
	}

	var res struct {
		User User `json:"user"`
	}

	if err := c.doRequest(ctx, usersUrl, &res); err != nil {
		return User{}, err
	}

	return res.User, nil
}

func (c *Client) getBaseAccounts(ctx context.Context) (BaseAccount, error) {
	accountsUrl, err := url.JoinPath(c.baseUrl, "/accounts")
	if err != nil {
		return BaseAccount{}, err
	}

	var res struct {
		Accounts BaseAccount `json:"accounts"`
	}

	if err := c.doRequest(ctx, accountsUrl, &res); err != nil {
		return BaseAccount{}, err
	}

	return res.Accounts, nil
}

// GetGroupDetails returns Jamf group details.
func (c *Client) GetGroupDetails(ctx context.Context, groupId int) (Group, error) {
	groupIdString := strconv.Itoa(groupId)
	usersUrl, err := url.JoinPath(c.baseUrl, "/accounts/groupid/", groupIdString)
	if err != nil {
		return Group{}, err
	}

	var res struct {
		Group Group `json:"group"`
	}

	if err := c.doRequest(ctx, usersUrl, &res); err != nil {
		return Group{}, err
	}

	return res.Group, nil
}

// GetUserAccountDetails returns Jamf user account details.
func (c *Client) GetUserAccountDetails(ctx context.Context, userId int) (UserAccount, error) {
	userIdString := strconv.Itoa(userId)
	usersUrl, err := url.JoinPath(c.baseUrl, "/accounts/userid/", userIdString)
	if err != nil {
		return UserAccount{}, err
	}

	var res struct {
		UserAccount UserAccount `json:"account"`
	}

	if err := c.doRequest(ctx, usersUrl, &res); err != nil {
		return UserAccount{}, err
	}

	return res.UserAccount, nil
}

// GetSites returns all Jamf sites.
func (c *Client) GetSites(ctx context.Context) ([]Site, error) {
	sitesUrl, err := url.JoinPath(c.baseUrl, "/sites")
	if err != nil {
		return nil, err
	}

	var res struct {
		Sites []Site `json:"sites"`
	}

	if err := c.doRequest(ctx, sitesUrl, &res); err != nil {
		return nil, err
	}

	return res.Sites, nil
}

func (c *Client) getBaseUserGroups(ctx context.Context) ([]UserGroup, error) {
	accountsUrl, err := url.JoinPath(c.baseUrl, "/usergroups")
	if err != nil {
		return nil, err
	}

	var res struct {
		UserGroups []UserGroup `json:"user_groups"`
	}

	if err := c.doRequest(ctx, accountsUrl, &res); err != nil {
		return nil, err
	}

	return res.UserGroups, nil
}

// GetUserGroupDetails returns Jamf user group details.
func (c *Client) GetUserGroupDetails(ctx context.Context, userGroupId int) (UserGroup, error) {
	groupIdString := strconv.Itoa(userGroupId)
	usersUrl, err := url.JoinPath(c.baseUrl, "/usergroups/id/", groupIdString)
	if err != nil {
		return UserGroup{}, err
	}

	var res struct {
		UserGroup UserGroup `json:"user_group"`
	}

	if err := c.doRequest(ctx, usersUrl, &res); err != nil {
		return UserGroup{}, err
	}

	return res.UserGroup, nil
}

// GetUsers returns all Jamf users.
func (c *Client) GetUsers(ctx context.Context) ([]User, error) {
	var users []User
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
func (c *Client) GetUserGroups(ctx context.Context) ([]UserGroup, error) {
	var userGroups []UserGroup
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

// GetUsers returns all Jamf accounts.
func (c *Client) GetAccounts(ctx context.Context) ([]UserAccount, []Group, error) {
	var userAccounts []UserAccount
	var groups []Group
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

func (c *Client) doRequest(ctx context.Context, url string, res interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", c.token))
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return err
	}

	return nil
}
