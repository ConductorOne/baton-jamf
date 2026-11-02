package connector

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/conductorone/baton-jamf/pkg/jamf"
	"github.com/conductorone/baton-sdk/pkg/session"
	"github.com/conductorone/baton-sdk/pkg/types/sessions"
)

const privilegeCatalogKey = "privilege_catalog"

var userIDsNamespace = sessions.WithPrefix("user_ids:")

var userGroupMembersNamespace = sessions.WithPrefix("user_group_members:")

// userGroupMemberPage is one grants page of a user group's member ids, sorted.
type userGroupMemberPage struct {
	UserIDs []int `json:"user_ids"`
	Last    bool  `json:"last"`
}

// privilegeCatalog returns the individual privileges Jamf offers, read once per sync.
func privilegeCatalog(ctx context.Context, store sessions.SessionStore, client *jamf.Client) ([]string, error) {
	catalog, found, err := session.GetJSON[[]string](ctx, store, privilegeCatalogKey)
	if err != nil {
		return nil, err
	}
	if found {
		return catalog, nil
	}

	response, err := client.GetPrivileges(ctx)
	if err != nil {
		return nil, err
	}
	if err := session.SetJSON(ctx, store, privilegeCatalogKey, response.Privileges); err != nil {
		return nil, err
	}
	return response.Privileges, nil
}

// cacheUserIDs stores each user's username and email -> user id.
func cacheUserIDs(ctx context.Context, store sessions.SessionStore, users []jamf.ProUser) error {
	userIDs := userIDsByLookupKey(users)

	// Pages come in id order, so a key an earlier page stored keeps its lower id.
	stored, err := cachedUserIDs(ctx, store, slices.Collect(maps.Keys(userIDs)))
	if err != nil {
		return err
	}
	for key := range stored {
		delete(userIDs, key)
	}

	return session.SetManyJSON(ctx, store, userIDs, userIDsNamespace)
}

// cachedUserIDs returns the cached user id of each key that has one.
func cachedUserIDs(ctx context.Context, store sessions.SessionStore, keys []string) (map[string]string, error) {
	return session.GetManyJSON[string](ctx, store, keys, userIDsNamespace)
}

// userIDsByLookupKey maps each user's username and email to the user id. Users come ordered by id, so the lowest wins.
func userIDsByLookupKey(users []jamf.ProUser) map[string]string {
	userIDs := make(map[string]string, len(users)*2)
	for _, user := range users {
		for _, value := range []string{user.Username, user.Email} {
			key := userLookupKey(value)
			if _, taken := userIDs[key]; key != "" && !taken {
				userIDs[key] = strconv.Itoa(user.ID)
			}
		}
	}
	return userIDs
}

// userLookupKey normalizes a username or email for the user id cache.
func userLookupKey(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// cacheUserGroupMemberPages stores a user group's member pages from page first on, one key per page.
func cacheUserGroupMemberPages(ctx context.Context, store sessions.SessionStore, userGroupID int, pages []userGroupMemberPage, first int) error {
	values := make(map[string]userGroupMemberPage, len(pages)-first)
	for page := first; page < len(pages); page++ {
		values[userGroupMemberPageKey(userGroupID, page)] = pages[page]
	}
	return session.SetManyJSON(ctx, store, values, userGroupMembersNamespace)
}

// cachedUserGroupMemberPage returns one stored member page of a user group.
func cachedUserGroupMemberPage(ctx context.Context, store sessions.SessionStore, userGroupID, page int) (userGroupMemberPage, bool, error) {
	return session.GetJSON[userGroupMemberPage](ctx, store, userGroupMemberPageKey(userGroupID, page), userGroupMembersNamespace)
}

func userGroupMemberPageKey(userGroupID, page int) string {
	return fmt.Sprintf("%d:%d", userGroupID, page)
}
