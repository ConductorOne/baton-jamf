package connector

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/conductorone/baton-jamf/pkg/jamf"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/session"
	"github.com/conductorone/baton-sdk/pkg/types/sessions"
)

const privilegeCatalogKey = "privilege_catalog"

var userIDsNamespace = sessions.WithPrefix("user_ids:")

var userGroupMembersNamespace = sessions.WithPrefix("user_group_members:")

var groupDetailsNamespace = sessions.WithPrefix("group_details:")

// userGroupMemberPage is one grants page of a user group's member ids, sorted.
type userGroupMemberPage struct {
	UserIDs []int `json:"user_ids"`
	Last    bool  `json:"last"`
}

// privilegeCatalog returns the individual privileges Jamf offers, read once per sync.
func privilegeCatalog(ctx context.Context, store sessions.SessionStore, client *jamf.Client) ([]string, annotations.Annotations, error) {
	catalog, found, err := session.GetJSON[[]string](ctx, store, privilegeCatalogKey)
	if err != nil {
		return nil, nil, err
	}
	if found {
		return catalog, nil, nil
	}

	response, annos, err := client.GetPrivileges(ctx)
	if err != nil {
		return nil, nil, err
	}
	if err := session.SetJSON(ctx, store, privilegeCatalogKey, response.Privileges); err != nil {
		return nil, nil, err
	}
	return response.Privileges, annos, nil
}

// privilegeCatalogSet returns the privilege catalog as a set, for checking a Custom account's or group's privileges.
func privilegeCatalogSet(ctx context.Context, store sessions.SessionStore, client *jamf.Client) (map[string]struct{}, error) {
	privileges, _, err := privilegeCatalog(ctx, store, client)
	if err != nil {
		return nil, err
	}
	catalog := make(map[string]struct{}, len(privileges))
	for _, privilege := range privileges {
		catalog[privilege] = struct{}{}
	}
	return catalog, nil
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

// cacheUserGroupMemberPages stores each page after the first under its cursor, the last user id of the page before.
func cacheUserGroupMemberPages(ctx context.Context, store sessions.SessionStore, userGroupID int, pages []userGroupMemberPage) error {
	values := make(map[string]userGroupMemberPage, len(pages)-1)
	for i := 1; i < len(pages); i++ {
		previousIDs := pages[i-1].UserIDs
		values[userGroupMemberPageKey(userGroupID, previousIDs[len(previousIDs)-1])] = pages[i]
	}
	return session.SetManyJSON(ctx, store, values, userGroupMembersNamespace)
}

// cachedUserGroupMemberPage returns the stored member page of a user group that follows cursor.
func cachedUserGroupMemberPage(ctx context.Context, store sessions.SessionStore, userGroupID, cursor int) (userGroupMemberPage, bool, error) {
	return session.GetJSON[userGroupMemberPage](ctx, store, userGroupMemberPageKey(userGroupID, cursor), userGroupMembersNamespace)
}

func userGroupMemberPageKey(userGroupID, cursor int) string {
	return fmt.Sprintf("%d:%d", userGroupID, cursor)
}

// cacheGroupDetails stores an admin group's detail for its later grants pages.
func cacheGroupDetails(ctx context.Context, store sessions.SessionStore, groupID int, group *jamf.Group) error {
	return session.SetJSON(ctx, store, strconv.Itoa(groupID), group, groupDetailsNamespace)
}

// cachedGroupDetails returns the stored detail of an admin group.
func cachedGroupDetails(ctx context.Context, store sessions.SessionStore, groupID int) (jamf.Group, bool, error) {
	return session.GetJSON[jamf.Group](ctx, store, strconv.Itoa(groupID), groupDetailsNamespace)
}
