package connector

import (
	"context"
	"fmt"
	"strings"

	"github.com/ConductorOne/baton-jamf/pkg/jamf"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
)

type userAccountResourceType struct {
	resourceType *v2.ResourceType
	client       *jamf.Client
}

func (o *userAccountResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

// Create a new connector resource for a Jamf user account.
func userAccountResource(account *jamf.UserAccount, parentResourceID *v2.ResourceId) (*v2.Resource, error) {
	names := strings.SplitN(account.Name, " ", 2)
	var firstName, lastName string

	switch len(names) {
	case 1:
		firstName = names[0]
	case 2:
		firstName = names[0]
		lastName = names[1]
	}

	profile := map[string]interface{}{
		"first_name": firstName,
		"last_name":  lastName,
		"login":      account.Email,
		"user_id":    fmt.Sprintf("account:%d", account.ID),
	}

	var userStatus v2.UserTrait_Status_Status
	if account.Enabled == "Enabled" {
		userStatus = v2.UserTrait_Status_STATUS_ENABLED
	} else {
		userStatus = v2.UserTrait_Status_STATUS_DISABLED
	}

	userTraitOptions := []rs.UserTraitOption{
		rs.WithUserProfile(profile),
		rs.WithEmail(account.Email, true),
		rs.WithStatus(userStatus),
	}

	ret, err := rs.NewUserResource(
		account.Name,
		resourceTypeUserAccount,
		account.ID,
		userTraitOptions,
		rs.WithParentResourceID(parentResourceID),
	)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func (o *userAccountResourceType) List(ctx context.Context, parentId *v2.ResourceId, token *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	userAccounts, _, err := o.client.GetAccounts(ctx)
	if err != nil {
		return nil, "", nil, fmt.Errorf("jamf-connector: failed to list accounts: %w", err)
	}

	var rv []*v2.Resource

	for _, user := range userAccounts {
		userCopy := user
		ur, err := userAccountResource(&userCopy, parentId)
		if err != nil {
			return nil, "", nil, err
		}
		rv = append(rv, ur)
	}

	return rv, "", nil, nil
}

func (o *userAccountResourceType) Entitlements(_ context.Context, _ *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	return nil, "", nil, nil

	// TODO - access level entitlements & grants
}

func (o *userAccountResourceType) Grants(_ context.Context, _ *v2.Resource, _ *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func userAccountBuilder(client *jamf.Client) *userAccountResourceType {
	return &userAccountResourceType{
		resourceType: resourceTypeUserAccount,
		client:       client,
	}
}
