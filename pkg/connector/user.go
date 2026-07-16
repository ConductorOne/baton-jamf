package connector

import (
	"context"
	"fmt"
	"strconv"

	"github.com/conductorone/baton-jamf/pkg/jamf"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
)

type userResourceType struct {
	resourceType *v2.ResourceType
	client       *jamf.Client
}

// Account-creation profile field names, shared between the "user" and
// "userAccount" creation schemas.
const (
	profileFieldFullName     = "full_name"
	profileFieldEmail        = "email"
	profileFieldPrivilegeSet = "privilege_set"
)

func (o *userResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

// requireLogin returns AccountInfo.Login, or an error if it's empty. Shared
// between userResourceType.CreateAccount and userAccountResourceType.CreateAccount.
func requireLogin(accountInfo *v2.AccountInfo) (string, error) {
	name := accountInfo.GetLogin()
	if name == "" {
		return "", fmt.Errorf("jamf-connector: create account: login is required")
	}
	return name, nil
}

// Create a new connector resource for a Jamf user.
func userResource(user *jamf.User, parentResourceID *v2.ResourceId) (*v2.Resource, error) {
	firstName, lastName := rs.SplitFullName(user.FullName)
	profile := map[string]interface{}{
		"first_name":         firstName,
		"last_name":          lastName,
		"login":              user.Email,
		"user_id":            fmt.Sprintf("user:%d", user.ID),
		"name":               user.Name,
		profileFieldFullName: user.FullName,
	}

	userTraitOptions := []rs.UserTraitOption{
		rs.WithUserProfile(profile),
		rs.WithEmail(user.Email, true),
		rs.WithStatus(v2.UserTrait_Status_STATUS_ENABLED),
	}

	ret, err := rs.NewUserResource(
		user.FullName,
		resourceTypeUser,
		user.ID,
		userTraitOptions,
		rs.WithParentResourceID(parentResourceID),
	)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func (o *userResourceType) List(ctx context.Context, parentId *v2.ResourceId, attrs rs.SyncOpAttrs) ([]*v2.Resource, *rs.SyncOpResults, error) {
	users, err := o.client.GetUsers(ctx)
	if err != nil {
		return nil, nil, err
	}

	var rv []*v2.Resource
	for _, baseUser := range users {
		baseUserCopy := baseUser
		ur, err := userResource(baseUserCopy, parentId)
		if err != nil {
			return nil, nil, err
		}
		rv = append(rv, ur)
	}

	return rv, nil, nil
}

func (o *userResourceType) Entitlements(_ context.Context, _ *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	return nil, nil, nil
}

func (o *userResourceType) Grants(_ context.Context, _ *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	return nil, nil, nil
}

// userCreationSchema declares the C1 UI form fields for creating a Jamf
// directory user. The login/username itself comes from AccountInfo.Login
// (a first-class field the C1 UI always collects), not from this profile map.
func userCreationSchema() *v2.ConnectorAccountCreationSchema {
	return &v2.ConnectorAccountCreationSchema{
		FieldMap: map[string]*v2.ConnectorAccountCreationSchema_Field{
			profileFieldFullName: {
				DisplayName: "Full Name",
				Required:    false,
				Description: "The user's full name.",
				Field: &v2.ConnectorAccountCreationSchema_Field_StringField{
					StringField: &v2.ConnectorAccountCreationSchema_StringField{},
				},
				Placeholder: "Jane Doe",
				Order:       1,
			},
			profileFieldEmail: {
				DisplayName: "Email",
				Required:    false,
				Description: "The user's email address.",
				Field: &v2.ConnectorAccountCreationSchema_Field_StringField{
					StringField: &v2.ConnectorAccountCreationSchema_StringField{},
				},
				Placeholder: "jane.doe@example.com",
				Order:       2,
			},
		},
	}
}

// provisionableUserType adds account-creation capability on top of
// userResourceType. It is only constructed — and therefore only satisfies the
// SDK's AccountManagerLimited interface — when the connector is configured
// with create-account-resource-type=user (see Jamf.userSyncer). Registering
// CreateAccount unconditionally on both "user" and "userAccount" would make
// the SDK see two account managers at once; when a CreateAccount request
// omits resource_type_id, the SDK then defaults to "user" regardless of
// config, and getCredentialDetails picks an arbitrary one of the two
// registered managers' credential options. Only ever registering the
// currently-active target as an account manager avoids both.
type provisionableUserType struct {
	*userResourceType
}

// CreateAccountCapabilityDetails is required alongside CreateAccount and
// Delete for the SDK to detect AccountManagerV2. Jamf directory users have no
// login credential of their own (they're directory metadata, not console
// logins), so no password option applies.
func (o *provisionableUserType) CreateAccountCapabilityDetails(_ context.Context) (*v2.CredentialDetailsAccountProvisioning, annotations.Annotations, error) {
	return &v2.CredentialDetailsAccountProvisioning{
		SupportedCredentialOptions: []v2.CapabilityDetailCredentialOption{
			v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_NO_PASSWORD,
		},
		PreferredCredentialOption: v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_NO_PASSWORD,
	}, nil, nil
}

// CreateAccount creates a new Jamf directory user.
func (o *provisionableUserType) CreateAccount(
	ctx context.Context,
	accountInfo *v2.AccountInfo,
	_ *v2.LocalCredentialOptions,
) (connectorbuilder.CreateAccountResponse, []*v2.PlaintextData, annotations.Annotations, error) {
	name, err := requireLogin(accountInfo)
	if err != nil {
		return nil, nil, nil, err
	}

	profileMap := accountInfo.GetProfile().AsMap()
	fullName, _ := profileMap[profileFieldFullName].(string)
	email, _ := profileMap[profileFieldEmail].(string)

	// Step 1: attempt creation.
	err = o.client.CreateUser(ctx, name, fullName, email)
	alreadyExists := err != nil && jamf.IsAlreadyExistsError(err)
	if err != nil && !alreadyExists {
		return nil, nil, nil, fmt.Errorf("jamf-connector: create account %s: %w", name, err)
	}

	// Step 2: fetch the user, whether just created or already existing.
	fetched, err := o.client.GetUserByName(ctx, name)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("jamf-connector: create account %s: fetch failed: %w", name, err)
	}

	resource, err := userResource(fetched, nil)
	if err != nil {
		return nil, nil, nil, err
	}

	// Step 3: return the correct result type.
	if alreadyExists {
		return &v2.CreateAccountResponse_AlreadyExistsResult{Resource: resource}, nil, nil, nil
	}
	return &v2.CreateAccountResponse_SuccessResult{Resource: resource}, nil, nil, nil
}

// Delete removes a Jamf directory user. Not gated by create-account-resource-type —
// deprovisioning works for both account types regardless of which one is
// configured for creation.
func (o *userResourceType) Delete(ctx context.Context, resourceID *v2.ResourceId, _ *v2.ResourceId) (annotations.Annotations, error) {
	id, err := strconv.Atoi(resourceID.Resource)
	if err != nil {
		return nil, fmt.Errorf("jamf-connector: delete user: invalid resource id %q: %w", resourceID.Resource, err)
	}

	err = o.client.DeleteUser(ctx, id)
	if err != nil {
		if jamf.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("jamf-connector: delete user %d: %w", id, err)
	}
	return nil, nil
}

func userBuilder(client *jamf.Client) *userResourceType {
	return &userResourceType{
		resourceType: resourceTypeUser,
		client:       client,
	}
}
