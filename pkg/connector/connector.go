package connector

import (
	"context"
	"fmt"
	"reflect"

	cfg "github.com/conductorone/baton-jamf/pkg/config"
	"github.com/conductorone/baton-jamf/pkg/jamf"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/cli"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"golang.org/x/oauth2"
)

var (
	resourceTypeUser = &v2.ResourceType{
		Id:          "user",
		DisplayName: "User",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_USER,
		},
		Annotations: annotationsForUserResourceType(),
	}
	resourceTypeGroup = &v2.ResourceType{
		Id:          "group",
		DisplayName: "Group",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_GROUP,
		},
	}
	resourceTypeUserAccount = &v2.ResourceType{
		Id:          "userAccount",
		DisplayName: "User Account",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_USER,
		},
		Annotations: annotationsForUserResourceType(),
	}
	resourceTypeSite = &v2.ResourceType{
		Id:          "site",
		DisplayName: "Site",
	}
	resourceTypeUserGroup = &v2.ResourceType{
		Id:          "userGroup",
		DisplayName: "User Group",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_GROUP,
		},
	}
	resourceTypeRole = &v2.ResourceType{
		Id:          "role",
		DisplayName: "Role",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_ROLE,
		},
	}
	resourceTypeManagedDevice = &v2.ResourceType{
		Id:          "managedDevice",
		DisplayName: "Managed Device",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_MANAGED_DEVICE,
		},
		Annotations: annotationsForManagedDeviceResourceType(),
	}
)

type Jamf struct {
	client *jamf.Client

	// accountProvisioningTarget is the resource type ID ("user" or
	// "userAccount") that CreateAccount is allowed to create for this
	// connector instance. C1 only supports one creatable account type per
	// connector instance; Delete is not gated by this and works for both
	// types regardless of the configured target.
	accountProvisioningTarget string
}

// userProvisioningActive treats an empty accountProvisioningTarget as "user"
// (the documented default), so the zero-value *Jamf{} used for capabilities
// generation (main.go, bypassing New()) resolves the same default New()
// would apply from an empty config value.
func (j *Jamf) userProvisioningActive() bool {
	return j.accountProvisioningTarget == "" || j.accountProvisioningTarget == resourceTypeUser.Id
}

func (j *Jamf) userAccountProvisioningActive() bool {
	return j.accountProvisioningTarget == resourceTypeUserAccount.Id
}

func New(ctx context.Context, cc *cfg.Jamf, opts *cli.ConnectorOpts) (connectorbuilder.ConnectorBuilderV2, []connectorbuilder.Opt, error) {
	httpClient, err := uhttp.NewClient(ctx, uhttp.WithLogger(true, ctxzap.Extract(ctx)))
	if err != nil {
		return nil, nil, err
	}

	wrapper := uhttp.NewBaseHttpClient(httpClient)

	var tokenSource oauth2.TokenSource
	switch opts.SelectedAuthMethod {
	case cfg.APIClientGroup:
		tokenSource, err = jamf.NewAPIClientTokenSource(wrapper, cc.InstanceUrl, cc.JamfClientId, cc.JamfClientSecret)
	default:
		tokenSource, err = jamf.NewBasicTokenSource(wrapper, cc.InstanceUrl, cc.Username, cc.Password)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("jamf-connector: failed to create token source: %w", err)
	}

	client, err := jamf.NewClient(wrapper, cc.InstanceUrl, tokenSource)
	if err != nil {
		return nil, nil, fmt.Errorf("jamf-connector: failed to create client: %w", err)
	}
	accountProvisioningTarget := cc.CreateAccountResourceType
	if accountProvisioningTarget == "" {
		accountProvisioningTarget = resourceTypeUser.Id
	}

	return &Jamf{client: client, accountProvisioningTarget: accountProvisioningTarget}, nil, nil
}

func (j *Jamf) Metadata(ctx context.Context) (*v2.ConnectorMetadata, error) {
	return &v2.ConnectorMetadata{
		DisplayName: "Jamf",
		Description: "Connector syncing groups, users, user accounts, user groups, sites, roles, and managed devices from Jamf Pro to Baton, " +
			"with Grant/Revoke for groups, user groups, roles, sites and managed devices, and account provisioning (create/delete) for users and user accounts",
		AccountCreationSchema: j.accountCreationSchema(),
	}, nil
}

func (j *Jamf) Validate(ctx context.Context) (annotations.Annotations, error) {
	tokenDetails, err := j.client.GetTokenDetails(ctx)
	if err != nil {
		return nil, fmt.Errorf("jamf-connector: error fetching token details: %w", err)
	}

	if reflect.ValueOf(tokenDetails).IsZero() {
		return nil, fmt.Errorf("jamf-connector: missing token details")
	}
	return nil, nil
}

func (j *Jamf) ResourceSyncers(ctx context.Context) []connectorbuilder.ResourceSyncerV2 {
	return []connectorbuilder.ResourceSyncerV2{
		j.userSyncer(),
		groupBuilder(j.client),
		j.userAccountSyncer(),
		userGroupBuilder(j.client),
		siteBuilder(j.client),
		roleBuilder(j.client),
		managedDeviceBuilder(j.client),
	}
}

// accountCreationSchema declares the C1 UI form fields for whichever account
// type is currently configured for creation (see accountProvisioningTarget).
func (j *Jamf) accountCreationSchema() *v2.ConnectorAccountCreationSchema {
	if j.userAccountProvisioningActive() {
		return userAccountCreationSchema()
	}
	return userCreationSchema()
}

// userSyncer returns the "user" resource syncer, wrapped with account-creation
// capability only when create-account-resource-type targets "user". See
// provisionableUserType for why only ever registering one target as an
// AccountManagerV2 matters.
func (j *Jamf) userSyncer() connectorbuilder.ResourceSyncerV2 {
	base := userBuilder(j.client)
	if j.userProvisioningActive() {
		return &provisionableUserType{base}
	}
	return base
}

// userAccountSyncer returns the "userAccount" resource syncer, wrapped with
// account-creation capability only when create-account-resource-type targets
// "userAccount". See provisionableUserType for why only ever registering one
// target as an AccountManagerV2 matters.
func (j *Jamf) userAccountSyncer() connectorbuilder.ResourceSyncerV2 {
	base := userAccountBuilder(j.client)
	if j.userAccountProvisioningActive() {
		return &provisionableUserAccountType{base}
	}
	return base
}
