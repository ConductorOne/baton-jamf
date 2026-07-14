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

	// opts carries the runtime sync-resource-type selection. It is nil for the
	// zero-value builder used to emit capabilities/config metadata, and non-nil
	// for every real sync (see cli.ConnectorOpts, populated in New).
	opts *cli.ConnectorOpts

	// accountProvisioningTarget is the resource type ID ("user" or
	// "userAccount") that CreateAccount is allowed to create for this
	// connector instance. C1 only supports one creatable account type per
	// connector instance; Delete is not gated by this and works for both
	// types regardless of the configured target.
	accountProvisioningTarget string
}

func (j *Jamf) userProvisioningActive() bool {
	return j.accountProvisioningTarget == resourceTypeUser.Id
}

func (j *Jamf) userAccountProvisioningActive() bool {
	return j.accountProvisioningTarget == resourceTypeUserAccount.Id
}

func New(ctx context.Context, cc *cfg.Jamf, opts *cli.ConnectorOpts) (connectorbuilder.ConnectorBuilderV2, []connectorbuilder.Opt, error) {
	httpClient, err := uhttp.NewClient(ctx, uhttp.WithLogger(true, ctxzap.Extract(ctx)))
	if err != nil {
		return nil, nil, err
	}

	client := jamf.NewClient(
		uhttp.NewBaseHttpClient(httpClient),
		cc.Username,
		cc.Password,
		"",
		cc.InstanceUrl,
	)

	token, err := client.CreateBearerToken(ctx, cc.Username, cc.Password)
	if err != nil {
		return nil, nil, fmt.Errorf("jamf-connector: failed to get token: %w", err)
	}
	client.SetBearerToken(token)

	accountProvisioningTarget := cc.CreateAccountResourceType
	if accountProvisioningTarget == "" {
		accountProvisioningTarget = resourceTypeUser.Id
	}

	return &Jamf{client: client, opts: opts, accountProvisioningTarget: accountProvisioningTarget}, nil, nil
}

func (j *Jamf) Metadata(ctx context.Context) (*v2.ConnectorMetadata, error) {
	return &v2.ConnectorMetadata{
		DisplayName:           "Jamf",
		Description:           "Connector syncing groups, users, user accounts, user groups, sites, roles, and managed devices from Jamf Pro to Baton",
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
	syncers := []connectorbuilder.ResourceSyncerV2{
		userBuilder(j.client, j),
		groupBuilder(j.client),
		userAccountBuilder(j.client, j),
		userGroupBuilder(j.client),
		siteBuilder(j.client),
		roleBuilder(j.client),
	}

	// managedDevice is opt-in (see annotationsForManagedDeviceResourceType). The
	// SDK sync engine does not itself honor the OptInRequired annotation — with
	// no --sync-resource-types filter it syncs every advertised type
	// (pkg/sync/syncer.go SyncResourceTypes). To keep the type OFF by default for
	// local/CLI runs too, we only register the device syncer when the operator
	// has explicitly selected it. The type is still advertised (with
	// opt_in_required: true) whenever opts is absent, i.e. when the connector
	// emits capabilities metadata.
	if j.shouldSyncManagedDevice() {
		syncers = append(syncers, managedDeviceBuilder(j.client))
	}

	return syncers
}

// accountCreationSchema declares the C1 UI form fields for whichever account
// type is currently configured for creation (see accountProvisioningTarget).
func (j *Jamf) accountCreationSchema() *v2.ConnectorAccountCreationSchema {
	if j.userAccountProvisioningActive() {
		return userAccountCreationSchema()
	}
	return userCreationSchema()
}

// shouldSyncManagedDevice reports whether the opt-in managedDevice syncer should
// be registered for this run. Metadata generation (nil opts) always advertises
// it so baton_capabilities.json carries opt_in_required: true. A real sync
// registers it only when the resource-type filter explicitly names it, so an
// empty filter ("sync everything") leaves devices — and their Jamf "Read
// Computers" / "Read Mobile Devices" API calls — off.
func (j *Jamf) shouldSyncManagedDevice() bool {
	if j.opts == nil {
		return true
	}
	return j.opts.SyncFilterIsExplicit() && j.opts.WillSyncResourceType(resourceTypeManagedDevice.Id)
}
