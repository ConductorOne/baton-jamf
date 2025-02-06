package connector

import (
	"context"
	"fmt"
	"github.com/conductorone/baton-jamf/pkg/jamf"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"reflect"
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
)

type Jamf struct {
	client *jamf.Client
}

func New(ctx context.Context, username string, password string, instanceURL string) (*Jamf, error) {
	httpClient, err := uhttp.NewClient(ctx, uhttp.WithLogger(true, ctxzap.Extract(ctx)))
	if err != nil {
		return nil, err
	}

	client := jamf.NewClient(
		uhttp.NewBaseHttpClient(httpClient),
		username,
		password,
		"",
		instanceURL,
	)

	token, err := client.CreateBearerToken(ctx, username, password)
	if err != nil {
		return nil, fmt.Errorf("jamf-connector: failed to get token: %w", err)
	}
	client.SetBearerToken(token)

	return &Jamf{client: client}, nil
}

func (j *Jamf) Metadata(ctx context.Context) (*v2.ConnectorMetadata, error) {
	return &v2.ConnectorMetadata{
		DisplayName: "Jamf",
		Description: "Connector syncing groups, users, user accounts, user groups, sites, and roles from Jamf Pro to Baton",
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

func (j *Jamf) ResourceSyncers(ctx context.Context) []connectorbuilder.ResourceSyncer {
	return []connectorbuilder.ResourceSyncer{
		userBuilder(j.client),
		groupBuilder(j.client),
		userAccountBuilder(j.client),
		userGroupBuilder(j.client),
		siteBuilder(j.client),
		roleBuilder(j.client),
	}
}
