package connector

import (
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
)

var (
	resourceTypeUser = &v2.ResourceType{
		Id:          "user",
		DisplayName: "User",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_USER,
		},
		Annotations: annotations.New(&v2.SkipEntitlementsAndGrants{}),
	}
	resourceTypeGroup = &v2.ResourceType{
		Id:          "group",
		DisplayName: "Group",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_GROUP,
		},
		Annotations: annotations.New(&v2.SkipEntitlements{}),
	}
	resourceTypeUserAccount = &v2.ResourceType{
		Id:          "userAccount",
		DisplayName: "User Account",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_USER,
		},
		Annotations: annotations.New(&v2.SkipEntitlementsAndGrants{}),
	}
	resourceTypeSite = &v2.ResourceType{
		Id:          "site",
		DisplayName: "Site",
		Annotations: annotations.New(&v2.SkipEntitlements{}),
	}
	resourceTypeUserGroup = &v2.ResourceType{
		Id:          "userGroup",
		DisplayName: "User Group",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_GROUP,
		},
		Annotations: annotations.New(&v2.SkipEntitlements{}),
	}
	resourceTypeRole = &v2.ResourceType{
		Id:          "role",
		DisplayName: "Role",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_ROLE,
		},
		Annotations: annotations.New(&v2.SkipEntitlements{}, &v2.TypeScopedGrants{}),
	}
	resourceTypeManagedDevice = &v2.ResourceType{
		Id:          "managedDevice",
		DisplayName: "Managed Device",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_MANAGED_DEVICE,
		},
		// Opt-in: existing API roles may lack Read Computers and Read Mobile Devices.
		Annotations: annotations.New(&v2.OptInRequired{}),
	}
)
