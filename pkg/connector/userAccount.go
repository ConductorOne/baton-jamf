package connector

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/conductorone/baton-jamf/pkg/jamf"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/crypto"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
)

type userAccountResourceType struct {
	resourceType *v2.ResourceType
	client       *jamf.Client
}

// Valid values Jamf accepts for an admin account's privilege_set. See
// https://developer.jamf.com/jamf-pro/reference/createaccountbyid.
const (
	privilegeSetAdministrator  = "Administrator"
	privilegeSetAuditor        = "Auditor"
	privilegeSetEnrollmentOnly = "Enrollment Only"
	privilegeSetCustom         = "Custom"
)

var knownPrivilegeSets = []string{privilegeSetAdministrator, privilegeSetAuditor, privilegeSetEnrollmentOnly, privilegeSetCustom}

func isKnownPrivilegeSet(privilegeSet string) bool {
	for _, p := range knownPrivilegeSets {
		if p == privilegeSet {
			return true
		}
	}
	return false
}

// The following profile fields only apply when privilege_set is "Custom" —
// they populate the Classic API's <privileges> block, which is what gives a
// Custom privilege_set its meaning (Jamf otherwise creates the account with
// no privileges at all). See
// https://developer.jamf.com/jamf-pro/reference/createaccountbyid.
const (
	profileFieldPrivilegesJSSObjects    = "privileges_jss_objects"
	profileFieldPrivilegesJSSSettings   = "privileges_jss_settings"
	profileFieldPrivilegesJSSActions    = "privileges_jss_actions"
	profileFieldPrivilegesRecon         = "privileges_recon"
	profileFieldPrivilegesCasperAdmin   = "privileges_casper_admin"
	profileFieldPrivilegesCasperRemote  = "privileges_casper_remote"
	profileFieldPrivilegesCasperImaging = "privileges_casper_imaging"
)

// customPrivilegeFields maps each profile field to the jamf.Privileges
// category it populates, in schema display order.
var customPrivilegeFields = []struct {
	field       string
	displayName string
}{
	{profileFieldPrivilegesJSSObjects, "Privileges: JSS Objects"},
	{profileFieldPrivilegesJSSSettings, "Privileges: JSS Settings"},
	{profileFieldPrivilegesJSSActions, "Privileges: JSS Actions"},
	{profileFieldPrivilegesRecon, "Privileges: Recon"},
	{profileFieldPrivilegesCasperAdmin, "Privileges: Casper Admin"},
	{profileFieldPrivilegesCasperRemote, "Privileges: Casper Remote"},
	{profileFieldPrivilegesCasperImaging, "Privileges: Casper Imaging"},
}

const (
	defaultAccessLevel  = "Full Access"
	defaultPrivilegeSet = privilegeSetAuditor

	// enabledValue is the Jamf Classic API's string representation of an
	// enabled account (as opposed to "Disabled").
	enabledValue = "Enabled"
)

func (o *userAccountResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

// Create a new connector resource for a Jamf user account.
func userAccountResource(account *jamf.UserAccount, parentResourceID *v2.ResourceId) (*v2.Resource, error) {
	firstName, lastName := rs.SplitFullName(account.Name)
	profile := map[string]interface{}{
		"first_name": firstName,
		"last_name":  lastName,
		"login":      account.Email,
		"user_id":    fmt.Sprintf("account:%d", account.ID),
	}

	var resourceStatus v2.Status_ResourceStatus
	if account.Enabled == enabledValue {
		resourceStatus = v2.Status_RESOURCE_STATUS_ENABLED
	} else {
		resourceStatus = v2.Status_RESOURCE_STATUS_DISABLED
	}

	userTraitOptions := []rs.UserTraitOption{
		rs.WithEmail(account.Email, true),
	}

	ret, err := rs.NewUserResource(
		account.Name,
		resourceTypeUserAccount,
		account.ID,
		userTraitOptions,
		rs.WithParentResourceID(parentResourceID),
		rs.WithResourceProfile(profile),
		rs.WithResourceStatus(resourceStatus, ""),
	)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func (o *userAccountResourceType) List(ctx context.Context, parentId *v2.ResourceId, attrs rs.SyncOpAttrs) ([]*v2.Resource, *rs.SyncOpResults, error) {
	userAccounts, _, err := o.client.GetAccounts(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("jamf-connector: failed to list accounts: %w", err)
	}

	var rv []*v2.Resource

	for _, user := range userAccounts {
		userCopy := user
		ur, err := userAccountResource(userCopy, parentId)
		if err != nil {
			return nil, nil, err
		}
		rv = append(rv, ur)
	}

	return rv, nil, nil
}

func (o *userAccountResourceType) Entitlements(_ context.Context, _ *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	return nil, nil, nil

	// TODO - access level entitlements & grants
}

func (o *userAccountResourceType) Grants(_ context.Context, _ *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	return nil, nil, nil
}

// userAccountCreationSchema declares the C1 UI form fields for creating a
// Jamf Pro console admin account. The login/username itself comes from
// AccountInfo.Login (a first-class field the C1 UI always collects), not from
// this profile map. Password is generated by C1 (see CreateAccountCapabilityDetails),
// not collected here.
func userAccountCreationSchema() *v2.ConnectorAccountCreationSchema {
	privilegeSetDescription := fmt.Sprintf(
		"The admin's privilege set. One of: %s. Defaults to %q. When %q, set at least one of the Privileges fields below.",
		strings.Join(knownPrivilegeSets, ", "), defaultPrivilegeSet, privilegeSetCustom,
	)

	fieldMap := map[string]*v2.ConnectorAccountCreationSchema_Field{
		profileFieldFullName: {
			DisplayName: "Full Name",
			Required:    false,
			Description: "The admin's full name.",
			Field: &v2.ConnectorAccountCreationSchema_Field_StringField{
				StringField: &v2.ConnectorAccountCreationSchema_StringField{},
			},
			Placeholder: "Jane Doe",
			Order:       1,
		},
		profileFieldEmail: {
			DisplayName: "Email",
			Required:    false,
			Description: "The admin's email address.",
			Field: &v2.ConnectorAccountCreationSchema_Field_StringField{
				StringField: &v2.ConnectorAccountCreationSchema_StringField{},
			},
			Placeholder: "jane.doe@example.com",
			Order:       2,
		},
		profileFieldPrivilegeSet: {
			DisplayName: "Privilege Set",
			Required:    false,
			Description: privilegeSetDescription,
			Field: &v2.ConnectorAccountCreationSchema_Field_StringField{
				StringField: &v2.ConnectorAccountCreationSchema_StringField{},
			},
			Placeholder: defaultPrivilegeSet,
			Order:       3,
		},
	}

	for i, cp := range customPrivilegeFields {
		fieldMap[cp.field] = &v2.ConnectorAccountCreationSchema_Field{
			DisplayName: cp.displayName,
			Required:    false,
			Description: fmt.Sprintf("Only used when Privilege Set is %q. List of privilege names to grant in this category.", privilegeSetCustom),
			Field: &v2.ConnectorAccountCreationSchema_Field_StringListField{
				StringListField: &v2.ConnectorAccountCreationSchema_StringListField{},
			},
			Order: int32(4 + i),
		}
	}

	return &v2.ConnectorAccountCreationSchema{FieldMap: fieldMap}
}

// provisionableUserAccountType adds account-creation capability on top of
// userAccountResourceType. It is only constructed — and therefore only
// satisfies the SDK's AccountManagerLimited interface — when the connector is
// configured with create-account-resource-type=userAccount (see
// Jamf.userAccountSyncer). See provisionableUserType for why this matters:
// registering CreateAccount unconditionally on both resource types would make
// the SDK see two account managers and default ambiguous CreateAccount calls
// to "user" regardless of config.
type provisionableUserAccountType struct {
	*userAccountResourceType
}

// CreateAccountCapabilityDetails is required alongside CreateAccount and
// Delete for the SDK to detect AccountManagerV2. Jamf console admin accounts
// require a password, so C1 generates one and returns it as plaintext data.
func (o *provisionableUserAccountType) CreateAccountCapabilityDetails(_ context.Context) (*v2.CredentialDetailsAccountProvisioning, annotations.Annotations, error) {
	return &v2.CredentialDetailsAccountProvisioning{
		SupportedCredentialOptions: []v2.CapabilityDetailCredentialOption{
			v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_RANDOM_PASSWORD,
		},
		PreferredCredentialOption: v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_RANDOM_PASSWORD,
	}, nil, nil
}

// CreateAccount creates a new Jamf Pro console admin account.
func (o *provisionableUserAccountType) CreateAccount(
	ctx context.Context,
	accountInfo *v2.AccountInfo,
	credentialOptions *v2.LocalCredentialOptions,
) (connectorbuilder.CreateAccountResponse, []*v2.PlaintextData, annotations.Annotations, error) {
	name, err := requireLogin(accountInfo)
	if err != nil {
		return nil, nil, nil, err
	}

	profileMap := accountInfo.GetProfile().AsMap()
	fullName, _ := profileMap[profileFieldFullName].(string)
	email, _ := profileMap[profileFieldEmail].(string)

	privilegeSet := defaultPrivilegeSet
	if raw, ok := profileMap[profileFieldPrivilegeSet].(string); ok && raw != "" {
		if !isKnownPrivilegeSet(raw) {
			return nil, nil, nil, fmt.Errorf("jamf-connector: unknown privilege_set %q (valid: %v)", raw, knownPrivilegeSets)
		}
		privilegeSet = raw
	}

	password, err := crypto.GeneratePassword(ctx, credentialOptions)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("jamf-connector: failed to generate random password: %w", err)
	}

	var privileges *jamf.Privileges
	if privilegeSet == privilegeSetCustom {
		privileges = &jamf.Privileges{
			JSSObjects:    stringSliceFromProfile(profileMap, profileFieldPrivilegesJSSObjects),
			JSSSettings:   stringSliceFromProfile(profileMap, profileFieldPrivilegesJSSSettings),
			JSSActions:    stringSliceFromProfile(profileMap, profileFieldPrivilegesJSSActions),
			Recon:         stringSliceFromProfile(profileMap, profileFieldPrivilegesRecon),
			CasperAdmin:   stringSliceFromProfile(profileMap, profileFieldPrivilegesCasperAdmin),
			CasperRemote:  stringSliceFromProfile(profileMap, profileFieldPrivilegesCasperRemote),
			CasperImaging: stringSliceFromProfile(profileMap, profileFieldPrivilegesCasperImaging),
		}
		if privileges.IsEmpty() {
			return nil, nil, nil, fmt.Errorf("jamf-connector: privilege_set is %q but no privileges were set — set at least one of the Privileges fields", privilegeSetCustom)
		}
	}

	// Step 1: attempt creation.
	err = o.client.CreateUserAccount(ctx, jamf.UserAccountCreateBody{
		Name:         name,
		Password:     password,
		FullName:     fullName,
		Email:        email,
		Enabled:      enabledValue,
		AccessLevel:  defaultAccessLevel,
		PrivilegeSet: privilegeSet,
		Privileges:   privileges,
	})
	alreadyExists := err != nil && jamf.IsAlreadyExistsError(err)
	if err != nil && !alreadyExists {
		return nil, nil, nil, fmt.Errorf("jamf-connector: create account %s: %w", name, err)
	}

	// Step 2: fetch the account, whether just created or already existing.
	fetched, err := o.client.GetUserAccountByName(ctx, name)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("jamf-connector: create account %s: fetch failed: %w", name, err)
	}

	resource, err := userAccountResource(fetched, nil)
	if err != nil {
		return nil, nil, nil, err
	}

	// Step 3: return the correct result type.
	if alreadyExists {
		return &v2.CreateAccountResponse_AlreadyExistsResult{Resource: resource}, nil, nil, nil
	}

	plaintextData := []*v2.PlaintextData{
		{
			Name:  "password",
			Bytes: []byte(password),
		},
	}
	return &v2.CreateAccountResponse_SuccessResult{Resource: resource}, plaintextData, nil, nil
}

// Delete removes a Jamf console admin account. Not gated by
// create-account-resource-type — deprovisioning works for both account types
// regardless of which one is configured for creation.
func (o *userAccountResourceType) Delete(ctx context.Context, resourceID *v2.ResourceId, _ *v2.ResourceId) (annotations.Annotations, error) {
	id, err := strconv.Atoi(resourceID.Resource)
	if err != nil {
		return nil, fmt.Errorf("jamf-connector: delete userAccount: invalid resource id %q: %w", resourceID.Resource, err)
	}

	err = o.client.DeleteUserAccount(ctx, id)
	if err != nil {
		if jamf.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("jamf-connector: delete userAccount %d: %w", id, err)
	}
	return nil, nil
}

func userAccountBuilder(client *jamf.Client) *userAccountResourceType {
	return &userAccountResourceType{
		resourceType: resourceTypeUserAccount,
		client:       client,
	}
}
