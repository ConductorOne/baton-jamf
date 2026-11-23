package connector

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/conductorone/baton-jamf/pkg/jamf"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/conductorone/baton-sdk/pkg/types/sessions"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// Phases of the device walk, kept in the pagination bag: computers, then mobile devices.
	devicePhaseComputer = "computer"
	devicePhaseMobile   = "mobile"

	// devicePageSize is Jamf's documented default page-size for both device lists; no maximum is documented.
	devicePageSize = 100

	// deviceGrantsPageSize is larger because the grants pass reads small records (computers bring only USER_AND_LOCATION).
	// No maximum is documented; Jamf honored 1000 and 2000 on both device lists.
	deviceGrantsPageSize = 1000

	// assignedEntitlement links a device to the user it is assigned to.
	assignedEntitlement = "assigned"

	// ExternalResourceMatch key names used when a device's assignee can't be
	// resolved to a synced Jamf user.
	matchKeyEmail    = "email"
	matchKeyUsername = "username"
)

// assignee is a device assignee's identity, independent of the jamf
// package's request/response body shapes. Matching only uses username and
// email; realname, position and phone are only written by a computer Grant.
type assignee struct {
	username string
	email    string
	realname string
	position string
	phone    string
}

// empty treats whitespace-only values as blank: no principal can be built from them.
func (a assignee) empty() bool {
	return strings.TrimSpace(a.username) == "" && strings.TrimSpace(a.email) == ""
}

// matches reports whether a and other identify the same assignee. Usernames
// are compared only when BOTH sides carry one; whenever either side has no
// username (one side is unassigned, or an unsynced assignee matched by
// email alone — see deviceGrants), this falls back to comparing emails
// instead. Jamf never auto-populates a computer's email when its username
// changes, so mixing the two could let Revoke clear a different, live
// assignee's data — hence the comparison never crosses from one field to
// the other when both sides do have a username.
func (a assignee) matches(other assignee) bool {
	username := strings.TrimSpace(a.username)
	otherUsername := strings.TrimSpace(other.username)
	if username != "" && otherUsername != "" {
		return strings.EqualFold(username, otherUsername)
	}

	email := strings.TrimSpace(a.email)
	otherEmail := strings.TrimSpace(other.email)
	return email != "" && otherEmail != "" && strings.EqualFold(email, otherEmail)
}

type managedDeviceResourceType struct {
	resourceType *v2.ResourceType
	client       *jamf.Client

	// Without a user sync the session store holds no user ids to resolve assignees against.
	syncUsers bool
}

var _ connectorbuilder.TypeScopedGrantsSyncer = (*managedDeviceResourceType)(nil)

func (d *managedDeviceResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return d.resourceType
}

func (d *managedDeviceResourceType) List(ctx context.Context, parentId *v2.ResourceId, attrs rs.SyncOpAttrs) ([]*v2.Resource, *rs.SyncOpResults, error) {
	bag := &pagination.Bag{}
	if err := bag.Unmarshal(attrs.PageToken.Token); err != nil {
		return nil, nil, fmt.Errorf("jamf-connector: parse device page token: %w", err)
	}
	if bag.Current() == nil {
		bag.Push(pagination.PageState{ResourceTypeID: devicePhaseMobile})
		bag.Push(pagination.PageState{ResourceTypeID: devicePhaseComputer})
	}

	phase := bag.Current()
	var resources []*v2.Resource
	var nextPage string
	var annos annotations.Annotations
	switch phase.ResourceTypeID {
	case devicePhaseComputer:
		computers, next, pageAnnos, err := d.client.GetComputersInventory(ctx, phase.Token, devicePageSize, jamf.ComputerInventorySections)
		if err != nil {
			return nil, nil, fmt.Errorf("jamf-connector: list computers: %w", err)
		}
		for _, computer := range computers {
			resource, err := computerResource(&computer, parentId)
			if err != nil {
				return nil, nil, fmt.Errorf("jamf-connector: build computer resource: %w", err)
			}
			resources = append(resources, resource)
		}
		nextPage, annos = next, pageAnnos

	case devicePhaseMobile:
		devices, next, pageAnnos, err := d.client.GetMobileDevices(ctx, phase.Token, devicePageSize)
		if err != nil {
			return nil, nil, fmt.Errorf("jamf-connector: list mobile devices: %w", err)
		}
		for _, device := range devices {
			resource, err := mobileDeviceResource(&device, parentId)
			if err != nil {
				return nil, nil, fmt.Errorf("jamf-connector: build mobile device resource: %w", err)
			}
			resources = append(resources, resource)
		}
		nextPage, annos = next, pageAnnos

	default:
		return nil, nil, fmt.Errorf("jamf-connector: unknown device phase %q", phase.ResourceTypeID)
	}

	nextToken, err := bag.NextToken(nextPage)
	if err != nil {
		return nil, nil, fmt.Errorf("jamf-connector: build device page token: %w", err)
	}
	return resources, &rs.SyncOpResults{NextPageToken: nextToken, Annotations: annos}, nil
}

// Entitlements is unused: StaticEntitlements declares the assigned entitlement.
func (d *managedDeviceResourceType) Entitlements(_ context.Context, _ *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	return nil, nil, nil
}

// StaticEntitlements declares the assigned entitlement on every device, so an unassigned device can be granted one too.
func (d *managedDeviceResourceType) StaticEntitlements(_ context.Context, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	return []*v2.Entitlement{
		ent.NewAssignmentEntitlement(nil, assignedEntitlement,
			ent.WithGrantableTo(resourceTypeUser),
			ent.WithDisplayName("Assigned user"),
			ent.WithDescription("Assigned user of the device. Granting it to a new user replaces the current assignee."),
		),
	}, nil, nil
}

// Grants is unused: GrantsForResourceType emits the assigned grants.
func (d *managedDeviceResourceType) Grants(_ context.Context, _ *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	return nil, nil, nil
}

// GrantsForResourceType walks the devices again, computers with only their assignee section, 1000 devices per page,
// and resolves each page's assignees with one GetManyJSON (the SDK sends 100 keys per request).
func (d *managedDeviceResourceType) GrantsForResourceType(ctx context.Context, _ string, attrs rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	bag := &pagination.Bag{}
	if err := bag.Unmarshal(attrs.PageToken.Token); err != nil {
		return nil, nil, fmt.Errorf("jamf-connector: parse device grants page token: %w", err)
	}
	if bag.Current() == nil {
		bag.Push(pagination.PageState{ResourceTypeID: devicePhaseMobile})
		bag.Push(pagination.PageState{ResourceTypeID: devicePhaseComputer})
	}

	phase := bag.Current()
	owners := make(map[string]assignee, deviceGrantsPageSize)
	var nextPage string
	var annos annotations.Annotations
	switch phase.ResourceTypeID {
	case devicePhaseComputer:
		computers, next, pageAnnos, err := d.client.GetComputersInventory(ctx, phase.Token, deviceGrantsPageSize, jamf.ComputerAssigneeSections)
		if err != nil {
			return nil, nil, fmt.Errorf("jamf-connector: list computer owners: %w", err)
		}
		for _, computer := range computers {
			if computer.UserAndLocation != nil {
				owners[deviceObjectID(devicePhaseComputer, computer.ID)] = assignee{
					username: computer.UserAndLocation.Username,
					email:    computer.UserAndLocation.EmailAddr(),
				}
			}
		}
		nextPage, annos = next, pageAnnos

	case devicePhaseMobile:
		devices, next, pageAnnos, err := d.client.GetMobileDevices(ctx, phase.Token, deviceGrantsPageSize)
		if err != nil {
			return nil, nil, fmt.Errorf("jamf-connector: list mobile device owners: %w", err)
		}
		for _, device := range devices {
			// The list carries only the username.
			owners[deviceObjectID(devicePhaseMobile, device.ID)] = assignee{username: device.Username}
		}
		nextPage, annos = next, pageAnnos

	default:
		return nil, nil, fmt.Errorf("jamf-connector: unknown device phase %q", phase.ResourceTypeID)
	}

	grants, err := d.ownerGrants(ctx, attrs.Session, owners)
	if err != nil {
		return nil, nil, fmt.Errorf("jamf-connector: grant devices to their owners: %w", err)
	}

	nextToken, err := bag.NextToken(nextPage)
	if err != nil {
		return nil, nil, fmt.Errorf("jamf-connector: build device grants page token: %w", err)
	}
	return grants, &rs.SyncOpResults{NextPageToken: nextToken, Annotations: annos}, nil
}

// ownerGrants grants each device to its owner, resolving the owners to synced users with one GetManyJSON.
func (d *managedDeviceResourceType) ownerGrants(ctx context.Context, store sessions.SessionStore, owners map[string]assignee) ([]*v2.Grant, error) {
	var userIndex map[string]*v2.ResourceId
	if d.syncUsers {
		lookupKeys := make([]string, 0, len(owners)*2)
		for _, owner := range owners {
			lookupKeys = append(lookupKeys, assigneeLookupKeys(owner)...)
		}
		slices.Sort(lookupKeys)

		userIDs, err := cachedUserIDs(ctx, store, slices.Compact(lookupKeys))
		if err != nil {
			return nil, err
		}
		userIndex = userResourceIDs(userIDs)
	}

	grants := make([]*v2.Grant, 0, len(owners))
	for deviceID, owner := range owners {
		deviceResource := &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeManagedDevice.Id, Resource: deviceID}}
		assignedGrants, err := deviceGrants(deviceResource, owner, userIndex)
		if err != nil {
			return nil, err
		}
		grants = append(grants, assignedGrants...)
	}
	return grants, nil
}

// Grant sets principal (a Jamf user) as the assigned user of the device
// backing entitlement's resource. If principal is already the current
// assignee it is a no-op reported as GrantAlreadyExists, without a PATCH.
// A different current assignee is overwritten; that user's grant drops on the next sync.
func (d *managedDeviceResourceType) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) ([]*v2.Grant, annotations.Annotations, error) {
	ctx = jamf.WithFreshReads(ctx)

	if err := requirePrincipalType(principal.Id.ResourceType, resourceTypeUser, "device assignment", "granted to users"); err != nil {
		return nil, nil, err
	}

	newAssignee, err := resolvePrincipalUser(ctx, d.client, principal)
	if err != nil {
		return nil, nil, fmt.Errorf("jamf-connector: grant device assigned: resolve principal identity: %w", err)
	}
	if strings.TrimSpace(newAssignee.username) == "" {
		return nil, nil, status.Errorf(codes.FailedPrecondition, "jamf-connector: jamf user %s has no username", principal.Id.Resource)
	}

	current, annos, err := d.currentAssignedUser(ctx, entitlement.Resource)
	if err != nil {
		if jamf.IsNotFoundError(err) {
			return nil, nil, status.Errorf(codes.NotFound, "jamf-connector: grant device assigned: device %q not found", entitlement.Resource.Id.Resource)
		}
		return nil, nil, fmt.Errorf("jamf-connector: grant device assigned: %w", err)
	}

	newGrant := grant.NewGrant(entitlement.Resource, assignedEntitlement, principal.Id)

	if current.matches(newAssignee) {
		// principal is already the live assignee — nothing would be displaced,
		// and re-sending the same PATCH would only churn Jamf's audit log.
		annos.Update(&v2.GrantAlreadyExists{})
		return nil, annos, nil
	}

	annos, err = d.setAssignedUser(ctx, entitlement.Resource, newAssignee)
	if err != nil {
		return nil, nil, fmt.Errorf("jamf-connector: grant device assigned: %w", err)
	}

	return []*v2.Grant{newGrant}, annos, nil
}

// Revoke clears the device's assignee only while it matches the grant's principal (see matches). If the device
// was reassigned or unassigned since the grant was synced, the grant is already gone and the live assignment is left alone.
func (d *managedDeviceResourceType) Revoke(ctx context.Context, gr *v2.Grant) (annotations.Annotations, error) {
	ctx = jamf.WithFreshReads(ctx)

	if err := requirePrincipalType(gr.Principal.Id.ResourceType, resourceTypeUser, "device assignment", "revoked for users"); err != nil {
		return nil, err
	}

	principal, err := principalIdentityForRevoke(ctx, d.client, gr)
	if err != nil {
		if jamf.IsNotFoundError(err) {
			// The principal (a Jamf user) has been deleted since this grant was
			// synced. Jamf already clears a device's assignee when the assigned
			// user is deleted, so there is nothing left to revoke.
			return annotations.New(&v2.GrantAlreadyRevoked{}), nil
		}
		return nil, fmt.Errorf("jamf-connector: revoke device assigned: resolve principal identity: %w", err)
	}

	current, annos, err := d.currentAssignedUser(ctx, gr.Entitlement.Resource)
	if err != nil {
		if jamf.IsNotFoundError(err) {
			// The device itself has been deleted — nothing left to revoke.
			return annotations.New(&v2.GrantAlreadyRevoked{}), nil
		}
		return nil, fmt.Errorf("jamf-connector: revoke device assigned: %w", err)
	}

	if !current.matches(principal) {
		// Already reassigned to someone else — or already unassigned — since
		// this grant was synced. Clearing now would either be a no-op or,
		// worse, would clear a different user's live assignment, so treat
		// this specific grant as already gone rather than touching the device.
		annos.Update(&v2.GrantAlreadyRevoked{})
		return annos, nil
	}

	// Jamf never refreshes a computer's email, so once the device's username is a synced user the email grant is stale.
	if strings.TrimSpace(principal.username) == "" && strings.TrimSpace(current.username) != "" {
		index, err := d.syncedUserIndex(ctx, current)
		if err != nil {
			return nil, fmt.Errorf("jamf-connector: revoke device assigned: resolve current assignee: %w", err)
		}
		if _, synced := resolveUser(index, current.username, ""); synced {
			annos.Update(&v2.GrantAlreadyRevoked{})
			return annos, nil
		}
	}

	// Clearing the whole assignee identity: for computers, every
	// userAndLocation key the connector writes (username, realname, email,
	// position, phone) is sent as "" — matching what Grant wrote for the new
	// assignee, so none of the outgoing assignee's data is left behind for a
	// future sync (or Jamf's own UI) to pick back up. Mobile devices clear
	// the same way via location.username alone (see
	// SetMobileDeviceAssignedUser): Jamf drops the auto-populated fields
	// together with it.
	annos, err = d.setAssignedUser(ctx, gr.Entitlement.Resource, assignee{})
	if err != nil {
		return nil, fmt.Errorf("jamf-connector: revoke device assigned: %w", err)
	}
	return annos, nil
}

// setAssignedUser dispatches to the computer or mobile-device client call
// based on the device-type prefix deviceObjectID encoded into the resource
// id at List() time. A computer's userAndLocation is written with every
// field of a; mobile devices only send a.username (Jamf auto-populates the
// rest, see SetMobileDeviceAssignedUser). The zero assignee clears the device.
func (d *managedDeviceResourceType) setAssignedUser(ctx context.Context, resource *v2.Resource, a assignee) (annotations.Annotations, error) {
	phase, id, err := parseDeviceObjectID(resource.Id.Resource)
	if err != nil {
		return nil, err
	}

	if phase == devicePhaseComputer {
		return d.client.SetComputerAssignedUser(ctx, id, jamf.ComputerAssignedUserFields{
			Username: a.username,
			Realname: a.realname,
			Email:    a.email,
			Position: a.position,
			Phone:    a.phone,
		})
	}
	return d.client.SetMobileDeviceAssignedUser(ctx, id, a.username)
}

// currentAssignedUser fetches the device's CURRENT assignee directly from
// Jamf (not from any cached sync state), dispatching to the computer or
// mobile-device detail endpoint based on the device-type prefix encoded
// into the resource id. Returns the zero assignee when the device is
// currently unassigned; email is always "" for mobile devices, since the
// mobile-device detail endpoint this uses exposes no email field.
func (d *managedDeviceResourceType) currentAssignedUser(ctx context.Context, resource *v2.Resource) (assignee, annotations.Annotations, error) {
	phase, id, err := parseDeviceObjectID(resource.Id.Resource)
	if err != nil {
		return assignee{}, nil, err
	}

	if phase == devicePhaseComputer {
		detail, annos, err := d.client.GetComputerInventoryDetail(ctx, id)
		if err != nil {
			return assignee{}, nil, err
		}
		if detail.UserAndLocation == nil {
			return assignee{}, annos, nil
		}
		return assignee{username: detail.UserAndLocation.Username, email: detail.UserAndLocation.EmailAddr()}, annos, nil
	}

	detail, annos, err := d.client.GetMobileDeviceDetail(ctx, id)
	if err != nil {
		return assignee{}, nil, err
	}
	if detail.Location == nil {
		return assignee{}, annos, nil
	}
	return assignee{username: detail.Location.Username}, annos, nil
}

// parseDeviceObjectID reverses deviceObjectID, splitting a resource id like
// "computer:17" back into its phase and native Jamf id. Rejects any phase
// other than devicePhaseComputer/devicePhaseMobile, so callers that dispatch
// on the returned phase never need their own default/unknown-phase case.
func parseDeviceObjectID(objectID string) (string, string, error) {
	parts := strings.SplitN(objectID, ":", 2)
	if len(parts) != 2 || (parts[0] != devicePhaseComputer && parts[0] != devicePhaseMobile) {
		return "", "", status.Errorf(codes.InvalidArgument, "jamf-connector: invalid managed device resource id %q", objectID)
	}
	return parts[0], parts[1], nil
}

// resolvePrincipalUser resolves a numeric-Jamf-user-id "user" principal's
// ResourceId to the assignee read from the Jamf user record.
func resolvePrincipalUser(ctx context.Context, client *jamf.Client, principal *v2.Resource) (assignee, error) {
	userID, err := parseResourceID(principal.Id.Resource, "jamf-connector: invalid user id")
	if err != nil {
		return assignee{}, err
	}

	// Grant and Revoke return the device calls' annotations, not this read's.
	user, _, err := client.GetUserDetails(ctx, userID)
	if err != nil {
		return assignee{}, err
	}

	return assignee{
		username: user.LoginName(),
		email:    user.PrimaryEmail(),
		realname: user.FullName,
		position: user.Position,
		phone:    user.PhoneNumber,
	}, nil
}

// assigneePrincipal returns the principal id deviceGrants emits for a, plus
// the ExternalResourceMatch key when a isn't a synced Jamf user ("" when it
// is). rid is nil only when a has neither username nor email to resolve.
func assigneePrincipal(idx map[string]*v2.ResourceId, a assignee) (*v2.ResourceId, string, error) {
	if r, ok := resolveUser(idx, a.username, a.email); ok {
		return r, "", nil
	}

	matchKey, value := matchKeyEmail, strings.TrimSpace(a.email)
	if value == "" {
		matchKey, value = matchKeyUsername, strings.TrimSpace(a.username)
	}
	if value == "" {
		return nil, "", nil
	}

	rid, err := rs.NewResourceID(resourceTypeUser, value)
	if err != nil {
		return nil, "", err
	}
	return rid, matchKey, nil
}

// syncedUserIndex resolves owner the way sync does: nil without a user sync, else the Jamf users matching its username or email.
func (d *managedDeviceResourceType) syncedUserIndex(ctx context.Context, owner assignee) (map[string]*v2.ResourceId, error) {
	if !d.syncUsers {
		return nil, nil
	}
	// Revoke has no session store, so ask Jamf. This read's annotations are dropped: Revoke returns the write's.
	users, _, err := d.client.GetProUsersByUsernameOrEmail(ctx, assigneeLookupKeys(owner))
	if err != nil {
		return nil, err
	}
	return userResourceIDs(userIDsByLookupKey(users)), nil
}

// principalIdentityForRevoke resolves gr's principal to the assignee Revoke
// compares against the device's current one: a synced Jamf user (numeric
// id, via resolvePrincipalUser) or an unsynced one carried in an
// ExternalResourceMatch annotation — or, lacking that annotation, the raw id
// string itself, read as an email if it contains "@" and a username
// otherwise.
func principalIdentityForRevoke(ctx context.Context, client *jamf.Client, gr *v2.Grant) (assignee, error) {
	match := &v2.ExternalResourceMatch{}
	grantAnnos := annotations.Annotations(gr.GetAnnotations())
	ok, err := grantAnnos.Pick(match)
	if err != nil {
		return assignee{}, fmt.Errorf("jamf-connector: read external resource match annotation: %w", err)
	}
	if ok {
		switch match.GetKey() {
		case matchKeyEmail:
			return assignee{email: match.GetValue()}, nil
		case matchKeyUsername:
			return assignee{username: match.GetValue()}, nil
		default:
			return assignee{}, status.Errorf(codes.Internal, "jamf-connector: unknown external resource match key %q", match.GetKey())
		}
	}

	if _, err := strconv.Atoi(gr.Principal.Id.Resource); err != nil {
		value := strings.TrimSpace(gr.Principal.Id.Resource)
		if strings.Contains(value, "@") {
			return assignee{email: value}, nil
		}
		return assignee{username: value}, nil
	}

	return resolvePrincipalUser(ctx, client, gr.Principal)
}

func managedDeviceBuilder(client *jamf.Client, syncUsers bool) *managedDeviceResourceType {
	return &managedDeviceResourceType{
		resourceType: resourceTypeManagedDevice,
		client:       client,
		syncUsers:    syncUsers,
	}
}

// computerResource maps a Jamf computer-inventory record onto a ManagedDevice
// resource carrying a ManagedDeviceTrait.
func computerResource(c *jamf.ComputerInventory, parentResourceID *v2.ResourceId) (*v2.Resource, error) {
	var opts []rs.ManagedDeviceTraitOption

	name := c.ID
	if c.General != nil && c.General.Name != "" {
		name = c.General.Name
	}

	if c.Hardware != nil && c.Hardware.SerialNumber != "" {
		opts = append(opts, rs.WithManagedDeviceSerial(c.Hardware.SerialNumber))
	}
	if c.UDID != "" {
		opts = append(opts, rs.WithManagedDeviceUDID(c.UDID))
	}

	if dt, ok := computerDeviceType(c.Hardware); ok {
		opts = append(opts, rs.WithManagedDeviceType(dt))
	}

	if c.Hardware != nil {
		if model := computerModel(c.Hardware); model != "" {
			opts = append(opts, rs.WithManagedDeviceModel(model))
		}
		if c.Hardware.Make != "" {
			opts = append(opts, rs.WithManagedDeviceVendor(c.Hardware.Make))
		}
	}

	if os := computerOS(c.OperatingSystem); os != nil {
		opts = append(opts, rs.WithManagedDeviceOS(os))
	}

	if enc, ok := isEncrypted(c.DiskEncryption); ok {
		opts = append(opts, rs.WithManagedDeviceEncrypted(enc))
	}

	if c.General != nil {
		opts = append(opts, rs.WithManagedDeviceSupervised(c.General.Supervised))
	}

	if managementStateManaged(c.General) {
		opts = append(opts, rs.WithManagedDeviceManagementState(v2.ManagedDeviceTrait_MANAGEMENT_STATE_MANAGED))
	}

	if c.General != nil {
		if t, ok := parseJamfTime(c.General.LastEnrolledDate); ok {
			opts = append(opts, rs.WithManagedDeviceEnrolledAt(t))
		}
	}

	return rs.NewManagedDeviceResource(
		name,
		resourceTypeManagedDevice,
		deviceObjectID(devicePhaseComputer, c.ID),
		opts,
		rs.WithParentResourceID(parentResourceID),
	)
}

// mobileDeviceResource maps a Jamf mobile-device record onto a ManagedDevice
// resource. The v2 list endpoint exposes a flatter field set than the computers
// inventory, so fewer trait fields are populated.
func mobileDeviceResource(m *jamf.MobileDevice, parentResourceID *v2.ResourceId) (*v2.Resource, error) {
	var opts []rs.ManagedDeviceTraitOption

	name := m.Name
	if name == "" {
		name = m.ID
	}

	if m.SerialNumber != "" {
		opts = append(opts, rs.WithManagedDeviceSerial(m.SerialNumber))
	}
	if m.UDID != "" {
		opts = append(opts, rs.WithManagedDeviceUDID(m.UDID))
	}

	if dt, ok := mobileDeviceType(m); ok {
		opts = append(opts, rs.WithManagedDeviceType(dt))
	}

	if model := mobileModel(m); model != "" {
		opts = append(opts, rs.WithManagedDeviceModel(model))
	}

	if os := mobileOS(m); os != nil {
		opts = append(opts, rs.WithManagedDeviceOS(os))
	}

	opts = append(opts, rs.WithManagedDeviceSupervised(m.Supervised))

	if m.Managed {
		opts = append(opts, rs.WithManagedDeviceManagementState(v2.ManagedDeviceTrait_MANAGEMENT_STATE_MANAGED))
	}

	return rs.NewManagedDeviceResource(
		name,
		resourceTypeManagedDevice,
		deviceObjectID(devicePhaseMobile, m.ID),
		opts,
		rs.WithParentResourceID(parentResourceID),
	)
}

// deviceObjectID namespaces device IDs by source so a computer and a mobile
// device that happen to share a numeric ID do not collide.
func deviceObjectID(phase, id string) string {
	return fmt.Sprintf("%s:%s", phase, id)
}

// computerDeviceType derives LAPTOP vs DESKTOP from the Apple model identifier.
// Every Mac is one or the other, so once a model string exists the only
// ambiguity is laptop vs desktop, which "book" (MacBook / MacBook Pro / Air)
// resolves cleanly.
func computerDeviceType(hw *jamf.ComputerHardware) (v2.ManagedDeviceTrait_DeviceType, bool) {
	if hw == nil {
		return 0, false
	}
	id := strings.ToLower(hw.ModelIdentifier)
	if id == "" {
		id = strings.ToLower(hw.Model)
	}
	if id == "" {
		return 0, false
	}
	if strings.Contains(id, "book") {
		return v2.ManagedDeviceTrait_DEVICE_TYPE_LAPTOP, true
	}
	return v2.ManagedDeviceTrait_DEVICE_TYPE_DESKTOP, true
}

// computerModel prefers the human-friendly model name, falling back to the
// model identifier.
func computerModel(hw *jamf.ComputerHardware) string {
	if hw.Model != "" {
		return hw.Model
	}
	return hw.ModelIdentifier
}

// computerOS builds a DeviceOS from the operating-system section. Returns nil
// when there is nothing to report.
func computerOS(os *jamf.ComputerOperatingSystem) *v2.DeviceOS {
	if os == nil {
		return nil
	}
	if os.Name == "" && os.Version == "" && os.Build == "" {
		return nil
	}
	d := &v2.DeviceOS{}
	if t, ok := osTypeFromName(os.Name); ok {
		d.SetType(t)
	}
	if os.Name != "" {
		d.SetName(os.Name)
	}
	if os.Version != "" {
		d.SetVersion(os.Version)
	}
	if os.Build != "" {
		d.SetBuild_(os.Build)
	}
	return d
}

// osTypeFromName maps a Jamf OS name string onto a DeviceOS_OsType. Unknown
// names leave the type unset rather than guessing.
func osTypeFromName(name string) (v2.DeviceOS_OsType, bool) {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "ipados"):
		return v2.DeviceOS_OS_TYPE_IPADOS, true
	case strings.Contains(n, "ios"):
		return v2.DeviceOS_OS_TYPE_IOS, true
	case strings.Contains(n, "mac"): // "macOS", "Mac OS X"
		return v2.DeviceOS_OS_TYPE_MACOS, true
	}
	return 0, false
}

// isEncrypted derives a tri-state disk-encryption flag from the boot partition
// FileVault 2 state. Only definitive states assert a value; transitional or
// unknown states leave it unset.
func isEncrypted(de *jamf.ComputerDiskEncryption) (bool, bool) {
	if de == nil || de.BootPartitionEncryptionDetails == nil {
		return false, false
	}
	switch strings.ToUpper(strings.TrimSpace(de.BootPartitionEncryptionDetails.PartitionFileVault2State)) {
	case "ENCRYPTED":
		return true, true
	case "UNENCRYPTED", "DECRYPTED":
		return false, true
	default:
		return false, false
	}
}

// managementStateManaged reports whether a computer should be considered MANAGED:
// it must be MDM-capable and actively remotely managed.
func managementStateManaged(g *jamf.ComputerGeneral) bool {
	if g == nil {
		return false
	}
	mdm := g.MDMCapable != nil && g.MDMCapable.Capable
	remote := g.RemoteManagement != nil && g.RemoteManagement.Managed
	return mdm && remote
}

// mobileDeviceType derives the device form factor for a mobile device. iPads map
// to TABLET; iPhones and other iOS devices map to MOBILE.
func mobileDeviceType(m *jamf.MobileDevice) (v2.ManagedDeviceTrait_DeviceType, bool) {
	id := strings.ToLower(strings.Join([]string{m.ModelIdentifier, m.Model, m.Type}, " "))
	switch {
	case strings.Contains(id, "ipad"):
		return v2.ManagedDeviceTrait_DEVICE_TYPE_TABLET, true
	case strings.Contains(id, "iphone"), strings.Contains(id, "ios"):
		return v2.ManagedDeviceTrait_DEVICE_TYPE_MOBILE, true
	}
	return 0, false
}

// mobileModel prefers the model name, falling back to the model identifier.
func mobileModel(m *jamf.MobileDevice) string {
	if m.Model != "" {
		return m.Model
	}
	return m.ModelIdentifier
}

// mobileOS builds a DeviceOS for a mobile device from the type / model hints and
// the reported OS version/build.
func mobileOS(m *jamf.MobileDevice) *v2.DeviceOS {
	d := &v2.DeviceOS{}
	id := strings.ToLower(strings.Join([]string{m.ModelIdentifier, m.Model}, " "))
	switch {
	case strings.Contains(id, "ipad"):
		d.SetType(v2.DeviceOS_OS_TYPE_IPADOS)
		d.SetName("iPadOS")
	case strings.Contains(id, "iphone"), strings.Contains(strings.ToLower(m.Type), "ios"):
		d.SetType(v2.DeviceOS_OS_TYPE_IOS)
		d.SetName("iOS")
	}
	if m.OSVersion != "" {
		d.SetVersion(m.OSVersion)
	}
	if m.OSBuild != "" {
		d.SetBuild_(m.OSBuild)
	}
	if d.GetType() == v2.DeviceOS_OS_TYPE_UNSPECIFIED && d.GetName() == "" && d.GetVersion() == "" && d.GetBuild_() == "" {
		return nil
	}
	return d
}

// assigneeLookupKeys returns the distinct non-empty lookup keys of owner's username and email.
func assigneeLookupKeys(owner assignee) []string {
	keys := make([]string, 0, 2)
	for _, value := range []string{owner.username, owner.email} {
		key := userLookupKey(value)
		if key != "" && !slices.Contains(keys, key) {
			keys = append(keys, key)
		}
	}
	return keys
}

// userResourceIDs maps each lookup key to its user ResourceId.
func userResourceIDs(userIDs map[string]string) map[string]*v2.ResourceId {
	resourceIDs := make(map[string]*v2.ResourceId, len(userIDs))
	for key, userID := range userIDs {
		resourceIDs[key] = &v2.ResourceId{ResourceType: resourceTypeUser.Id, Resource: userID}
	}
	return resourceIDs
}

// resolveUser looks up a synced user ResourceId by username then email.
func resolveUser(idx map[string]*v2.ResourceId, username, email string) (*v2.ResourceId, bool) {
	for _, key := range []string{username, email} {
		key = userLookupKey(key)
		if key == "" {
			continue
		}
		if rid, ok := idx[key]; ok {
			return rid, true
		}
	}
	return nil, false
}

// deviceGrants builds the device->user grant(s) for the assignee. A synced Jamf
// user is granted directly; an unsynced assignee produces a grant carrying an
// ExternalResourceMatch so the platform binds it to a directory identity.
func deviceGrants(resource *v2.Resource, a assignee, userIndex map[string]*v2.ResourceId) ([]*v2.Grant, error) {
	if a.empty() {
		return nil, nil
	}

	rid, matchKey, err := assigneePrincipal(userIndex, a)
	if err != nil {
		return nil, err
	}
	if matchKey == "" {
		return []*v2.Grant{grant.NewGrant(resource, assignedEntitlement, rid)}, nil
	}

	match := v2.ExternalResourceMatch_builder{
		ResourceType: v2.ResourceType_TRAIT_USER,
		Key:          matchKey,
		Value:        rid.Resource,
	}.Build()

	return []*v2.Grant{grant.NewGrant(resource, assignedEntitlement, rid, grant.WithAnnotation(match))}, nil
}

// parseJamfTime parses the ISO-8601 timestamps Jamf returns. Returns ok=false
// on empty or unparseable input so callers leave the field unset.
func parseJamfTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.000-0700",
		"2006-01-02T15:04:05-0700",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
