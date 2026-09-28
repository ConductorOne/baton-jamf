package jamf

import (
	"context"
	"fmt"
	"net/http"
	liburl "net/url"
	"strconv"
)

const (
	computersInventoryUrlPath      = "/api/v1/computers-inventory"
	computerInventoryDetailUrlPath = "/api/v1/computers-inventory-detail/%s"
	mobileDevicesUrlPath           = "/api/v2/mobile-devices"
	mobileDeviceUrlPath            = "/api/v2/mobile-devices/%s"
	mobileDeviceDetailUrlPath      = "/api/v2/mobile-devices/%s/detail"
)

// ComputerInventorySections are the inventory sections the connector requests.
// The endpoint only populates a section when it is explicitly requested via a
// `section` query parameter, so mapping relies on these being asked for.
var ComputerInventorySections = []string{
	"GENERAL",
	"HARDWARE",
	"OPERATING_SYSTEM",
	"USER_AND_LOCATION",
	"DISK_ENCRYPTION",
	"SECURITY",
}

// GetComputersInventory returns a single page of the computers inventory.
// The Jamf API is zero-indexed on `page`; callers drive pagination by
// incrementing page until (page+1)*pageSize >= totalCount.
func (c *Client) GetComputersInventory(
	ctx context.Context,
	page int,
	pageSize int,
	sections []string,
) (*ComputersInventoryResponse, error) {
	url, err := c.getUrl(computersInventoryUrlPath)
	if err != nil {
		return nil, err
	}

	query := liburl.Values{}
	for _, section := range sections {
		query.Add("section", section)
	}
	query.Set("page", strconv.Itoa(page))
	query.Set("page-size", strconv.Itoa(pageSize))
	url.RawQuery = query.Encode()

	var target ComputersInventoryResponse
	if err := c.doRequest(ctx, url, &target); err != nil {
		return nil, err
	}

	return &target, nil
}

// GetMobileDevices returns a single page of mobile devices from the v2 list
// endpoint. Pagination follows the same zero-indexed page convention as the
// computers inventory endpoint.
func (c *Client) GetMobileDevices(
	ctx context.Context,
	page int,
	pageSize int,
) (*MobileDevicesResponse, error) {
	url, err := c.getUrl(mobileDevicesUrlPath)
	if err != nil {
		return nil, err
	}

	query := liburl.Values{}
	query.Set("page", strconv.Itoa(page))
	query.Set("page-size", strconv.Itoa(pageSize))
	url.RawQuery = query.Encode()

	var target MobileDevicesResponse
	if err := c.doRequest(ctx, url, &target); err != nil {
		return nil, err
	}

	return &target, nil
}

// GetComputerInventoryDetail fetches a single computer's inventory detail
// record via GET /api/v1/computers-inventory-detail/{id}. Used by Revoke to
// discover the CURRENT assigned username (userAndLocation.username) before
// clearing it, since the device may have been reassigned to a different user
// since the grant being revoked was last synced.
func (c *Client) GetComputerInventoryDetail(ctx context.Context, computerID string) (*ComputerInventory, error) {
	url, err := c.getUrl(fmt.Sprintf(computerInventoryDetailUrlPath, computerID))
	if err != nil {
		return nil, err
	}

	var target ComputerInventory
	if err := c.doRequest(ctx, url, &target); err != nil {
		return nil, err
	}

	return &target, nil
}

// GetMobileDeviceDetail fetches a single mobile device's detail record via
// GET /api/v2/mobile-devices/{id}/detail, used by Revoke for the same
// reassignment check as GetComputerInventoryDetail. Per Jamf's OpenAPI spec,
// this endpoint's response (MobileDeviceDetailsGetV2, which extends
// MobileDeviceDetailsV2) nests the current assignee under `location.username`
// (LocationV2) - see
// https://developer.jamf.com/jamf-pro/reference/get_v2-mobile-devices-id-detail.
// This differs from the plain GET /api/v2/mobile-devices/{id} endpoint
// (MobileDeviceV2), which returns a flat top-level `username` field instead -
// see https://developer.jamf.com/jamf-pro/reference/get_v2-mobile-devices-id.
// That plain endpoint backs the list endpoint's MobileDevice type and
// SetMobileDeviceAssignedUser's PATCH, neither of which is affected by this.
func (c *Client) GetMobileDeviceDetail(ctx context.Context, deviceID string) (*MobileDeviceDetail, error) {
	url, err := c.getUrl(fmt.Sprintf(mobileDeviceDetailUrlPath, deviceID))
	if err != nil {
		return nil, err
	}

	var target MobileDeviceDetail
	if err := c.doRequest(ctx, url, &target); err != nil {
		return nil, err
	}

	return &target, nil
}

// SetComputerAssignedUser sets (Grant) or clears (Revoke, username == "")
// the assigned-user field on a computer's inventory record via
// PATCH /api/v1/computers-inventory-detail/{id}, userAndLocation.username.
// Single-valued/exclusive: setting a new username silently displaces
// whatever username was previously recorded.
func (c *Client) SetComputerAssignedUser(ctx context.Context, computerID string, username string) error {
	url, err := c.getUrl(fmt.Sprintf(computerInventoryDetailUrlPath, computerID))
	if err != nil {
		return err
	}

	reqBody := ComputerAssignedUserUpdate{UserAndLocation: ComputerAssignedUserUpdateLocation{Username: username}}
	return c.doRequestWithJSONMethod(ctx, http.MethodPatch, url, reqBody, nil)
}

// SetMobileDeviceAssignedUser is the mobile-device equivalent, via
// PATCH /api/v2/mobile-devices/{id}, location.username.
func (c *Client) SetMobileDeviceAssignedUser(ctx context.Context, deviceID string, username string) error {
	url, err := c.getUrl(fmt.Sprintf(mobileDeviceUrlPath, deviceID))
	if err != nil {
		return err
	}

	reqBody := MobileDeviceAssignedUserUpdate{Location: MobileDeviceAssignedUserUpdateLocation{Username: username}}
	return c.doRequestWithJSONMethod(ctx, http.MethodPatch, url, reqBody, nil)
}
