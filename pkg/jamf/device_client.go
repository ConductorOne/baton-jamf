package jamf

import (
	"context"
	"fmt"
	"net/http"
	liburl "net/url"
	"strconv"
)

const (
	// v4 is the non-deprecated version of the computers-inventory(-detail)
	// endpoints.
	computersInventoryUrlPath      = "/api/v4/computers-inventory"
	computerInventoryDetailUrlPath = "/api/v4/computers-inventory-detail/%s"
	mobileDevicesUrlPath           = "/api/v2/mobile-devices"
	mobileDeviceUrlPath            = "/api/v2/mobile-devices/%s"
	mobileDeviceDetailUrlPath      = "/api/v2/mobile-devices/%s/detail"
)

// ComputerInventorySections are the inventory sections requested from the v4
// list endpoint, which only returns the sections requested via `section=`
// (only GENERAL when none is sent).
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

// GetComputerInventoryDetail fetches a computer's current inventory detail.
// Grant and Revoke read it first since the device may have been reassigned
// since last sync; Grant reports a displaced assignee via GrantReplaced.
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

// GetMobileDeviceDetail fetches a mobile device's detail record, used by
// Grant and Revoke for the same reassignment check as
// GetComputerInventoryDetail. Unlike the plain GET endpoint (flat top-level
// username), the detail response nests it under location.username; the two
// values agree.
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

// SetComputerAssignedUser sets (Grant) or clears (Revoke, zero-value fields)
// the assigned user on a computer's inventory record — see
// ComputerAssignedUserFields for the field semantics.
func (c *Client) SetComputerAssignedUser(ctx context.Context, computerID string, fields ComputerAssignedUserFields) error {
	url, err := c.getUrl(fmt.Sprintf(computerInventoryDetailUrlPath, computerID))
	if err != nil {
		return err
	}

	reqBody := computerAssignedUserUpdate{UserAndLocation: fields}
	return c.doRequestWithJSONMethod(ctx, http.MethodPatch, url, reqBody, nil)
}

// SetMobileDeviceAssignedUser is the mobile-device equivalent, via
// location.username — see MobileDeviceLocation for the field semantics. The
// Classic PUT is deliberately not used here: it writes the device's
// leftover location values back into the directory user's own record.
func (c *Client) SetMobileDeviceAssignedUser(ctx context.Context, deviceID string, username string) error {
	url, err := c.getUrl(fmt.Sprintf(mobileDeviceUrlPath, deviceID))
	if err != nil {
		return err
	}

	reqBody := mobileDeviceAssignedUserUpdate{Location: MobileDeviceLocation{Username: username}}
	return c.doRequestWithJSONMethod(ctx, http.MethodPatch, url, reqBody, nil)
}
