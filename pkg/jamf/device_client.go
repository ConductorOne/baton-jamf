package jamf

import (
	"context"
	"fmt"
	"net/http"
	liburl "net/url"
	"strconv"

	"github.com/conductorone/baton-sdk/pkg/annotations"
)

const (
	// v4 is the non-deprecated version of the computers-inventory(-detail)
	// endpoints.
	computersInventoryUrlPath      = "/api/v4/computers-inventory"
	computerInventoryDetailUrlPath = "/api/v4/computers-inventory-detail/%s"
	mobileDevicesUrlPath           = "/api/v2/mobile-devices"
	mobileDeviceUrlPath            = "/api/v2/mobile-devices/%s"
	mobileDeviceDetailUrlPath      = "/api/v2/mobile-devices/%s/detail"

	// deviceSort keeps offset pages stable within a pass; computers default to name order,
	// which shifts when a device is renamed mid-sync.
	deviceSort = "id:asc"
)

// ComputerInventorySections are the sections List requests from the v4 list endpoint,
// which returns only the requested sections (only GENERAL when none is sent).
var ComputerInventorySections = []string{
	"GENERAL",
	"HARDWARE",
	"OPERATING_SYSTEM",
	"DISK_ENCRYPTION",
	"SECURITY",
}

// ComputerAssigneeSections is the only section the grants pass reads: the assignee.
var ComputerAssigneeSections = []string{"USER_AND_LOCATION"}

// GetComputersInventory returns one page of computers ordered by id, holding only the requested sections,
// and the next page token, "" after the last page. GET /api/v4/computers-inventory, needs the Read Computers privilege.
func (c *Client) GetComputersInventory(ctx context.Context, pageToken string, pageSize int, sections []string) ([]ComputerInventory, string, annotations.Annotations, error) {
	page, err := parsePageToken(pageToken)
	if err != nil {
		return nil, "", nil, err
	}

	url, err := c.getUrl(computersInventoryUrlPath)
	if err != nil {
		return nil, "", nil, err
	}

	query := liburl.Values{}
	for _, section := range sections {
		query.Add("section", section)
	}
	query.Set("page", strconv.Itoa(page))
	query.Set("page-size", strconv.Itoa(pageSize))
	query.Set("sort", deviceSort)
	url.RawQuery = query.Encode()

	var response ComputersInventoryResponse
	annos, err := c.doRequest(ctx, url, &response)
	if err != nil {
		return nil, "", nil, proEndpointError(computersInventoryUrlPath, err)
	}

	nextPage := nextPageToken(page, pageSize, len(response.Results), response.TotalCount)
	return response.Results, nextPage, annos, nil
}

// GetMobileDevices returns one page of mobile devices ordered by id and the next page token, "" after the last page.
// GET /api/v2/mobile-devices, needs the Read Mobile Devices privilege.
func (c *Client) GetMobileDevices(ctx context.Context, pageToken string, pageSize int) ([]MobileDevice, string, annotations.Annotations, error) {
	page, err := parsePageToken(pageToken)
	if err != nil {
		return nil, "", nil, err
	}

	url, err := c.getUrl(mobileDevicesUrlPath)
	if err != nil {
		return nil, "", nil, err
	}

	query := liburl.Values{}
	query.Set("page", strconv.Itoa(page))
	query.Set("page-size", strconv.Itoa(pageSize))
	query.Set("sort", deviceSort)
	url.RawQuery = query.Encode()

	var response MobileDevicesResponse
	annos, err := c.doRequest(ctx, url, &response)
	if err != nil {
		return nil, "", nil, proEndpointError(mobileDevicesUrlPath, err)
	}

	nextPage := nextPageToken(page, pageSize, len(response.Results), response.TotalCount)
	return response.Results, nextPage, annos, nil
}

// GetComputerInventoryDetail fetches a computer's current inventory detail.
// Grant and Revoke read it first since the device may have been reassigned
// since last sync; Grant reports a displaced assignee via GrantReplaced.
func (c *Client) GetComputerInventoryDetail(ctx context.Context, computerID string) (*ComputerInventory, annotations.Annotations, error) {
	url, err := c.getUrl(fmt.Sprintf(computerInventoryDetailUrlPath, computerID))
	if err != nil {
		return nil, nil, err
	}

	var target ComputerInventory
	annos, err := c.doRequest(ctx, url, &target)
	if err != nil {
		return nil, nil, err
	}

	return &target, annos, nil
}

// GetMobileDeviceDetail fetches a mobile device's detail record, used by
// Grant and Revoke for the same reassignment check as
// GetComputerInventoryDetail. Unlike the plain GET endpoint (flat top-level
// username), the detail response nests it under location.username; the two
// values agree.
func (c *Client) GetMobileDeviceDetail(ctx context.Context, deviceID string) (*MobileDeviceDetail, annotations.Annotations, error) {
	url, err := c.getUrl(fmt.Sprintf(mobileDeviceDetailUrlPath, deviceID))
	if err != nil {
		return nil, nil, err
	}

	var target MobileDeviceDetail
	annos, err := c.doRequest(ctx, url, &target)
	if err != nil {
		return nil, nil, err
	}

	return &target, annos, nil
}

// SetComputerAssignedUser sets (Grant) or clears (Revoke, zero-value fields)
// the assigned user on a computer's inventory record — see
// ComputerAssignedUserFields for the field semantics.
func (c *Client) SetComputerAssignedUser(ctx context.Context, computerID string, fields ComputerAssignedUserFields) (annotations.Annotations, error) {
	url, err := c.getUrl(fmt.Sprintf(computerInventoryDetailUrlPath, computerID))
	if err != nil {
		return nil, err
	}

	reqBody := computerAssignedUserUpdate{UserAndLocation: fields}
	return c.doRequestWithJSONMethod(ctx, http.MethodPatch, url, reqBody, nil)
}

// SetMobileDeviceAssignedUser is the mobile-device equivalent, via
// location.username — see MobileDeviceLocation for the field semantics. The
// Classic PUT is deliberately not used here: it writes the device's
// leftover location values back into the directory user's own record.
func (c *Client) SetMobileDeviceAssignedUser(ctx context.Context, deviceID string, username string) (annotations.Annotations, error) {
	url, err := c.getUrl(fmt.Sprintf(mobileDeviceUrlPath, deviceID))
	if err != nil {
		return nil, err
	}

	reqBody := mobileDeviceAssignedUserUpdate{Location: MobileDeviceLocation{Username: username}}
	return c.doRequestWithJSONMethod(ctx, http.MethodPatch, url, reqBody, nil)
}
