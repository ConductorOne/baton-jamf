package jamf

import (
	"context"
	liburl "net/url"
	"strconv"
)

const (
	computersInventoryUrlPath = "/api/v1/computers-inventory"
	mobileDevicesUrlPath      = "/api/v2/mobile-devices"
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
