package jamf

import (
	"fmt"
	"strconv"
)

// parsePageToken decodes a page token: the zero-indexed page number, "" meaning page 0.
func parsePageToken(pageToken string) (int, error) {
	if pageToken == "" {
		return 0, nil
	}
	page, err := strconv.Atoi(pageToken)
	if err != nil {
		return 0, fmt.Errorf("invalid page token %q: %w", pageToken, err)
	}
	return page, nil
}

// nextPageToken returns the token of the page after page, or "" when page was the last one.
func nextPageToken(page, pageSize, count, totalCount int) string {
	if count == 0 || (page+1)*pageSize >= totalCount {
		return ""
	}
	return strconv.Itoa(page + 1)
}
