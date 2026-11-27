package jamf

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// parsePageToken decodes a page token "<page>" or "<page>:<received>": the zero-indexed page to request and the
// records received before it, 0 when absent. "" is the first page.
func parsePageToken(pageToken string) (int, int, error) {
	if pageToken == "" {
		return 0, 0, nil
	}
	pageText, receivedText, hasReceived := strings.Cut(pageToken, ":")
	if !hasReceived {
		receivedText = "0"
	}
	page, pageErr := strconv.Atoi(pageText)
	received, receivedErr := strconv.Atoi(receivedText)
	if err := errors.Join(pageErr, receivedErr); err != nil {
		return 0, 0, fmt.Errorf("invalid page token %q: %w", pageToken, err)
	}
	return page, received, nil
}

// nextPageToken returns the next page's token, or "" when everything was received or the page came back empty.
// Jamf can serve fewer records than page-size, so progress is the records received, not pages x page-size.
func nextPageToken(page, received, count, totalCount int) string {
	received += count
	if count == 0 || received >= totalCount {
		return ""
	}
	return fmt.Sprintf("%d:%d", page+1, received)
}
