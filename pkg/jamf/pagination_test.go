package jamf

import (
	"context"
	"net/http"
	"slices"
	"strconv"
	"testing"
)

// Jamf can serve fewer records per page than page-size asks for and numbers the next page by the size it
// served. Stopping on the requested size would drop the remaining records with a green sync.
func TestPagination_ServerServesFewerRecordsThanRequested(t *testing.T) {
	const (
		servedPerPage = 3
		totalRecords  = 10
	)
	ctx := context.Background()

	testCases := []struct {
		name         string
		idKey        string
		objectType   string
		hasTotal     bool
		wantRequests int
		fetch        func(client *Client, pageToken string) ([]string, string, error)
	}{
		{
			name:         "GetProUsers",
			idKey:        "id",
			hasTotal:     true,
			wantRequests: 4,
			fetch: func(client *Client, pageToken string) ([]string, string, error) {
				users, next, _, err := client.GetProUsers(ctx, pageToken, UsersPageSize)
				ids := make([]string, 0, len(users))
				for _, user := range users {
					ids = append(ids, strconv.Itoa(user.ID))
				}
				return ids, next, err
			},
		},
		{
			name:         "GetProAccounts",
			idKey:        "id",
			hasTotal:     true,
			wantRequests: 4,
			fetch: func(client *Client, pageToken string) ([]string, string, error) {
				accounts, next, _, err := client.GetProAccounts(ctx, "", pageToken, AccountsPageSize)
				ids := make([]string, 0, len(accounts))
				for _, account := range accounts {
					ids = append(ids, strconv.Itoa(account.ID))
				}
				return ids, next, err
			},
		},
		{
			name:         "GetComputersInventory",
			idKey:        "id",
			hasTotal:     true,
			wantRequests: 4,
			fetch: func(client *Client, pageToken string) ([]string, string, error) {
				computers, next, _, err := client.GetComputersInventory(ctx, pageToken, 100, ComputerInventorySections)
				ids := make([]string, 0, len(computers))
				for _, computer := range computers {
					ids = append(ids, computer.ID)
				}
				return ids, next, err
			},
		},
		{
			name:         "GetMobileDevices",
			idKey:        "id",
			hasTotal:     true,
			wantRequests: 4,
			fetch: func(client *Client, pageToken string) ([]string, string, error) {
				devices, next, _, err := client.GetMobileDevices(ctx, pageToken, 100)
				ids := make([]string, 0, len(devices))
				for _, device := range devices {
					ids = append(ids, device.ID)
				}
				return ids, next, err
			},
		},
		{
			name:         "GetSiteObjects",
			idKey:        "objectId",
			objectType:   "User",
			wantRequests: 5, // The last page is empty: the response has no total.
			fetch: func(client *Client, pageToken string) ([]string, string, error) {
				objects, next, _, err := client.GetSiteObjects(ctx, 3, "User", pageToken)
				ids := make([]string, 0, len(objects))
				for _, object := range objects {
					ids = append(ids, strconv.Itoa(object.ObjectID))
				}
				return ids, next, err
			},
		},
	}

	wantIDs := []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10"}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			requests := 0
			client := newTestClient(t, func(writer http.ResponseWriter, request *http.Request) {
				requests++
				page, err := strconv.Atoi(request.URL.Query().Get("page"))
				if err != nil {
					t.Errorf("page %q: %v", request.URL.Query().Get("page"), err)
					http.Error(writer, "invalid page", http.StatusBadRequest)
					return
				}
				start := min(page*servedPerPage, totalRecords)
				end := min(start+servedPerPage, totalRecords)
				records := make([]map[string]any, 0, servedPerPage)
				for id := start + 1; id <= end; id++ {
					record := map[string]any{testCase.idKey: strconv.Itoa(id)}
					if testCase.objectType != "" {
						record["objectType"] = testCase.objectType
					}
					records = append(records, record)
				}
				var body any = records
				if testCase.hasTotal {
					body = map[string]any{"totalCount": totalRecords, "results": records}
				}
				writeTestJSON(t, writer, body)
			})

			var gotIDs []string
			pageToken := ""
			for {
				ids, next, err := testCase.fetch(client, pageToken)
				if err != nil {
					t.Fatalf("fetch with token %q: %v", pageToken, err)
				}
				gotIDs = append(gotIDs, ids...)
				if next == "" {
					break
				}
				if requests > totalRecords {
					t.Fatalf("still paginating after %d requests, last token %q", requests, next)
				}
				pageToken = next
			}

			if !slices.Equal(gotIDs, wantIDs) {
				t.Errorf("ids = %v, want %v", gotIDs, wantIDs)
			}
			if requests != testCase.wantRequests {
				t.Errorf("requests = %d, want %d", requests, testCase.wantRequests)
			}
		})
	}
}
