package jamf

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// An instance without a Pro list endpoint answers 404; NotFound would make the SDK skip the
// List or Grants action, and C1 would delete what it synced before.
func TestProListEndpoints_MissingEndpointIsFailedPrecondition(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	ctx := context.Background()

	calls := map[string]func() error{
		"GetProUsers": func() error {
			_, _, err := client.GetProUsers(ctx, "", UsersPageSize)
			return err
		},
		"GetProUsersByUsernameOrEmail": func() error {
			_, err := client.GetProUsersByUsernameOrEmail(ctx, []string{"jdoe"})
			return err
		},
		"GetProAccounts": func() error {
			_, _, err := client.GetProAccounts(ctx, "", "", AccountsPageSize)
			return err
		},
		"GetSiteObjects": func() error {
			_, _, err := client.GetSiteObjects(ctx, 3, "User", "")
			return err
		},
		"GetPrivileges": func() error {
			_, err := client.GetPrivileges(ctx)
			return err
		},
	}
	for name, call := range calls {
		if code := status.Code(call()); code != codes.FailedPrecondition {
			t.Errorf("%s: code = %v, want FailedPrecondition", name, code)
		}
	}
}

// jsonHandler serves body as JSON and records the request URL.
func jsonHandler(t *testing.T, gotURL **url.URL, body string) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected method %s", r.Method)
		}
		*gotURL = r.URL
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatalf("write response: %v", err)
		}
	}
}

func TestGetProUsers_SendsPagingAndSort_DecodesStringIDs(t *testing.T) {
	var gotURL *url.URL
	client := newTestClient(t, jsonHandler(t, &gotURL, `{
		"totalCount": 2,
		"results": [
			{"id": "44", "username": "jappleseed", "realname": "John Appleseed", "email": "john@example.com"},
			{"id": "45", "username": "jdoe", "realname": "", "email": ""}
		]
	}`))

	users, _, err := client.GetProUsers(context.Background(), "2", 50)
	if err != nil {
		t.Fatalf("GetProUsers: %v", err)
	}

	if gotURL.Path != "/api/v1/users" {
		t.Errorf("path = %q, want /api/v1/users", gotURL.Path)
	}
	query := gotURL.Query()
	for key, want := range map[string]string{"page": "2", "page-size": "50", "sort": "id:asc"} {
		if got := query.Get(key); got != want {
			t.Errorf("query %s = %q, want %q", key, got, want)
		}
	}

	if len(users) != 2 {
		t.Fatalf("got %d users, want 2", len(users))
	}
	if users[0].ID != 44 || users[1].ID != 45 {
		t.Errorf("user ids = %d, %d, want 44, 45", users[0].ID, users[1].ID)
	}
}

func TestGetProUsersByUsernameOrEmail_SendsFilter(t *testing.T) {
	var gotURL *url.URL
	client := newTestClient(t, jsonHandler(t, &gotURL, `{
		"totalCount": 1,
		"results": [{"id": "5", "username": "c@d", "realname": "", "email": "c@d"}]
	}`))

	users, err := client.GetProUsersByUsernameOrEmail(context.Background(), []string{`a"b`, "c@d"})
	if err != nil {
		t.Fatalf("GetProUsersByUsernameOrEmail: %v", err)
	}

	if gotURL.Path != "/api/v1/users" {
		t.Errorf("path = %q, want /api/v1/users", gotURL.Path)
	}
	query := gotURL.Query()
	for key, want := range map[string]string{
		"filter":    `username=="a\"b",email=="a\"b",username=="c@d",email=="c@d"`,
		"page":      "0",
		"page-size": "1000",
		"sort":      "id:asc",
	} {
		if got := query.Get(key); got != want {
			t.Errorf("query %s = %q, want %q", key, got, want)
		}
	}

	if len(users) != 1 || users[0].ID != 5 || users[0].Username != "c@d" {
		t.Errorf("users = %+v, want one user with ID 5 and username c@d", users)
	}
}
