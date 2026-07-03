package jamf

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/conductorone/baton-sdk/pkg/uhttp"
)

// TestKeepAliveTokenRecoversFromExpiredToken verifies that when the Jamf
// bearer token has fully expired, an API call transparently mints a fresh
// token from credentials instead of failing with 401. This reproduces the
// idle-then-provision scenario where keep-alive (which requires a valid token)
// returns 401 and cannot refresh a dead token.
func TestKeepAliveTokenRecoversFromExpiredToken(t *testing.T) {
	const (
		staleToken = "stale-expired-token"
		freshToken = "fresh-token"
	)

	var keepAliveCalls, tokenCalls, groupCalls int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case keepAliveUrlPath:
			// Token has expired -> keep-alive is rejected.
			atomic.AddInt32(&keepAliveCalls, 1)
			w.WriteHeader(http.StatusUnauthorized)

		case tokenUrlPath:
			// Re-auth from credentials should be used to recover.
			atomic.AddInt32(&tokenCalls, 1)
			if user, pass, ok := r.BasicAuth(); !ok || user != "svc" || pass != "secret" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"token":"` + freshToken + `","expires":"2099-01-01T00:00:00.000Z"}`))

		case "/JSSResource/usergroups/id/24":
			// The actual API call must carry the refreshed token.
			atomic.AddInt32(&groupCalls, 1)
			if got := r.Header.Get("Authorization"); got != "Bearer "+freshToken {
				t.Errorf("group request used %q, want bearer with fresh token", got)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"user_group":{"id":24,"name":"Aikido","is_smart":false,"users":[]}}`))

		default:
			t.Errorf("unexpected request path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client := NewClient(uhttp.NewBaseHttpClient(srv.Client()), "svc", "secret", staleToken, srv.URL)
	// Force keep-alive to run (it only fires when >5m since the last refresh).
	client.lastKeepAlive = time.Now().Add(-10 * time.Minute)

	group, err := client.GetUserGroupDetails(context.Background(), 24)
	if err != nil {
		t.Fatalf("GetUserGroupDetails returned error after token expiry: %v", err)
	}
	if group == nil || group.ID != 24 {
		t.Fatalf("unexpected group result: %+v", group)
	}

	if got := atomic.LoadInt32(&keepAliveCalls); got != 1 {
		t.Errorf("keep-alive calls = %d, want 1", got)
	}
	if got := atomic.LoadInt32(&tokenCalls); got != 1 {
		t.Errorf("token (re-auth) calls = %d, want 1", got)
	}
	if got := atomic.LoadInt32(&groupCalls); got != 1 {
		t.Errorf("group calls = %d, want 1", got)
	}
	if client.token != freshToken {
		t.Errorf("client token = %q, want refreshed token", client.token)
	}
}
