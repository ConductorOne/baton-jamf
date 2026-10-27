package connector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/conductorone/baton-jamf/pkg/jamf"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
)

// newTestJamfClient spins up an httptest.Server driven by handler and returns
// a real *jamf.Client pointed at it. Grant/Revoke provisioning is exercised
// through the same client the connector uses in production — mocking at the
// HTTP boundary rather than introducing a client interface the rest of the
// connector doesn't otherwise need. The server is closed automatically when
// the test ends.
func newTestJamfClient(t *testing.T, handler http.HandlerFunc) *jamf.Client {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/auth/token", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(writer).Encode(jamf.TokenResponse{Token: "test-token", Expires: "2100-01-01T00:00:00Z"}); err != nil {
			t.Errorf("encode token response: %v", err)
		}
	})
	mux.Handle("/", handler)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	wrapper := uhttp.NewBaseHttpClient(server.Client())
	tokenSource, err := jamf.NewBasicTokenSource(wrapper, server.URL, "user", "pass")
	if err != nil {
		t.Fatalf("NewBasicTokenSource: %v", err)
	}
	client, err := jamf.NewClient(wrapper, server.URL, tokenSource)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}
