package connector

import (
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
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	return jamf.NewClient(uhttp.NewBaseHttpClient(server.Client()), "user", "pass", "test-token", server.URL)
}
