package connector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	cfg "github.com/conductorone/baton-jamf/pkg/config"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/cli"
)

// The server has no username/password token endpoint, so Validate fails if New ignores the selected API client.
func TestNew_UsesSelectedAPIClient(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/oauth/token", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if _, err := writer.Write([]byte(`{"access_token":"api-client-token","token_type":"Bearer","expires_in":1200}`)); err != nil {
			t.Errorf("write token response: %v", err)
		}
	})
	mux.HandleFunc("/api/v1/auth", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if _, err := writer.Write([]byte(`{"authenticationType":"OAUTH"}`)); err != nil {
			t.Errorf("write token details: %v", err)
		}
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	jamfConfig := &cfg.Jamf{InstanceUrl: server.URL, JamfClientId: "client-id", JamfClientSecret: "client-secret"}
	jamfConnector, _, err := New(context.Background(), jamfConfig, &cli.ConnectorOpts{SelectedAuthMethod: cfg.APIClientGroup})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := jamfConnector.Validate(context.Background()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestManagedDeviceResourceTypeIsOptIn(t *testing.T) {
	annos := annotations.Annotations(resourceTypeManagedDevice.GetAnnotations())
	if !annos.Contains(&v2.OptInRequired{}) {
		t.Fatal("managedDevice resource type must carry the OptInRequired annotation")
	}
}

func TestResourceSyncersIncludeManagedDevice(t *testing.T) {
	j := &Jamf{}
	ids := make(map[string]bool)
	for _, rb := range j.ResourceSyncers(context.Background()) {
		ids[rb.ResourceType(context.Background()).GetId()] = true
	}
	for _, id := range []string{
		resourceTypeUser.Id,
		resourceTypeGroup.Id,
		resourceTypeUserAccount.Id,
		resourceTypeUserGroup.Id,
		resourceTypeRole.Id,
		resourceTypeSite.Id,
		resourceTypeManagedDevice.Id,
	} {
		if !ids[id] {
			t.Fatalf("expected %q to be registered as a resource syncer", id)
		}
	}
}
