package jamf

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	liburl "net/url"
	"testing"
)

func TestGetComputersInventory_QueryEncoding(t *testing.T) {
	var gotURL *liburl.URL
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotURL = r.URL
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ComputersInventoryResponse{TotalCount: 0})
	})

	_, err := client.GetComputersInventory(context.Background(), 2, 50, ComputerInventorySections)
	if err != nil {
		t.Fatalf("GetComputersInventory: %v", err)
	}

	if got := gotURL.Path; got != computersInventoryUrlPath {
		t.Errorf("path = %q, want %q", got, computersInventoryUrlPath)
	}
	q := gotURL.Query()
	if got := q.Get("page"); got != "2" {
		t.Errorf("page = %q, want %q", got, "2")
	}
	if got := q.Get("page-size"); got != "50" {
		t.Errorf("page-size = %q, want %q", got, "50")
	}
	if got := q["section"]; len(got) != len(ComputerInventorySections) {
		t.Errorf("section params = %v, want %v", got, ComputerInventorySections)
	} else {
		for i, s := range ComputerInventorySections {
			if got[i] != s {
				t.Errorf("section[%d] = %q, want %q", i, got[i], s)
			}
		}
	}
}

func TestGetMobileDevices_QueryEncoding(t *testing.T) {
	var gotURL *liburl.URL
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotURL = r.URL
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(MobileDevicesResponse{TotalCount: 0})
	})

	_, err := client.GetMobileDevices(context.Background(), 3, 25)
	if err != nil {
		t.Fatalf("GetMobileDevices: %v", err)
	}

	if got := gotURL.Path; got != mobileDevicesUrlPath {
		t.Errorf("path = %q, want %q", got, mobileDevicesUrlPath)
	}
	q := gotURL.Query()
	if got := q.Get("page"); got != "3" {
		t.Errorf("page = %q, want %q", got, "3")
	}
	if got := q.Get("page-size"); got != "25" {
		t.Errorf("page-size = %q, want %q", got, "25")
	}
}

func TestGetComputerInventoryDetail_IssuesGET(t *testing.T) {
	var gotPath, gotMethod string
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ComputerInventory{ID: "17", UserAndLocation: &ComputerUserAndLocation{Username: "jappleseed"}})
	})

	detail, err := client.GetComputerInventoryDetail(context.Background(), "17")
	if err != nil {
		t.Fatalf("GetComputerInventoryDetail: %v", err)
	}
	if gotMethod != http.MethodGet {
		t.Errorf("method = %q, want GET", gotMethod)
	}
	if want := "/api/v4/computers-inventory-detail/17"; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
	if detail.UserAndLocation == nil || detail.UserAndLocation.Username != "jappleseed" {
		t.Errorf("unexpected detail: %+v", detail)
	}
}

func TestGetMobileDeviceDetail_IssuesGET(t *testing.T) {
	var gotPath, gotMethod string
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(MobileDeviceDetail{ID: "3", Location: &MobileDeviceLocation{Username: "jappleseed"}})
	})

	detail, err := client.GetMobileDeviceDetail(context.Background(), "3")
	if err != nil {
		t.Fatalf("GetMobileDeviceDetail: %v", err)
	}
	if gotMethod != http.MethodGet {
		t.Errorf("method = %q, want GET", gotMethod)
	}
	if want := "/api/v2/mobile-devices/3/detail"; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
	if detail.Location == nil || detail.Location.Username != "jappleseed" {
		t.Errorf("unexpected detail: %+v", detail)
	}
}

// TestSetComputerAssignedUser_PATCHBody_AllFiveKeysIncludingEmpty covers the
// computer PATCH body: all five userAndLocation keys are always sent as
// plain strings, including empty ones for fields the assignee lacks — Jamf
// treats an omitted key as a no-op, so clearing or leaving blank a field
// requires explicitly sending "".
func TestSetComputerAssignedUser_PATCHBody_AllFiveKeysIncludingEmpty(t *testing.T) {
	var gotBody []byte
	var gotMethod, gotPath string
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read PATCH body: %v", err)
		}
		gotBody = body
		w.WriteHeader(http.StatusNoContent)
	})

	err := client.SetComputerAssignedUser(context.Background(), "17", ComputerAssignedUserFields{Username: "jappleseed"})
	if err != nil {
		t.Fatalf("SetComputerAssignedUser: %v", err)
	}
	if gotMethod != http.MethodPatch {
		t.Errorf("method = %q, want PATCH", gotMethod)
	}
	if want := "/api/v4/computers-inventory-detail/17"; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
	want := `{"userAndLocation":{"username":"jappleseed","realname":"","email":"","position":"","phone":""}}` + "\n"
	if string(gotBody) != want {
		t.Errorf("PATCH body = %q, want %q", string(gotBody), want)
	}
}

// TestSetComputerAssignedUser_204NoBody_TreatedAsSuccess covers the v4 PATCH
// endpoint's documented response shape: 204 with no body (v1 answered 200
// with the updated record). doRequestWithJSONMethod must not try to decode
// a response body here since the caller passes a nil target.
func TestSetComputerAssignedUser_204NoBody_TreatedAsSuccess(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	if err := client.SetComputerAssignedUser(context.Background(), "17", ComputerAssignedUserFields{}); err != nil {
		t.Fatalf("SetComputerAssignedUser: %v", err)
	}
}

// TestSetMobileDeviceAssignedUser_PATCHBody_LocationUsernameOnly covers the
// mobile PATCH body: only location.username is ever sent — Jamf
// auto-populates realname/email/position/phone from the directory user, so
// the connector has no slot to send them from.
func TestSetMobileDeviceAssignedUser_PATCHBody_LocationUsernameOnly(t *testing.T) {
	var gotBody []byte
	var gotMethod, gotPath string
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read PATCH body: %v", err)
		}
		gotBody = body
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"3"}`))
	})

	if err := client.SetMobileDeviceAssignedUser(context.Background(), "3", "jappleseed"); err != nil {
		t.Fatalf("SetMobileDeviceAssignedUser: %v", err)
	}
	if gotMethod != http.MethodPatch {
		t.Errorf("method = %q, want PATCH", gotMethod)
	}
	if want := "/api/v2/mobile-devices/3"; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
	want := `{"location":{"username":"jappleseed"}}` + "\n"
	if string(gotBody) != want {
		t.Errorf("PATCH body = %q, want %q", string(gotBody), want)
	}
}

// TestSetMobileDeviceAssignedUser_EmptyUsername_ClearsExplicitly covers
// Revoke's clearing path: "" is sent explicitly (never omitted) since Jamf
// treats a missing key as a no-op.
func TestSetMobileDeviceAssignedUser_EmptyUsername_ClearsExplicitly(t *testing.T) {
	var gotBody []byte
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read PATCH body: %v", err)
		}
		gotBody = body
		w.WriteHeader(http.StatusOK)
	})

	if err := client.SetMobileDeviceAssignedUser(context.Background(), "3", ""); err != nil {
		t.Fatalf("SetMobileDeviceAssignedUser: %v", err)
	}
	want := `{"location":{"username":""}}` + "\n"
	if string(gotBody) != want {
		t.Errorf("PATCH body = %q, want %q", string(gotBody), want)
	}
}
