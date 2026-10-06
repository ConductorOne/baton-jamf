package jamf

import (
	"context"
	"io"
	"net/http"
	"testing"
)

// TestAddUserGroupMembers_RequestWiring covers the method, path, and body
// AddUserGroupMembers sends: PUT .../usergroups/id/{id} with a bare
// <user_additions> list of <user><id> elements.
func TestAddUserGroupMembers_RequestWiring(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody []byte
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read PUT body: %v", err)
		}
		gotBody = body
		w.WriteHeader(http.StatusCreated)
	})

	if err := client.AddUserGroupMembers(context.Background(), 301, []int{10, 11}); err != nil {
		t.Fatalf("AddUserGroupMembers: %v", err)
	}
	if gotMethod != http.MethodPut {
		t.Errorf("method = %q, want PUT", gotMethod)
	}
	if want := "/JSSResource/usergroups/id/301"; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
	want := "<user_group><user_additions><user><id>10</id></user><user><id>11</id></user></user_additions></user_group>"
	if got := string(gotBody); got != want {
		t.Errorf("PUT body = %s, want %s", got, want)
	}
}

// TestRemoveUserGroupMembers_RequestWiring covers RemoveUserGroupMembers'
// method, path, and body: PUT .../usergroups/id/{id} with a bare
// <user_deletions> list.
func TestRemoveUserGroupMembers_RequestWiring(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody []byte
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read PUT body: %v", err)
		}
		gotBody = body
		w.WriteHeader(http.StatusCreated)
	})

	if err := client.RemoveUserGroupMembers(context.Background(), 301, []int{10}); err != nil {
		t.Fatalf("RemoveUserGroupMembers: %v", err)
	}
	if gotMethod != http.MethodPut {
		t.Errorf("method = %q, want PUT", gotMethod)
	}
	if want := "/JSSResource/usergroups/id/301"; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
	want := "<user_group><user_deletions><user><id>10</id></user></user_deletions></user_group>"
	if got := string(gotBody); got != want {
		t.Errorf("PUT body = %s, want %s", got, want)
	}
}

// TestRemoveUserGroupMembers_NotFound_SurfacesNotFoundError covers the
// deleted-group case: a 404 must surface as IsNotFoundError, which Revoke
// relies on to treat a deleted group as already-revoked.
func TestRemoveUserGroupMembers_NotFound_SurfacesNotFoundError(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	err := client.RemoveUserGroupMembers(context.Background(), 999, []int{10})
	if !IsNotFoundError(err) {
		t.Errorf("want a NotFound error, got %v", err)
	}
}
