package jamf

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// basicTokenHandler mints a numbered token per call that expires after lifetime.
func basicTokenHandler(t *testing.T, mints *atomic.Int32, lifetime time.Duration) http.HandlerFunc {
	t.Helper()
	return func(writer http.ResponseWriter, request *http.Request) {
		username, password, ok := request.BasicAuth()
		if request.Method != http.MethodPost || !ok || username != "user" || password != "pass" {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		count := mints.Add(1)
		writeTestJSON(t, writer, TokenResponse{
			Token:   fmt.Sprintf("token-%d", count),
			Expires: time.Now().Add(lifetime).UTC().Format(time.RFC3339Nano),
		})
	}
}

// bearerHandler answers 200 only when the request carries the latest minted token.
func bearerHandler(t *testing.T, mints *atomic.Int32, body any) http.HandlerFunc {
	t.Helper()
	return func(writer http.ResponseWriter, request *http.Request) {
		if want := fmt.Sprintf("Bearer token-%d", mints.Load()); request.Header.Get("Authorization") != want {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeTestJSON(t, writer, body)
	}
}

func writeTestJSON(t *testing.T, writer http.ResponseWriter, body any) {
	t.Helper()
	writer.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(writer).Encode(body); err != nil {
		t.Errorf("encode response: %v", err)
	}
}

type tokenSourceConstructor func(wrapper *uhttp.BaseHttpClient, instanceURL, id, secret string) (*TokenSource, error)

func newAuthTestClient(t *testing.T, mux *http.ServeMux, constructor tokenSourceConstructor, id, secret string) *Client {
	t.Helper()
	server := httptest.NewUnstartedServer(mux)
	// Jamf Cloud speaks HTTP/2, which doesn't rewind a resent request body.
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)

	wrapper := uhttp.NewBaseHttpClient(server.Client())
	tokenSource, err := constructor(wrapper, server.URL, id, secret)
	if err != nil {
		t.Fatalf("token source: %v", err)
	}
	client, err := NewClient(wrapper, server.URL, tokenSource)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

// An expired token is replaced on the next request instead of wedging the client.
func TestBasicAuth_ExpiredTokenIsReMinted(t *testing.T) {
	var mints atomic.Int32
	mux := http.NewServeMux()
	// 5s is inside the one-minute early expiry, so every request sees an expired token.
	mux.HandleFunc(tokenUrlPath, basicTokenHandler(t, &mints, 5*time.Second))
	mux.HandleFunc("/JSSResource/users/id/42", bearerHandler(t, &mints, UserResponse{}))
	client := newAuthTestClient(t, mux, NewBasicTokenSource, "user", "pass")
	ctx := WithFreshReads(context.Background())

	for i := 0; i < 3; i++ {
		if _, err := client.GetUserDetails(ctx, 42); err != nil {
			t.Fatalf("GetUserDetails call %d: %v", i+1, err)
		}
	}
	if got := mints.Load(); got != 3 {
		t.Errorf("token mints = %d, want 3", got)
	}
}

func TestBasicAuth_ConcurrentRequestsShareOneToken(t *testing.T) {
	var mints atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc(tokenUrlPath, basicTokenHandler(t, &mints, 20*time.Minute))
	mux.HandleFunc("/JSSResource/users/id/42", bearerHandler(t, &mints, UserResponse{}))
	client := newAuthTestClient(t, mux, NewBasicTokenSource, "user", "pass")
	ctx := WithFreshReads(context.Background())

	var waitGroup sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			if _, err := client.GetUserDetails(ctx, 42); err != nil {
				errs <- err
			}
		}()
	}
	waitGroup.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("GetUserDetails: %v", err)
	}
	if got := mints.Load(); got != 1 {
		t.Errorf("token mints = %d, want 1", got)
	}
}

// A token Jamf rejects before its expiry is replaced, and the request is resent once with its body.
func TestDoRequest_RejectedTokenIsRenewed(t *testing.T) {
	var mints atomic.Int32
	var bodiesMutex sync.Mutex
	var bodies []string
	mux := http.NewServeMux()
	mux.HandleFunc(tokenUrlPath, basicTokenHandler(t, &mints, 20*time.Minute))
	mux.HandleFunc("/JSSResource/users/id/42", func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		bodiesMutex.Lock()
		bodies = append(bodies, string(body))
		bodiesMutex.Unlock()
		if request.Header.Get("Authorization") != "Bearer token-2" {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		writer.WriteHeader(http.StatusCreated)
	})
	client := newAuthTestClient(t, mux, NewBasicTokenSource, "user", "pass")

	if err := client.UpdateUserSites(context.Background(), 42, nil); err != nil {
		t.Fatalf("UpdateUserSites: %v", err)
	}
	if got := mints.Load(); got != 2 {
		t.Errorf("token mints = %d, want 2", got)
	}
	bodiesMutex.Lock()
	defer bodiesMutex.Unlock()
	if len(bodies) != 2 || bodies[0] == "" || bodies[1] != bodies[0] {
		t.Errorf("request bodies = %q, want the same non-empty body twice", bodies)
	}
}

// A zero expiry would make oauth2 reuse the token forever.
func TestBasicAuth_UnparseableExpiryFallsBack(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc(tokenUrlPath, func(writer http.ResponseWriter, request *http.Request) {
		writeTestJSON(t, writer, TokenResponse{Token: "token-1", Expires: "soon"})
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	tokenSource, err := NewBasicTokenSource(uhttp.NewBaseHttpClient(server.Client()), server.URL, "user", "pass")
	if err != nil {
		t.Fatalf("NewBasicTokenSource: %v", err)
	}

	token, err := tokenSource.Token()
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if expiresIn := time.Until(token.Expiry); expiresIn < 14*time.Minute || expiresIn > 15*time.Minute {
		t.Errorf("token expires in %v, want about 15m", expiresIn)
	}
}

func TestAPIClientAuth_SendsCredentialsInForm(t *testing.T) {
	var mints atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc(oauthTokenUrlPath, func(writer http.ResponseWriter, request *http.Request) {
		if err := request.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		if request.Header.Get("Authorization") != "" {
			t.Errorf("token request sent an Authorization header; want the credentials in the form only")
		}
		if request.PostForm.Get("grant_type") != "client_credentials" ||
			request.PostForm.Get("client_id") != "client-id" ||
			request.PostForm.Get("client_secret") != "client-secret" {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		count := mints.Add(1)
		writeTestJSON(t, writer, map[string]any{
			"access_token": fmt.Sprintf("token-%d", count),
			"token_type":   "Bearer",
			"expires_in":   1200,
		})
	})
	mux.HandleFunc("/JSSResource/users/id/42", bearerHandler(t, &mints, UserResponse{}))
	client := newAuthTestClient(t, mux, NewAPIClientTokenSource, "client-id", "client-secret")

	if _, err := client.GetUserDetails(context.Background(), 42); err != nil {
		t.Fatalf("GetUserDetails: %v", err)
	}
}

// A token endpoint 404 must not read as NotFound, or Revoke and Delete would report success.
func TestAuth_TokenErrors(t *testing.T) {
	cases := []struct {
		name        string
		tokenPath   string
		constructor tokenSourceConstructor
		statusCode  int
		body        string
		want        codes.Code
		wantMessage string
	}{
		{"username-password rejected", tokenUrlPath, NewBasicTokenSource, http.StatusUnauthorized, `{"error":"invalid_client"}`, codes.Unauthenticated, "failed to get a Jamf token"},
		{"api-client rejected", oauthTokenUrlPath, NewAPIClientTokenSource, http.StatusUnauthorized, `{"error":"invalid_client"}`, codes.Unauthenticated, "failed to get a Jamf token"},
		{"username-password endpoint missing", tokenUrlPath, NewBasicTokenSource, http.StatusNotFound, "", codes.InvalidArgument, "check the instance URL"},
		{"api-client endpoint missing", oauthTokenUrlPath, NewAPIClientTokenSource, http.StatusNotFound, "", codes.InvalidArgument, "check the instance URL"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			var tokenRequests atomic.Int32
			mux := http.NewServeMux()
			mux.HandleFunc(testCase.tokenPath, func(writer http.ResponseWriter, request *http.Request) {
				tokenRequests.Add(1)
				writer.Header().Set("Content-Type", "application/json")
				writer.WriteHeader(testCase.statusCode)
				if _, err := writer.Write([]byte(testCase.body)); err != nil {
					t.Errorf("write response: %v", err)
				}
			})
			client := newAuthTestClient(t, mux, testCase.constructor, "id", "wrong")

			_, err := client.GetTokenDetails(context.Background())
			if got := status.Code(err); got != testCase.want {
				t.Fatalf("code = %v, want %v (err: %v)", got, testCase.want, err)
			}
			if !strings.Contains(err.Error(), testCase.wantMessage) {
				t.Errorf("error %q does not contain %q", err, testCase.wantMessage)
			}
			// A retry would repeat a rejected login, which can lock the account.
			if got := tokenRequests.Load(); got != 1 {
				t.Errorf("token requests = %d, want 1", got)
			}
		})
	}
}

// A 401 renews the token and retries once; only the Classic API then reports a missing privilege.
func TestDoRequest_401Mapping(t *testing.T) {
	cases := []struct {
		name string
		path string
		call func(client *Client) error
		want codes.Code
	}{
		{
			name: "classic API",
			path: "/JSSResource/users/id/7",
			call: func(client *Client) error { return client.UpdateUserSites(context.Background(), 7, nil) },
			want: codes.PermissionDenied,
		},
		{
			name: "pro API",
			path: authUrlPath,
			call: func(client *Client) error {
				_, err := client.GetTokenDetails(context.Background())
				return err
			},
			want: codes.Unauthenticated,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			var mints, hits atomic.Int32
			mux := http.NewServeMux()
			mux.HandleFunc(tokenUrlPath, basicTokenHandler(t, &mints, 20*time.Minute))
			mux.HandleFunc(testCase.path, func(writer http.ResponseWriter, request *http.Request) {
				hits.Add(1)
				writer.WriteHeader(http.StatusUnauthorized)
			})
			client := newAuthTestClient(t, mux, NewBasicTokenSource, "user", "pass")

			err := testCase.call(client)
			if got := status.Code(err); got != testCase.want {
				t.Fatalf("code = %v, want %v (err: %v)", got, testCase.want, err)
			}
			if gotMints, gotHits := mints.Load(), hits.Load(); gotMints != 2 || gotHits != 2 {
				t.Errorf("token mints = %d and requests = %d, want 2 and 2", gotMints, gotHits)
			}
		})
	}
}

// When the renewed login fails, the client reports the login error, not the request's 401.
func TestDoRequest_RenewFailure(t *testing.T) {
	cases := []struct {
		name       string
		statusCode int
		want       codes.Code
	}{
		{"token endpoint missing", http.StatusNotFound, codes.InvalidArgument},
		{"credentials rejected", http.StatusUnauthorized, codes.Unauthenticated},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			var mints atomic.Int32
			mux := http.NewServeMux()
			mux.HandleFunc(tokenUrlPath, func(writer http.ResponseWriter, request *http.Request) {
				if mints.Add(1) > 1 {
					writer.WriteHeader(testCase.statusCode)
					return
				}
				writeTestJSON(t, writer, TokenResponse{Token: "token-1", Expires: time.Now().Add(20 * time.Minute).UTC().Format(time.RFC3339)})
			})
			mux.HandleFunc("/JSSResource/users/id/7", func(writer http.ResponseWriter, request *http.Request) {
				writer.WriteHeader(http.StatusUnauthorized)
			})
			client := newAuthTestClient(t, mux, NewBasicTokenSource, "user", "pass")

			err := client.UpdateUserSites(context.Background(), 7, nil)
			if got := status.Code(err); got != testCase.want {
				t.Fatalf("code = %v, want %v (err: %v)", got, testCase.want, err)
			}
		})
	}
}

func TestDoRequest_DecodeErrorOmitsBody(t *testing.T) {
	var mints atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc(tokenUrlPath, basicTokenHandler(t, &mints, 20*time.Minute))
	mux.HandleFunc("/JSSResource/users/id/42", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/html")
		if _, err := writer.Write([]byte("<html>jane.doe@example.com</html>")); err != nil {
			t.Errorf("write response: %v", err)
		}
	})
	client := newAuthTestClient(t, mux, NewBasicTokenSource, "user", "pass")

	_, err := client.GetUserDetails(context.Background(), 42)
	if err == nil {
		t.Fatal("GetUserDetails: want a decode error")
	}
	if strings.Contains(err.Error(), "jane.doe") || !strings.Contains(err.Error(), "body omitted (33 bytes)") {
		t.Errorf("decode error %q must omit the body and report its size", err)
	}
}

// Every constructor rejects a bad URL before credentials are sent to it.
func TestConstructors_ValidateInstanceURL(t *testing.T) {
	wrapper := uhttp.NewBaseHttpClient(http.DefaultClient)
	constructors := map[string]func(instanceURL string) error{
		"NewClient": func(instanceURL string) error {
			_, err := NewClient(wrapper, instanceURL, nil)
			return err
		},
		"NewBasicTokenSource": func(instanceURL string) error {
			_, err := NewBasicTokenSource(wrapper, instanceURL, "user", "pass")
			return err
		},
		"NewAPIClientTokenSource": func(instanceURL string) error {
			_, err := NewAPIClientTokenSource(wrapper, instanceURL, "client-id", "client-secret")
			return err
		},
	}
	cases := []struct {
		instanceURL string
		valid       bool
	}{
		{"https://yourcompany.jamfcloud.com", true},
		{"https://jamf.example.com:8443/", true},
		{"http://yourcompany.jamfcloud.com", false},
		{"http://localhost:8090", true},
		{"http://127.0.0.1:8090", true},
		{"yourcompany.jamfcloud.com", false},
		{"ftp://yourcompany.jamfcloud.com", false},
		{"", false},
		{" https://yourcompany.jamfcloud.com", false},
		{"https://yourcompany.jamfcloud.com\n", false},
	}
	for name, construct := range constructors {
		for _, testCase := range cases {
			t.Run(fmt.Sprintf("%s/%q", name, testCase.instanceURL), func(t *testing.T) {
				err := construct(testCase.instanceURL)
				if testCase.valid && err != nil {
					t.Fatalf("%q: %v", testCase.instanceURL, err)
				}
				if !testCase.valid && status.Code(err) != codes.InvalidArgument {
					t.Fatalf("%q error = %v, want InvalidArgument", testCase.instanceURL, err)
				}
			})
		}
	}
}
