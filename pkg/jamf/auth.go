package jamf

import (
	"context"
	"net/http"
	liburl "net/url"
	"sync"
	"time"

	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// TokenSource reuses a Jamf token until it is about to expire. Renew drops it when Jamf rejects it earlier.
type TokenSource struct {
	newCache        func() oauth2.TokenSource
	mu              sync.Mutex
	cache           oauth2.TokenSource
	lastAccessToken string
}

func newTokenSource(newCache func() oauth2.TokenSource) *TokenSource {
	return &TokenSource{newCache: newCache, cache: newCache()}
}

func (s *TokenSource) Token() (*oauth2.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	token, err := s.cache.Token()
	if err != nil {
		return nil, err
	}
	s.lastAccessToken = token.AccessToken
	return token, nil
}

// Renew drops the cached token only if it is still the rejected one, so concurrent 401s get one new token, not one each.
func (s *TokenSource) Renew(rejected string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastAccessToken == rejected {
		s.cache = s.newCache()
	}
}

// NewBasicTokenSource mints bearer tokens with a local Jamf Pro account's username and password.
func NewBasicTokenSource(wrapper *uhttp.BaseHttpClient, instanceURL, username, password string) (*TokenSource, error) {
	tokenURL, err := tokenEndpoint(instanceURL, tokenUrlPath)
	if err != nil {
		return nil, err
	}
	source := &basicTokenSource{
		wrapper:  wrapper,
		tokenURL: tokenURL,
		username: username,
		password: password,
	}
	return newTokenSource(func() oauth2.TokenSource {
		// The expiry comes from Jamf's clock, so renew a minute early to absorb clock skew.
		return oauth2.ReuseTokenSourceWithExpiry(nil, source, time.Minute)
	}), nil
}

// NewAPIClientTokenSource exchanges a Jamf Pro API client's ID and secret for access tokens via
// POST /api/v1/oauth/token: https://developer.jamf.com/jamf-pro/docs/client-credentials
func NewAPIClientTokenSource(wrapper *uhttp.BaseHttpClient, instanceURL, clientID, clientSecret string) (*TokenSource, error) {
	tokenURL, err := tokenEndpoint(instanceURL, oauthTokenUrlPath)
	if err != nil {
		return nil, err
	}
	config := clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     tokenURL.String(),
		AuthStyle:    oauth2.AuthStyleInParams,
	}
	// clientcredentials keeps this ctx for every refresh, so it must never be cancelled.
	tokenCtx := context.WithValue(context.Background(), oauth2.HTTPClient, wrapper.HttpClient)
	return newTokenSource(func() oauth2.TokenSource {
		return uhttp.NewClassifyingTokenSource(config.TokenSource(tokenCtx))
	}), nil
}

// tokenEndpoint validates instanceURL before any credentials are sent to it.
func tokenEndpoint(instanceURL, path string) (*liburl.URL, error) {
	if err := validateInstanceURL(instanceURL); err != nil {
		return nil, err
	}
	urlString, err := liburl.JoinPath(instanceURL, path)
	if err != nil {
		return nil, err
	}
	return liburl.Parse(urlString)
}

type basicTokenSource struct {
	wrapper  *uhttp.BaseHttpClient
	tokenURL *liburl.URL
	username string
	password string
}

// Token mints a token via POST /api/v1/auth/token: https://developer.jamf.com/jamf-pro/reference/post_v1-auth-token
// It runs outside any request ctx because the token is shared across requests.
func (s *basicTokenSource) Token() (*oauth2.Token, error) {
	request, err := s.wrapper.NewRequest(
		context.Background(),
		http.MethodPost,
		s.tokenURL,
		uhttp.WithAcceptJSONHeader(),
		uhttp.WithContentTypeJSONHeader(),
	)
	if err != nil {
		return nil, err
	}
	request.SetBasicAuth(s.username, s.password)

	var target TokenResponse
	response, err := s.wrapper.Do(request, uhttp.WithJSONResponse(&target))
	if err != nil {
		return nil, err
	}
	if err := response.Body.Close(); err != nil {
		return nil, err
	}

	expiry, err := time.Parse(time.RFC3339, target.Expires)
	if err != nil {
		// Jamf's schema doesn't guarantee expires; assume less than its 20-minute default lifetime.
		expiry = time.Now().Add(15 * time.Minute)
	}
	return &oauth2.Token{AccessToken: target.Token, TokenType: "Bearer", Expiry: expiry}, nil
}
