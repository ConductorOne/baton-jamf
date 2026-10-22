package jamf

import (
	"context"
	"fmt"
	"net/http"
	liburl "net/url"
	"time"

	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// NewBasicTokenSource mints bearer tokens with a local Jamf Pro account's username and password.
func NewBasicTokenSource(wrapper *uhttp.BaseHttpClient, instanceURL, username, password string) (oauth2.TokenSource, error) {
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
	// The expiry comes from Jamf's clock, so renew a minute early to absorb clock skew.
	return oauth2.ReuseTokenSourceWithExpiry(nil, source, time.Minute), nil
}

// NewAPIClientTokenSource exchanges a Jamf Pro API client's ID and secret for access tokens.
func NewAPIClientTokenSource(wrapper *uhttp.BaseHttpClient, instanceURL, clientID, clientSecret string) (oauth2.TokenSource, error) {
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
	return uhttp.NewClassifyingTokenSource(config.TokenSource(tokenCtx)), nil
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

// Token runs outside any request ctx because the token is shared across requests.
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
		return nil, fmt.Errorf("failed to parse token expiry %q: %w", target.Expires, err)
	}
	return &oauth2.Token{AccessToken: target.Token, TokenType: "Bearer", Expiry: expiry}, nil
}
