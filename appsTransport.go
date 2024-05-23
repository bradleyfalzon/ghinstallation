package ghinstallation

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
)

// AppsTransport provides a http.RoundTripper by wrapping an existing
// http.RoundTripper and provides GitHub Apps authentication as a
// GitHub App.
//
// Client can also be overwritten, and is useful to change to one which
// provides retry logic if you do experience retryable errors.
//
// See https://developer.github.com/apps/building-integrations/setting-up-and-registering-github-apps/about-authentication-options-for-github-apps/
type AppsTransport struct {
	BaseURL string            // BaseURL is the scheme and host for GitHub API, defaults to https://api.github.com
	Client  Client            // Client to use to refresh tokens, defaults to http.Client with provided transport
	tr      http.RoundTripper // tr is the underlying roundtripper being wrapped
	signer  Signer            // signer signs JWT tokens.
	issuer  string            // issuer is the ClientID (preferred) or AppID (legacy) of the GitHub App
	// appID is the GitHub App's ID
	//
	// deprecated: kept only for backwards compatibility.
	appID int64
}

// NewAppsTransportKeyFromFile returns a AppsTransport using a private key from file.
func NewAppsTransportKeyFromFile(tr http.RoundTripper, appID int64, privateKeyFile string) (*AppsTransport, error) {
	return NewAppsTransportWithAllOptions(
		tr,
		WithAppID(appID),
		WithPrivateKeyFile(privateKeyFile),
	)
}

// NewAppsTransport returns a AppsTransport using private key. The key is parsed
// and if any errors occur the error is non-nil.
//
// The provided tr http.RoundTripper should be shared between multiple
// installations to ensure reuse of underlying TCP connections.
//
// The returned Transport's RoundTrip method is safe to be used concurrently.
func NewAppsTransport(tr http.RoundTripper, appID int64, privateKey []byte) (*AppsTransport, error) {
	return NewAppsTransportWithAllOptions(
		tr,
		WithAppID(appID),
		WithPrivateKeyRaw(privateKey),
	)
}

// NewAppsTransportFromPrivateKey returns an AppsTransport using a crypto/rsa.(*PrivateKey).
func NewAppsTransportFromPrivateKey(tr http.RoundTripper, appID int64, key *rsa.PrivateKey) *AppsTransport {
	t, _ := NewAppsTransportWithAllOptions(
		tr,
		WithAppID(appID),
		WithPrivateKey(key),
	)

	return t
}

// deprecated: use NewAppsTransportWithAllOptions instead
func NewAppsTransportWithOptions(tr http.RoundTripper, appID int64, opts ...AppsTransportOption) (*AppsTransport, error) {
	t := &AppsTransport{
		BaseURL: apiBaseURL,
		Client:  &http.Client{Transport: tr},
		tr:      tr,
		appID:   appID,
		//fixme
	}

	for _, fn := range opts {
		fn(t)
	}

	if t.signer == nil {
		return nil, errors.New("no signer provided")
	}

	return t, nil
}

func NewAppsTransportWithAllOptions(tr http.RoundTripper, opts ...AppsTransportOptionError) (*AppsTransport, error) {
	t := &AppsTransport{
		BaseURL: apiBaseURL,
		Client:  &http.Client{Transport: tr},
		tr:      tr,
	}

	for _, fn := range opts {
		err := fn(t)
		if err != nil {
			return nil, err
		}
	}

	if t.issuer == "" {
		return nil, errors.New("no appID or clientID provided")
	}

	if t.signer == nil {
		return nil, errors.New("no signer provided")
	}

	return t, nil
}

// RoundTrip implements http.RoundTripper interface.
func (t *AppsTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// GitHub rejects expiry and issue timestamps that are not an integer,
	// while the jwt-go library serializes to fractional timestamps.
	// Truncate them before passing to jwt-go.
	iss := time.Now().Add(-30 * time.Second).Truncate(time.Second)
	exp := iss.Add(2 * time.Minute)
	claims := &jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(iss),
		ExpiresAt: jwt.NewNumericDate(exp),
		Issuer:    t.issuer,
	}

	ss, err := t.signer.Sign(claims)
	if err != nil {
		return nil, fmt.Errorf("could not sign jwt: %s", err)
	}

	req.Header.Set("Authorization", "Bearer "+ss)
	req.Header.Add("Accept", acceptHeader)

	resp, err := t.tr.RoundTrip(req)
	return resp, err
}

// AppID returns the appID of the transport. This will return 0 if the transport
// is using a ClientID.
//
// Deprecated: use [Issuer()] instead
func (t *AppsTransport) AppID() int64 {
	return t.appID
}

// Issuer returns the appID or clientID of the GitHub app used by this
// transport.
func (t *AppsTransport) Issuer() string {
	return t.issuer
}

// deprecated: kept only for backwards compatibility.
type AppsTransportOption func(*AppsTransport)
type AppsTransportOptionError func(*AppsTransport) error

// Specify the AppID of the GitHub App. Either this or ClientID must be
// specified, but ClientID is now preferred.
func WithAppID(appID int64) AppsTransportOptionError {
	return func(at *AppsTransport) error {
		// backwards compatibility to support the AppID() getter
		at.appID = appID
		at.issuer = strconv.FormatInt(appID, 10)

		return nil
	}
}

// Specify the ClientID of the GitHub App. Either this or AppID must be
// specified, but ClientID is now preferred.
func WithClientID(clientID string) AppsTransportOptionError {
	return func(at *AppsTransport) error {
		at.issuer = clientID
		return nil
	}
}

func WithPrivateKeyFile(privateKeyFile string) AppsTransportOptionError {
	return func(at *AppsTransport) error {
		// deprecated function kept for go 1.13 compatibility
		privateKey, err := ioutil.ReadFile(privateKeyFile)
		if err != nil {
			return fmt.Errorf("could not read private key: %w", err)
		}

		return WithPrivateKeyRaw(privateKey)(at)
	}
}

func WithPrivateKeyRaw(key []byte) AppsTransportOptionError {
	return func(at *AppsTransport) error {
		key, err := jwt.ParseRSAPrivateKeyFromPEM(key)
		if err != nil {
			return fmt.Errorf("could not parse private key: %w", err)
		}

		return WithPrivateKey(key)(at)
	}
}

func WithPrivateKey(key *rsa.PrivateKey) AppsTransportOptionError {
	return func(at *AppsTransport) error {
		at.signer = NewRSASigner(jwt.SigningMethodRS256, key)

		return nil
	}
}

// WithSigner configures the AppsTransport to use the given Signer for generating JWT tokens.
func WithSigner(signer Signer) AppsTransportOption {
	return func(at *AppsTransport) {
		at.signer = signer
	}
}
