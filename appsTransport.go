package ghinstallation

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
)

type signerFunc = func() (Signer, error)

// AppsTransport provides a http.RoundTripper by wrapping an existing
// http.RoundTripper and provides GitHub Apps authentication as a
// GitHub App.
//
// Client can also be overwritten, and is useful to change to one which
// provides retry logic if you do experience retryable errors.
//
// See https://developer.github.com/apps/building-integrations/setting-up-and-registering-github-apps/about-authentication-options-for-github-apps/
type AppsTransport struct {
	BaseURL    string            // BaseURL is the scheme and host for GitHub API, defaults to https://api.github.com
	Client     Client            // Client to use to refresh tokens, defaults to http.Client with provided transport
	tr         http.RoundTripper // tr is the underlying roundtripper being wrapped
	signerFunc signerFunc        // used at construction time to create the signer.
	signer     Signer            // signer signs JWT tokens.
	issuer     string            // issuer is the ClientID (preferred) or AppID (legacy) of the GitHub App
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

// deprecated: use [NewAppsTransportWithAllOptions] instead, passing "WithAppID(appID)".
func NewAppsTransportWithOptions(tr http.RoundTripper, appID int64, opts ...AppsTransportOption) (*AppsTransport, error) {
	allOpts := make([]AppsTransportOption, 0, len(opts))
	allOpts = append(allOpts, WithAppID(appID))
	allOpts = append(allOpts, opts...)

	return NewAppsTransportWithAllOptions(
		tr,
		allOpts...,
	)
}

// NewAppsTransportWithAllOptions creates a new AppsTransport instance with the
// provided options. Options allow the issuer and signer to be set as needed;
// see the [With*] option methods for further details.
func NewAppsTransportWithAllOptions(tr http.RoundTripper, opts ...AppsTransportOption) (*AppsTransport, error) {
	at := &AppsTransport{
		BaseURL: apiBaseURL,
		Client:  &http.Client{Transport: tr},
	}

	for _, fn := range opts {
		fn(at)
	}

	if at.issuer == "" {
		return nil, errors.New("appID or clientID must be provided")
	}

	if at.signerFunc == nil {
		return nil, errors.New("signer (or key) must be provided")
	}

	signer, err := at.signerFunc()
	if err != nil {
		return nil, fmt.Errorf("signer creation failed: %w", err)
	}

	at.signer = signer
	at.signerFunc = nil // once it's used, it's no longer needed

	return at, nil
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
// Deprecated: use [Issuer()] instead and specify the AppID as a string.
func (t *AppsTransport) AppID() int64 {
	return t.appID
}

// Issuer returns the appID or clientID of the GitHub app used by this
// transport.
func (t *AppsTransport) Issuer() string {
	return t.issuer
}

type AppsTransportOption func(*AppsTransport)

// Specify the AppID of the GitHub App. Either this or ClientID must be
// specified, but ClientID is now preferred.
func WithAppID(appID int64) AppsTransportOption {
	return func(at *AppsTransport) {
		at.appID = appID
		at.issuer = strconv.FormatInt(appID, 10)
	}
}

// WithClientID specifies the ClientID of the GitHub App. Either this or AppID
// must be specified, but ClientID is now preferred.
func WithClientID(clientID string) AppsTransportOption {
	return func(at *AppsTransport) {
		at.issuer = clientID
	}
}

// WithSigner configures the AppsTransport to use the given Signer for
// generating JWT tokens.
func WithSigner(signer Signer) AppsTransportOption {
	return func(at *AppsTransport) {
		at.signerFunc = func() (Signer, error) { return signer, nil }
	}
}

// WithPrivateKeyFile directs the transport to use the specified private key
// file for signing requests. The private key is loaded and processed as an RSA
// key in PEM format as provided by GitHub in the application settings.
func WithPrivateKeyFile(privateKeyFile string) AppsTransportOption {
	return func(at *AppsTransport) {
		at.signerFunc = currySignerFunc(createSignerFromFile, privateKeyFile)
	}
}

// WithPrivateKeyRaw directs the transport to use the specified private key for
// signing requests. The private key is loaded and processed as an RSA key in
// PEM format as provided by GitHub in the application settings.
func WithPrivateKeyRaw(key []byte) AppsTransportOption {
	return func(at *AppsTransport) {
		at.signerFunc = currySignerFunc(createSignerFromBytes, key)
	}
}

// WithPrivateKeyRaw directs the transport to use the specified private key for
// signing requests. The private key is provided by GitHub in the application
// settings.
func WithPrivateKey(key *rsa.PrivateKey) AppsTransportOption {
	return func(at *AppsTransport) {
		at.signerFunc = currySignerFunc(createSignerFromKey, key)
	}
}

func createSignerFromFile(privateKeyFile string) (Signer, error) {
	privateKey, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("could not read private key: %s", err)
	}

	return createSignerFromBytes(privateKey)
}

func createSignerFromBytes(rawKey []byte) (Signer, error) {
	key, err := jwt.ParseRSAPrivateKeyFromPEM(rawKey)
	if err != nil {
		return nil, fmt.Errorf("could not parse private key: %w", err)
	}

	return createSignerFromKey(key)
}

func createSignerFromKey(key *rsa.PrivateKey) (Signer, error) {
	return NewRSASigner(jwt.SigningMethodRS256, key), nil
}

// currySignerFunc allows the createSigner* functions to be simple, callable
// functions that can be used directly, while still supporting the function
// interface required for config options.
func currySignerFunc[T any](deferred func(T) (Signer, error), arg T) signerFunc {
	return func() (Signer, error) {
		return deferred(arg)
	}
}
