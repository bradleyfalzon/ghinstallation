package installationTransport

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

// acceptHeader is the GitHub Integrations Preview Accept header.
const (
	acceptHeader = "application/vnd.github.machine-man-preview+json"
	apiBaseURL   = "https://api.github.com"
)

// installationTransport provides a http.RoundTripper by wrapping an existing
// http.RoundTripper (that's shared between multiple installation transports to
// reuse underlying http connections), but provides GitHub Integration
// authentication as an installation.
//
// See https://developer.github.com/early-access/integrations/authentication/#as-an-installation
type InstallationTransport struct {
	BaseURL        string            // baseURL is the scheme and host for GitHub API, defaults to https://api.github.com
	client         *http.Client      // client is used to connect to GitHub to request for tokens
	tr             http.RoundTripper // tr is the underlying roundtripper being wrapped
	key            *rsa.PrivateKey   // key is the GitHub Integration's private key
	integrationID  int               // integrationID is the GitHub Integration's Installation ID
	installationID int               // installationID is the GitHub Integration's Installation ID
	token          *AccessToken      // token is the installation's access token
}

// AccessToken is an installation access token response from GitHub
type AccessToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

var _ http.RoundTripper = &InstallationTransport{}

// NewKeyFromFile returns an InstallationTransport using a private key from file.
func NewKeyFromFile(tr http.RoundTripper, integrationID, installationID int, privateKeyFile string) (*InstallationTransport, error) {
	privateKey, err := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("could not read private key: %s", err)
	}
	return New(tr, integrationID, installationID, privateKey)
}

func New(tr http.RoundTripper, integrationID, installationID int, privateKey []byte) (*InstallationTransport, error) {
	t := &InstallationTransport{
		tr:             tr,
		integrationID:  integrationID,
		installationID: installationID,
		BaseURL:        apiBaseURL,
	}
	var err error
	t.key, err = jwt.ParseRSAPrivateKeyFromPEM(privateKey)
	if err != nil {
		return nil, fmt.Errorf("could not parse private key: %s", err)
	}
	return t, nil
}

// RoundTrip implements http.RoundTripper interface.
func (t *InstallationTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.token == nil || t.token.ExpiresAt.Add(-time.Minute).Before(time.Now()) {
		// Token is not set or expired/nearly expired, so refresh
		if err := t.refreshToken(); err != nil {
			return nil, fmt.Errorf("could not refresh installation id %v's token: %s", t.installationID, err)
		}
	}

	req.Header.Set("Authorization", "token "+t.token.Token)
	req.Header.Set("Accept", acceptHeader)
	resp, err := t.tr.RoundTrip(req)
	return resp, err
}

func (t *InstallationTransport) refreshToken() error {
	// TODO these claims could probably be reused between installations before expiry
	claims := &jwt.StandardClaims{
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(time.Minute).Unix(),
		Issuer:    strconv.Itoa(t.integrationID),
	}
	bearer := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	ss, err := bearer.SignedString(t.key)
	if err != nil {
		return fmt.Errorf("could not sign jwt: %s", err)
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/installations/%v/access_tokens", t.BaseURL, t.installationID), nil)
	if err != nil {
		return fmt.Errorf("could not create request: %s", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", ss))
	req.Header.Set("Accept", acceptHeader)

	client := &http.Client{Transport: t.tr}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("could not get access_tokens from GitHub API for installation ID %v: %v", t.installationID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("received non 2xx response status %q when fetching %v", resp.Status, req.URL)
	}

	if err := json.NewDecoder(resp.Body).Decode(&t.token); err != nil {
		return err
	}

	return nil
}
