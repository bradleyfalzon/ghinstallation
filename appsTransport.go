package ghinstallation

import (
	"crypto/rsa"
	"fmt"
	"net/http"
	"strconv"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

type AppsTransport struct {
	BaseURL       string            // baseURL is the scheme and host for GitHub API, defaults to https://api.github.com
	Client        Client            // Client to use to refresh tokens, defaults to http.Client with provided transport
	tr            http.RoundTripper // tr is the underlying roundtripper being wrapped
	key           *rsa.PrivateKey   // key is the GitHub Integration's private key
	integrationID int               // integrationID is the GitHub Integration's Installation ID
}

func NewAppsTransport(tr http.RoundTripper, integrationID int, privateKey []byte) (*AppsTransport, error) {
	t := &AppsTransport{
		tr:            tr,
		integrationID: integrationID,
		BaseURL:       apiBaseURL,
		Client:        &http.Client{Transport: tr},
	}
	var err error
	t.key, err = jwt.ParseRSAPrivateKeyFromPEM(privateKey)
	if err != nil {
		return nil, fmt.Errorf("could not parse private key: %s", err)
	}
	return t, nil
}

// RoundTrip implements http.RoundTripper interface.
func (t *AppsTransport) RoundTrip(req *http.Request) (*http.Response, error) {

	// TODO check expiry

	// TODO these claims could probably be reused between installations before expiry
	claims := &jwt.StandardClaims{
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(time.Minute).Unix(),
		Issuer:    strconv.Itoa(t.integrationID),
	}
	bearer := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	ss, err := bearer.SignedString(t.key)
	if err != nil {
		return nil, fmt.Errorf("could not sign jwt: %s", err)
	}

	req.Header.Set("Authorization", "Bearer "+ss)
	req.Header.Set("Accept", acceptHeader)

	resp, err := t.tr.RoundTrip(req)
	return resp, err
}
