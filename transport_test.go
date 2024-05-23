package ghinstallation

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-github/v62/github"
)

const (
	installationID = 1
	appID          = 2
	token          = "abc123"
)

var key = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA0BUezcR7uycgZsfVLlAf4jXP7uFpVh4geSTY39RvYrAll0yh
q7uiQypP2hjQJ1eQXZvkAZx0v9lBYJmX7e0HiJckBr8+/O2kARL+GTCJDJZECpjy
97yylbzGBNl3s76fZ4CJ+4f11fCh7GJ3BJkMf9NFhe8g1TYS0BtSd/sauUQEuG/A
3fOJxKTNmICZr76xavOQ8agA4yW9V5hKcrbHzkfecg/sQsPMmrXixPNxMsqyOMmg
jdJ1aKr7ckEhd48ft4bPMO4DtVL/XFdK2wJZZ0gXJxWiT1Ny41LVql97Odm+OQyx
tcayMkGtMb1nwTcVVl+RG2U5E1lzOYpcQpyYFQIDAQABAoIBAAfUY55WgFlgdYWo
i0r81NZMNBDHBpGo/IvSaR6y/aX2/tMcnRC7NLXWR77rJBn234XGMeQloPb/E8iw
vtjDDH+FQGPImnQl9P/dWRZVjzKcDN9hNfNAdG/R9JmGHUz0JUddvNNsIEH2lgEx
C01u/Ntqdbk+cDvVlwuhm47MMgs6hJmZtS1KDPgYJu4IaB9oaZFN+pUyy8a1w0j9
RAhHpZrsulT5ThgCra4kKGDNnk2yfI91N9lkP5cnhgUmdZESDgrAJURLS8PgInM4
YPV9L68tJCO4g6k+hFiui4h/4cNXYkXnaZSBUoz28ICA6e7I3eJ6Y1ko4ou+Xf0V
csM8VFkCgYEA7y21JfECCfEsTHwwDg0fq2nld4o6FkIWAVQoIh6I6o6tYREmuZ/1
s81FPz/lvQpAvQUXGZlOPB9eW6bZZFytcuKYVNE/EVkuGQtpRXRT630CQiqvUYDZ
4FpqdBQUISt8KWpIofndrPSx6JzI80NSygShQsScWFw2wBIQAnV3TpsCgYEA3reL
L7AwlxCacsPvkazyYwyFfponblBX/OvrYUPPaEwGvSZmE5A/E4bdYTAixDdn4XvE
ChwpmRAWT/9C6jVJ/o1IK25dwnwg68gFDHlaOE+B5/9yNuDvVmg34PWngmpucFb/
6R/kIrF38lEfY0pRb05koW93uj1fj7Uiv+GWRw8CgYEAn1d3IIDQl+kJVydBKItL
tvoEur/m9N8wI9B6MEjhdEp7bXhssSvFF/VAFeQu3OMQwBy9B/vfaCSJy0t79uXb
U/dr/s2sU5VzJZI5nuDh67fLomMni4fpHxN9ajnaM0LyI/E/1FFPgqM+Rzb0lUQb
yqSM/ptXgXJls04VRl4VjtMCgYEAprO/bLx2QjxdPpXGFcXbz6OpsC92YC2nDlsP
3cfB0RFG4gGB2hbX/6eswHglLbVC/hWDkQWvZTATY2FvFps4fV4GrOt5Jn9+rL0U
elfC3e81Dw+2z7jhrE1ptepprUY4z8Fu33HNcuJfI3LxCYKxHZ0R2Xvzo+UYSBqO
ng0eTKUCgYEAxW9G4FjXQH0bjajntjoVQGLRVGWnteoOaQr/cy6oVii954yNMKSP
rezRkSNbJ8cqt9XQS+NNJ6Xwzl3EbuAt6r8f8VO1TIdRgFOgiUXRVNZ3ZyW8Hegd
kGTL0A6/0yAu9qQZlFbaD5bWhQo7eyx63u4hZGppBhkTSPikOYUPCH8=
-----END RSA PRIVATE KEY-----`)

func TestNew(t *testing.T) {
	var authed bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != acceptHeader {
			t.Fatalf("Request URI %q accept header got %q want: %q", r.RequestURI, r.Header.Get("Accept"), acceptHeader)
		}
		switch r.RequestURI {
		case fmt.Sprintf("/app/installations/%d/access_tokens", installationID):
			// respond with any token to installation transport
			js, _ := json.Marshal(accessToken{
				Token:     token,
				ExpiresAt: time.Now().Add(5 * time.Minute),
			})
			fmt.Fprintln(w, string(js))
			authed = true
		case "/auth/with/installation/token/endpoint":
			if want := "token " + token; r.Header.Get("Authorization") != want {
				t.Fatalf("Installation token got: %q want: %q", r.Header.Get("Authorization"), want)
			}
		default:
			t.Fatalf("unexpected URI: %q", r.RequestURI)
		}
	}))
	defer ts.Close()

	tr, err := New(&http.Transport{}, appID, installationID, key)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	tr.BaseURL = ts.URL

	// test id getter methods
	if tr.AppID() != appID {
		t.Fatalf("appID got: %q want: %q", tr.AppID(), appID)
	}

	if tr.InstallationID() != installationID {
		t.Fatalf("installationID got: %q want: %q", tr.InstallationID(), installationID)
	}

	client := http.Client{Transport: tr}
	_, err = client.Get(ts.URL + "/auth/with/installation/token/endpoint")
	if err != nil {
		t.Fatal("unexpected error from client:", err)
	}

	if !authed {
		t.Fatal("Expected fetch of access_token but none occurred")
	}

	// Check the token is reused by setting expires into far future
	tr.token.ExpiresAt = time.Now().Add(time.Hour)
	authed = false

	_, err = client.Get(ts.URL + "/auth/with/installation/token/endpoint")
	if err != nil {
		t.Fatal("unexpected error from client:", err)
	}

	if authed {
		t.Fatal("Unexpected fetch of access_token")
	}

	// Check the token is refreshed by setting expires into far past
	tr.token.ExpiresAt = time.Unix(0, 0)

	_, err = client.Get(ts.URL + "/auth/with/installation/token/endpoint")
	if err != nil {
		t.Fatal("unexpected error from client:", err)
	}

	if !authed {
		t.Fatal("Expected fetch of access_token but none occurred")
	}
}

func TestNewKeyFromFile(t *testing.T) {
	tmpfile, err := ioutil.TempFile("", "example")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name()) // clean up

	if _, err := tmpfile.Write(key); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = NewKeyFromFile(&http.Transport{}, appID, installationID, tmpfile.Name())
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
}

func TestNew_appendHeader(t *testing.T) {
	var headers http.Header
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers = r.Header
		fmt.Fprintln(w, `{}`) // dummy response that looks like json
	}))
	defer ts.Close()

	// Create a new request adding our own Accept header
	myheader := "my-header"
	req, err := http.NewRequest("GET", ts.URL+"/auth/with/installation/token/endpoint", nil)
	if err != nil {
		t.Fatal("unexpected error from http.NewRequest:", err)
	}
	req.Header.Add("Accept", myheader)

	tr, err := New(&http.Transport{}, appID, installationID, key)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	tr.BaseURL = ts.URL

	client := http.Client{Transport: tr}
	_, err = client.Do(req)
	if err != nil {
		t.Fatal("unexpected error from client:", err)
	}

	found := false
	for _, v := range headers["Accept"] {
		if v == myheader {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("could not find %v in request's accept headers: %v", myheader, headers["Accept"])
	}

	// Here we test that there isn't a second Accept header.
	// Though the Accept header 'application/vnd.github.v3+json' is used for most
	//  interactions with the GitHub API, having this header will force the
	//  GitHub API response as JSON, which we don't want when downloading a
	//  release (octet-stream)
	for _, v := range headers["Accept"] {
		if v == acceptHeader {
			t.Errorf("accept header '%s' should not be present when accept header '%s' is set: %v", acceptHeader, myheader, headers["Accept"])
			break
		}
	}
}

func TestRefreshTokenWithParameters(t *testing.T) {
	installationTokenOptions := &github.InstallationTokenOptions{
		RepositoryIDs: []int64{1234},
		Permissions: &github.InstallationPermissions{
			Contents: github.String("write"),
			Issues:   github.String("read"),
		},
	}

	// Convert InstallationTokenOptions into a ReadWriter to pass as an argument to http.NewRequest.
	body, err := GetReadWriter(installationTokenOptions)
	if err != nil {
		t.Fatalf("error calling GetReadWriter: %v", err)
	}

	// Convert io.ReadWriter to String without deleting body data.
	wantBody, _ := GetReadWriter(installationTokenOptions)
	wantBodyBytes := new(bytes.Buffer)
	wantBodyBytes.ReadFrom(wantBody)
	wantBodyString := wantBodyBytes.String()

	roundTripper := RoundTrip{
		rt: func(req *http.Request) (*http.Response, error) {
			// Convert io.ReadCloser to String without deleting body data.
			var gotBodyBytes []byte
			gotBodyBytes, _ = ioutil.ReadAll(req.Body)
			req.Body = ioutil.NopCloser(bytes.NewBuffer(gotBodyBytes))
			gotBodyString := string(gotBodyBytes)

			// Compare request sent with request received.
			if diff := cmp.Diff(wantBodyString, gotBodyString); diff != "" {
				t.Errorf("HTTP body want->got: %s", diff)
			}

			// Return acceptable access token.
			accessToken := accessToken{
				Token:     "token_string",
				ExpiresAt: time.Now(),
				Repositories: []github.Repository{{
					ID: github.Int64(1234),
				}},
				Permissions: github.InstallationPermissions{
					Contents: github.String("write"),
					Issues:   github.String("read"),
				},
			}
			tokenReadWriter, err := GetReadWriter(accessToken)
			if err != nil {
				return nil, fmt.Errorf("error converting token into io.ReadWriter: %+v", err)
			}
			tokenBody := ioutil.NopCloser(tokenReadWriter)
			return &http.Response{
				Body:       tokenBody,
				StatusCode: 200,
			}, nil
		},
	}

	tr, err := New(roundTripper, appID, installationID, key)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	tr.InstallationTokenOptions = installationTokenOptions

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/app/installations/%v/access_tokens", tr.BaseURL, tr.installationID), body)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("error calling RoundTrip: %v", err)
	}
}

func TestRefreshTokenWithTrailingSlashBaseURL(t *testing.T) {
	installationTokenOptions := &github.InstallationTokenOptions{
		RepositoryIDs: []int64{1234},
		Permissions: &github.InstallationPermissions{
			Contents: github.String("write"),
			Issues:   github.String("read"),
		},
	}

	tokenToBe := "token_string"

	// Convert io.ReadWriter to String without deleting body data.
	wantBody, _ := GetReadWriter(installationTokenOptions)
	wantBodyBytes := new(bytes.Buffer)
	wantBodyBytes.ReadFrom(wantBody)
	wantBodyString := wantBodyBytes.String()

	roundTripper := RoundTrip{
		rt: func(req *http.Request) (*http.Response, error) {
			if strings.Contains(req.URL.Path, "//") {
				return &http.Response{
					Body:       ioutil.NopCloser(strings.NewReader("Forbidden\n")),
					StatusCode: 401,
				}, fmt.Errorf("Got simulated 401 Github Forbidden response")
			}

			if req.URL.Path == "test_endpoint/" && req.Header.Get("Authorization") == fmt.Sprintf("token %s", tokenToBe) {
				return &http.Response{
					Body:       ioutil.NopCloser(strings.NewReader("Beautiful\n")),
					StatusCode: 200,
				}, nil
			}

			// Convert io.ReadCloser to String without deleting body data.
			var gotBodyBytes []byte
			gotBodyBytes, _ = ioutil.ReadAll(req.Body)
			req.Body = ioutil.NopCloser(bytes.NewBuffer(gotBodyBytes))
			gotBodyString := string(gotBodyBytes)

			// Compare request sent with request received.
			if diff := cmp.Diff(wantBodyString, gotBodyString); diff != "" {
				t.Errorf("HTTP body want->got: %s", diff)
			}

			// Return acceptable access token.
			accessToken := accessToken{
				Token:     tokenToBe,
				ExpiresAt: time.Now(),
				Repositories: []github.Repository{{
					ID: github.Int64(1234),
				}},
				Permissions: github.InstallationPermissions{
					Contents: github.String("write"),
					Issues:   github.String("read"),
				},
			}
			tokenReadWriter, err := GetReadWriter(accessToken)
			if err != nil {
				return nil, fmt.Errorf("error converting token into io.ReadWriter: %+v", err)
			}
			tokenBody := ioutil.NopCloser(tokenReadWriter)
			return &http.Response{
				Body:       tokenBody,
				StatusCode: 200,
			}, nil
		},
	}

	tr, err := New(roundTripper, appID, installationID, key)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	tr.InstallationTokenOptions = installationTokenOptions
	tr.BaseURL = "http://localhost/github/api/v3/"

	// Convert InstallationTokenOptions into a ReadWriter to pass as an argument to http.NewRequest.
	body, err := GetReadWriter(installationTokenOptions)
	if err != nil {
		t.Fatalf("error calling GetReadWriter: %v", err)
	}

	req, err := http.NewRequest("POST", "http://localhost/test_endpoint/", body)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	res, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("error calling RoundTrip: %v", err)
	}
	if res.StatusCode != 200 {
		t.Fatalf("Unexpected RoundTrip response code: %d", res.StatusCode)
	}
}

func TestRoundTripperContract(t *testing.T) {
	tr := &Transport{
		token: &accessToken{
			ExpiresAt: time.Now().Add(1 * time.Hour),
			Token:     "42",
		},
		mu: &sync.Mutex{},
		tr: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			if auth := req.Header.Get("Authorization"); auth != "token 42" {
				t.Errorf("got unexpected Authorization request header in parent RoundTripper: %q", auth)
			}
			return nil, nil
		}),
	}
	req, err := http.NewRequest("GET", "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "xxx")
	_, err = tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	if accept := req.Header.Get("Authorization"); accept != "xxx" {
		t.Errorf("got unexpected Authorization request header in caller: %q", accept)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (fn roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func TestExpiryAccessor(t *testing.T) {
	now := time.Now()
	future := now.Add(2 * time.Hour)
	futureRefresh := future.Add(-time.Minute)
	past := now.Add(-2 * time.Hour)
	pastRefresh := past.Add(-time.Minute)

	for _, tc := range []struct {
		name          string
		token         *accessToken
		expectErr     string
		expectExpiry  time.Time
		expectRefresh time.Time
	}{
		{
			name: "valid",
			token: &accessToken{
				Token:     token,
				ExpiresAt: future,
			},
			expectExpiry:  future,
			expectRefresh: futureRefresh,
		},
		{
			name: "expired",
			token: &accessToken{
				Token:     token,
				ExpiresAt: past,
			},
			expectExpiry:  past,
			expectRefresh: pastRefresh,
		},
		{
			name:      "unset",
			expectErr: "Expiry() = unknown, err: nil token",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := &Transport{token: tc.token}
			expiresAt, refreshAt, err := tr.Expiry()
			if err != nil {
				if tc.expectErr != err.Error() {
					t.Errorf("wrong error, expected=%q, actual=%q",
						tc.expectErr, err.Error())
				}
			} else {
				if tc.expectErr != "" {
					t.Fatalf("unexpected error: %v", err)
				}
			}
			if tc.expectExpiry != expiresAt {
				t.Errorf("expiresAt mismatch, expected=%v, actual=%v",
					tc.expectExpiry.String(), expiresAt.String())
			}
			if tc.expectRefresh != refreshAt {
				t.Errorf("refreshAt mismatch, expected=%v, actual=%v",
					tc.expectRefresh, refreshAt)
			}
		})
	}
}

func TestHTTPErrorUnwrap(t *testing.T) {
	wrappedError := errors.New("wrapped error")

	err := &HTTPError{
		RootCause: wrappedError,
	}

	if !errors.Is(err, wrappedError) {
		t.Errorf("HTTPError should be unwrapped to the root cause")
	}
}
