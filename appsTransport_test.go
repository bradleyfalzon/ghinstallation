package ghinstallation

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestNewAppsTransportKeyFromFile(t *testing.T) {
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

	_, err = NewAppsTransportKeyFromFile(&http.Transport{}, appID, tmpfile.Name())
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
}

type RoundTrip struct {
	rt func(*http.Request) (*http.Response, error)
}

func (r RoundTrip) RoundTrip(req *http.Request) (*http.Response, error) {
	return r.rt(req)
}

func TestAppsTransport(t *testing.T) {
	customHeader := "my-header"
	check := RoundTrip{
		rt: func(req *http.Request) (*http.Response, error) {
			h, ok := req.Header["Accept"]
			if !ok {
				t.Error("Header Accept not set")
			}
			want := []string{customHeader, acceptHeader}
			if diff := cmp.Diff(want, h); diff != "" {
				t.Errorf("HTTP Accept headers want->got: %s", diff)
			}
			return nil, nil
		},
	}

	tr, err := NewAppsTransport(check, appID, key)
	if err != nil {
		t.Fatalf("error creating transport: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com", new(bytes.Buffer))
	req.Header.Add("Accept", customHeader)
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("error calling RoundTrip: %v", err)
	}
}
