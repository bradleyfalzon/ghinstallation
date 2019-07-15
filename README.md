# ghinstallation

[![GoDoc](https://godoc.org/github.com/bradleyfalzon/ghinstallation?status.svg)](https://godoc.org/github.com/bradleyfalzon/ghinstallation)

`ghinstallation` provides `Transport`, which implements `http.RoundTripper` to
provide authentication as an installation for GitHub Apps.

This library is designed to provide automatic authentication for
https://github.com/google/go-github or your own HTTP client.

See
https://developer.github.com/apps/building-integrations/setting-up-and-registering-github-apps/about-authentication-options-for-github-apps/

# Example

Get the package:

```bash
go get -u github.com/bradleyfalzon/ghinstallation
```

Usage:

```go
import "github.com/bradleyfalzon/ghinstallation"

func main() {
    // Shared transport to reuse TCP connections.
    tr := http.DefaultTransport

    // Wrap the shared transport for use with the app ID 1 authenticating with installation ID 99.
    itr, err := ghinstallation.NewKeyFromFile(tr, 1, 99, "2016-10-19.private-key.pem")
    if err != nil {
        log.Fatal(err)
    }

    // Use installation transport with github.com/google/go-github
    client := github.NewClient(&http.Client{Transport: itr})
}
```

## What is app ID and installation ID

`app ID` is the GitHub App ID. \
You can check as following : \
Settings > Developer > settings > GitHub App > About item

`installation ID` is a part of WebHook request. \
You can get the number to check the request. \
Settings > Developer > settings > GitHub Apps > Advanced > Payload in Request
tab

```
WebHook request
...
  "installation": {
    "id": `installation ID`
  }
```

# License

[Apache 2.0](LICENSE)

# Dependencies

-   [github.com/dgrijalva/jwt-go](https://github.com/dgrijalva/jwt-go)
