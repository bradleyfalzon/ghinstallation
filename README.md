# InstallationTransport

[![GoDoc](https://godoc.org/github.com/bradleyfalzon/installationTransport?status.svg)](https://godoc.org/github.com/bradleyfalzon/installationTransport)

`installationTransport` provides a `http.RoundTripper` to provide authentication as an installation for GitHub
Integrations.

See https://developer.github.com/early-access/integrations/authentication/

# Example

```go
// Shared transport to reuse TCP connections, wrapped by installationTransport.
tr := &http.Transport{}

itr, err := installationTransport.NewKeyFromFile(tr, 1, 99, "2016-10-19.private-key.pem")

// Use installationTransport with github.com/google/go-github
client := github.NewClient(http.Client{Transport: itr})
```

# License

[Unlicense](LICENSE) - feel free to copy/paste without attribution/preservation of license etc.

# Dependencies

- [github.com/dgrijalva/jwt-go](https://github.com/dgrijalva/jwt-go)
