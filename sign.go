package ghinstallation

import (
	"context"
	"crypto/rsa"

	jwt "github.com/golang-jwt/jwt/v4"
)

// Signer is a JWT token signer. This is a wrapper around [jwt.SigningMethod]
// with predetermined key material.
type Signer interface {
	// Sign signs the given claims and returns a JWT token string, as specified
	// by [jwt.Token.SignedString]
	Sign(claims jwt.Claims) (string, error)
}

// SignerWithContext is a JWT token signer. This is a wrapper around
// [jwt.SigningMethod] with predetermined key material.
type SignerWithContext interface {
	// SignContext signs the given claims and returns a JWT token string, as
	// specified by [jwt.Token.SignedString]. The signing operation should use the
	// provided context as appropriate.
	SignContext(ctx context.Context, claims jwt.Claims) (string, error)
}

// SignerWithContextAdapter is a simple [Signer] wrapper that allows it to act
// as a [SignerWithContext].
type SignerWithContextAdapter struct {
	Signer Signer
}

func (s SignerWithContextAdapter) SignContext(_ context.Context, claims jwt.Claims) (string, error) {
	return s.Signer.Sign(claims)
}

// RSASigner signs JWT tokens using RSA keys.
type RSASigner struct {
	method *jwt.SigningMethodRSA
	key    *rsa.PrivateKey
}

func NewRSASigner(method *jwt.SigningMethodRSA, key *rsa.PrivateKey) *RSASigner {
	return &RSASigner{
		method: method,
		key:    key,
	}
}

// Sign signs the JWT claims with the RSA key.
//
// Deprecated: Use [SignContext] instead.
func (s *RSASigner) Sign(claims jwt.Claims) (string, error) {
	return jwt.NewWithClaims(s.method, claims).SignedString(s.key)
}

// Sign signs the JWT claims with the RSA key.
func (s *RSASigner) SignContext(_ context.Context, claims jwt.Claims) (string, error) {
	return s.Sign(claims)
}
