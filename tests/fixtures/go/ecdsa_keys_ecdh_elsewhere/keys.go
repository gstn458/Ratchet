package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

// Shaped like go-jose: the ephemeral key for ECDH-ES comes from
// ecdsa.GenerateKey here, and the key agreement happens in agree.go.
func ephemeral() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}
