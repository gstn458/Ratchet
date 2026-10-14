package signer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

// A different package (directory) with no key agreement: stays ECDSA.
func New() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}
