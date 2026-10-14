package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

// Same package, but this file signs, so its key stays ECDSA.
func signingKey(digest []byte) ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return ecdsa.SignASN1(rand.Reader, key, digest)
}
