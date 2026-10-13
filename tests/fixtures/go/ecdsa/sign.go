package sign

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

func Sign(digest []byte) ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return ecdsa.SignASN1(rand.Reader, key, digest)
}
