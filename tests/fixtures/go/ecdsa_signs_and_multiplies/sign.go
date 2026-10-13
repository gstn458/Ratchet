package sign

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
)

// Signs with the key, so it stays ECDSA even though the file also does a
// raw scalar multiplication.
func Both(digest []byte, x, y *big.Int) ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	_, _ = elliptic.P256().ScalarMult(x, y, key.D.Bytes())
	return ecdsa.SignASN1(rand.Reader, key, digest)
}
