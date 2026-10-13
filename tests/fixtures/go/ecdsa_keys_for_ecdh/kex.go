package kex

// Shaped like golang.org/x/crypto/ssh/kex.go: ECDH done with keys from
// ecdsa.GenerateKey and a raw ScalarMult, the idiom before crypto/ecdh.
import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"io"
	"math/big"
)

func Agree(curve elliptic.Curve, rand io.Reader, x, y *big.Int) ([]byte, error) {
	ephKey, err := ecdsa.GenerateKey(curve, rand)
	if err != nil {
		return nil, err
	}
	if x.Sign() > 0 { // big.Int.Sign, not a signature
		_ = x
	}
	secret, _ := curve.ScalarMult(x, y, ephKey.D.Bytes())
	return secret.Bytes(), nil
}
