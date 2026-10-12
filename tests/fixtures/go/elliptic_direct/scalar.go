package scalar

import (
	"crypto/elliptic"
	"math/big"
)

// Direct curve arithmetic with no ecdsa or ecdh import. Not recorded today.
func Mul(k []byte) (*big.Int, *big.Int) {
	curve := elliptic.P256()
	return curve.ScalarBaseMult(k)
}
