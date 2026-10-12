package scalar

import (
	"crypto/elliptic"
	"math/big"

	"golang.org/x/crypto/curve25519"
)

// Point encoding is direct crypto/elliptic use. curve25519.ScalarBaseMult in
// the same file is X25519 and must not be counted as crypto/elliptic.
func Encode(x, y *big.Int) []byte {
	return elliptic.Marshal(elliptic.P256(), x, y)
}

func Public(dst, scalar *[32]byte) {
	curve25519.ScalarBaseMult(dst, scalar)
}
