package agree

import "golang.org/x/crypto/curve25519"

func Shared(scalar, point []byte) ([]byte, error) {
	return curve25519.X25519(scalar, point)
}
