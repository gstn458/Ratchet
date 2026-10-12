package agree

import (
	"crypto/ecdh"
	"crypto/rand"
)

func NIST() (*ecdh.PrivateKey, error) {
	return ecdh.P256().GenerateKey(rand.Reader)
}

func Curve25519() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}
