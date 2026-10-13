package agree

import (
	"crypto/ecdh"
	"crypto/rand"
)

func New() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}
