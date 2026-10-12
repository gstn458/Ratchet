package keys

import (
	"crypto/ed25519"
	"crypto/rand"
)

func New() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}
