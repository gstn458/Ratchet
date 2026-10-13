package gateway

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
)

func Key() (*rsa.PrivateKey, error) {
	_ = sha1.New()
	return rsa.GenerateKey(rand.Reader, 2048)
}
