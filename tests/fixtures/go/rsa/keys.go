package keys

import (
	"crypto/rand"
	"crypto/rsa"
)

func Fixed() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func FromConfig(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}
