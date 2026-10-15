package names

import (
	"crypto/rand"
	gorsa "crypto/rsa"

	rsa "example.com/legacy/rsa" // not crypto/rsa: a project package with the same name
)

func Sign(key *gorsa.PrivateKey, digest []byte) ([]byte, error) {
	return gorsa.SignPKCS1v15(rand.Reader, key, 0, digest)
}

func Legacy() {
	rsa.GenerateKey(rand.Reader, 1024)
}
