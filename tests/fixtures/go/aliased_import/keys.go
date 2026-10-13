package keys

import (
	"crypto/rand"
	gorsa "crypto/rsa"
)

func New() (*gorsa.PrivateKey, error) {
	return gorsa.GenerateKey(rand.Reader, 2048)
}
