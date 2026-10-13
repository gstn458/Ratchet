package cipher

import (
	"crypto/aes"
	"crypto/rc4"
)

func Both(key []byte) {
	_, _ = rc4.NewCipher(key)
	_, _ = aes.NewCipher(key)
}
