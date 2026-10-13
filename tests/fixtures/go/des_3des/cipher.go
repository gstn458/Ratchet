package cipher

import "crypto/des"

func Single(key []byte) {
	_, _ = des.NewCipher(key)
}

func Triple(key []byte) {
	_, _ = des.NewTripleDESCipher(key)
}
