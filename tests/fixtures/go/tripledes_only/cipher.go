package cipher

import "crypto/des"

func Triple(key []byte) {
	_, _ = des.NewTripleDESCipher(key)
}
