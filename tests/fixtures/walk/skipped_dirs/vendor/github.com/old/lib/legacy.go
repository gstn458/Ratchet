package lib

import "crypto/des"

func Old(key []byte) { _, _ = des.NewCipher(key) }
