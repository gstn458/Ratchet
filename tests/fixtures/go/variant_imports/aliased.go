package variants

import (
	goecdh "crypto/ecdh"
	stddes "crypto/des"
)

func Agree() {
	k, _ := goecdh.P256().GenerateKey(nil)
	_ = k
	stddes.NewTripleDESCipher(make([]byte, 24))
}
