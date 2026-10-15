package variants

import (
	des "example.com/legacy/des" // a project package, not crypto/des
	"example.com/legacy/ecdh"   // nor crypto/ecdh
)

func Old(key []byte) {
	des.NewCipher(key)
	ecdh.X25519()
}
