package names

import (
	"crypto/rand"
	ec "crypto/ecdsa"
	ell "crypto/elliptic"
)

func Point(key *ec.PrivateKey) []byte {
	return ell.Marshal(key.Curve, key.X, key.Y)
}

func SignIt(key *ec.PrivateKey, digest []byte) ([]byte, error) {
	k, _ := ec.GenerateKey(ell.P256(), rand.Reader)
	_ = k
	return ec.SignASN1(rand.Reader, key, digest)
}
