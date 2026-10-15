package jose

import "crypto/ecdsa"

const ECDH_ES = "ECDH-ES"

func agree(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) ([]byte, error) {
	k, err := priv.ECDH()
	if err != nil {
		return nil, err
	}
	p, err := pub.ECDH()
	if err != nil {
		return nil, err
	}
	return k.ECDH(p)
}
