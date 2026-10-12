package ops

import (
	"crypto"
	"crypto/aes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"

	"golang.org/x/crypto/curve25519"
)

func RSA(priv *rsa.PrivateKey, digest []byte, bits int) {
	sig, _ := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest)
	_ = rsa.VerifyPKCS1v15(&priv.PublicKey, crypto.SHA256, digest, sig)
	pss, _ := rsa.SignPSS(rand.Reader, priv, crypto.SHA256, digest, nil)
	_ = rsa.VerifyPSS(&priv.PublicKey, crypto.SHA256, digest, pss, nil)
	ct, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, &priv.PublicKey, digest, nil)
	_, _ = rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, ct, nil)
	_, _ = rsa.EncryptPKCS1v15(rand.Reader, &priv.PublicKey, digest)
	_, _ = rsa.GenerateKey(rand.Reader, bits)
}

func ECDSA(priv *ecdsa.PrivateKey, digest []byte) {
	sig, _ := ecdsa.SignASN1(rand.Reader, priv, digest)
	_ = ecdsa.VerifyASN1(&priv.PublicKey, digest, sig)
}

func Ed25519(priv ed25519.PrivateKey, msg []byte) {
	sig := ed25519.Sign(priv, msg)
	_ = ed25519.Verify(priv.Public().(ed25519.PublicKey), msg, sig)
}

func DSA() {
	var params dsa.Parameters
	_ = dsa.GenerateParameters(&params, rand.Reader, dsa.L2048N256)
}

func X25519(scalar, point []byte) {
	_, _ = curve25519.X25519(scalar, point)
}

func AES(key []byte) [32]byte {
	_, _ = aes.NewCipher(key)
	return sha256.Sum256(key)
}
