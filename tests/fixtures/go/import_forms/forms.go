package forms

import "crypto/sha1"

import r "crypto/rsa"

import (
	"crypto/rand"
	// "crypto/rc4" is commented out and is not imported.
	m "crypto/md5" // trailing comment
	_ `crypto/sha256`
	/* "crypto/des" */
)

var banner = `
  this tool used to import "crypto/dsa"
`

type Config struct {
	Hash string `json:"hash" doc:"crypto/ed25519 is not used"`
}

func Use() {
	_ = sha1.New()
	_, _ = r.GenerateKey(rand.Reader, 2048)
	_ = m.New()
	_ = "import \"crypto/ecdsa\""
}
