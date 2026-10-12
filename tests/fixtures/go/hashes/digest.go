package digest

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
)

func All(b []byte) {
	_ = md5.Sum(b)
	_ = sha1.New()
	_ = sha256.Sum256(b)
}
