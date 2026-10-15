package names

import (
	. "crypto/md5"
	_ "crypto/sha1"
)

func Digest(data []byte) [16]byte {
	return Sum(data)
}
