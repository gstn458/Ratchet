package notes

import "crypto/sha256"

// rsa.GenerateKey(rand.Reader, 1024) in a line comment is ignored.

/*
   Block comments are not:
   rsa.GenerateKey(rand.Reader, 1024)
*/

func Sum(b []byte) [32]byte {
	return sha256.Sum256(b) // md5.Sum(b) in a trailing comment
}
