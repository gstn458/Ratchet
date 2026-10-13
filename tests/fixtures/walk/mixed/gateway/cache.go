package gateway

import "crypto/sha256"

func CacheKey(b []byte) [32]byte { return sha256.Sum256(b) }
