package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

// A test in the same package. Production ECDH evidence elsewhere does not
// reach it; only evidence in this file would.
func TestKey(t *testing.T) {
	if _, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
}
