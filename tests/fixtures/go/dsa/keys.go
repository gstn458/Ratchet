package keys

import (
	"crypto/dsa"
	"crypto/rand"
)

func New() error {
	var params dsa.Parameters
	return dsa.GenerateParameters(&params, rand.Reader, dsa.L2048N256)
}
