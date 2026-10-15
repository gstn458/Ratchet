package tokens

var supported = []string{"RS256", "ES512", "PS384"}

const wrapping = "ECDH-ES+A256KW"

// "HS256" in a comment is not a name
func Header() map[string]string {
	return map[string]string{"alg": "RSA1_5", "enc": "A256GCM", "note": "use RS256"}
}
