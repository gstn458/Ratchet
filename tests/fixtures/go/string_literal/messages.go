package messages

import "fmt"

// No crypto is imported in this file. The string below mentions a package path.
func Help() {
	fmt.Println("this service no longer uses " + "crypto/rsa" + " for tokens")
	msg := "crypto/md5"
	_ = msg
}
