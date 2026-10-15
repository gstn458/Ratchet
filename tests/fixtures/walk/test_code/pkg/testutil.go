package pkg

import "crypto/md5"

var _ = md5.Sum([]byte("y"))
