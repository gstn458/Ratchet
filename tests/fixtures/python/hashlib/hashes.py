import hashlib

hashlib.md5(b"data")
hashlib.sha1(b"data")
hashlib.new("md5")
hashlib.new("SHA1")
hashlib.new("sha256")
hashlib.sha256(b"data")  # not recorded today: only md5/sha1 are matched by name
