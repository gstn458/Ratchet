from Crypto.Cipher import AES, ARC4, DES, DES3
from Crypto.Hash import MD5, SHA1

des = DES.new(b"8bytekey", DES.MODE_ECB)
tdes = DES3.new(b"0123456789abcdef01234567", DES3.MODE_CBC)
rc4 = ARC4.new(b"key")
aes = AES.new(b"0123456789abcdef", AES.MODE_GCM)
md5 = MD5.new(b"data")
sha1 = SHA1.new(b"data")

from Crypto.Cipher import DES as SingleDES
from Crypto.Hash.MD5 import new as md5_new
from Crypto.PublicKey import RSA

renamed = SingleDES.new(b"8bytekey", SingleDES.MODE_ECB)
digest = md5_new(b"data")
# Not a cipher or hash module: RSA keys are not made with .new
key = RSA.import_key(open("key.pem").read())
