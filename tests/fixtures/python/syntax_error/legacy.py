# Python 2 syntax. ast.parse fails, so this file is skipped without notice today.
import md5
print "digest", md5.new("x").hexdigest()
from Crypto.PublicKey import RSA
key = RSA.generate(1024)
