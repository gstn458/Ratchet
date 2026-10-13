from cryptography.hazmat.primitives.asymmetric import rsa
import hashlib

signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
legacy = rsa.generate_private_key(public_exponent=65537, key_size=1024)
etag = hashlib.md5(b"body").hexdigest()
