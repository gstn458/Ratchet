import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
backup = rsa.generate_private_key(public_exponent=65537, key_size=4096)
digest = hashlib.md5(b"etag").hexdigest()
