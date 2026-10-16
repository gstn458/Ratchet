"""Key handling."""

import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa


digest = hashlib.md5(b"etag").hexdigest()

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
