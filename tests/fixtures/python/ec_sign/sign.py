from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

key = ec.generate_private_key(ec.SECP256R1())
signature = key.sign(b"message", ec.ECDSA(hashes.SHA256()))
key.public_key().verify(signature, b"message", ec.ECDSA(hashes.SHA256()))

keyword_curve = ec.generate_private_key(curve=ec.SECP384R1())
