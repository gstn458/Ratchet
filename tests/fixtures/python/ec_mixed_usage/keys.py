from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

signer = ec.generate_private_key(ec.SECP256R1())
signature = signer.sign(b"message", ec.ECDSA(hashes.SHA256()))

agreer = ec.generate_private_key(ec.SECP384R1())
peer = ec.generate_private_key(ec.SECP384R1())
shared = agreer.exchange(ec.ECDH(), peer.public_key())

# One key of each kind in the file, and this one is never used, so neither the
# import nor this key can be attributed.
spare = ec.generate_private_key(ec.SECP521R1())
