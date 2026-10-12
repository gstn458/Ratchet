import cryptography.hazmat.primitives.asymmetric.ec as curves
from cryptography.hazmat.primitives.asymmetric.ec import ECDH

private_key = curves.generate_private_key(curves.SECP256R1())
peer = curves.generate_private_key(curves.SECP256R1())
derived = peer.public_key()
shared = private_key.exchange(ECDH(), derived)
