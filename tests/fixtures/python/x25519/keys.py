from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

key = X25519PrivateKey.generate()
peer = X25519PrivateKey.generate()
shared = key.exchange(peer.public_key())
