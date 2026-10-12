from cryptography.hazmat.primitives.asymmetric import ec

private_key = ec.generate_private_key(ec.SECP384R1())
peer_public_key = ec.generate_private_key(ec.SECP384R1()).public_key()
shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
