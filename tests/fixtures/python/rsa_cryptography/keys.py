from cryptography.hazmat.primitives.asymmetric import rsa

with_size = rsa.generate_private_key(public_exponent=65537, key_size=2048)
also_sized = rsa.generate_private_key(public_exponent=65537, key_size=4096)


def from_config(bits):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)
