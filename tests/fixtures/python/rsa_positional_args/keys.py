from cryptography.hazmat.primitives.asymmetric import rsa

# Positional form: the first argument is the public exponent, not the key size.
key = rsa.generate_private_key(65537, 2048)
