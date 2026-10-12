from Crypto.PublicKey import DSA as PyDSA
from Crypto.PublicKey import RSA as PyRSA
from cryptography.hazmat.primitives.asymmetric import dh, dsa, ec, rsa

# cryptography: generate_private_key(public_exponent, key_size)
rsa_keyword = rsa.generate_private_key(public_exponent=65537, key_size=3072)
rsa_mixed = rsa.generate_private_key(65537, key_size=4096)

# cryptography: dsa.generate_private_key(key_size), dsa.generate_parameters(key_size)
dsa_positional = dsa.generate_private_key(2048)
dsa_params = dsa.generate_parameters(3072)

# cryptography: dh.generate_parameters(generator, key_size)
dh_positional = dh.generate_parameters(2, 2048)

# cryptography: ec.generate_private_key(curve)
ec_keyword_curve = ec.generate_private_key(curve=ec.SECP521R1())
ec_curve_class = ec.generate_private_key(ec.SECP384R1)

# PyCryptodome: RSA.generate(bits), DSA.generate(bits)
pycryptodome_rsa = PyRSA.generate(bits=2048)
pycryptodome_dsa = PyDSA.generate(2048)

# Not a literal: no parameter set can be claimed.
def from_config(n):
    return rsa.generate_private_key(65537, n)
