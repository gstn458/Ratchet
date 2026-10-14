from cryptography.hazmat.primitives.asymmetric.dsa import generate_private_key as dsa_generate_private_key
from cryptography.hazmat.primitives.asymmetric.ec import SECP384R1
from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key as ecdsa_generate_private_key
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key as rsa_generate_private_key

rsa_key = rsa_generate_private_key(65537, 4096)
dsa_key = dsa_generate_private_key(1024)
ec_key = ecdsa_generate_private_key(SECP384R1())
plain = generate_private_key(public_exponent=65537, key_size=2048)
