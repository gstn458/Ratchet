from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

# Generated and serialised. Nothing in this file shows whether it will sign or
# agree keys, so it must not be reported as ECDSA.
key = ec.generate_private_key(ec.SECP256R1())
pem = key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
)
