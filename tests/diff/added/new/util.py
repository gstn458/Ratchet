from cryptography.hazmat.primitives.asymmetric import rsa


def public(key):
    return key.public_key()
