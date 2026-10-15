import jwt

ALGORITHMS = {"RS256": "rsa", "ES256K": "secp256k1", "HS512": "hmac"}


def issue(payload, key):
    return jwt.encode(payload, key, algorithm="PS256")


def read(token, key):
    return jwt.decode(token, key, algorithms=["ES384", "EdDSA"])


def encrypted():
    return {"alg": "RSA-OAEP", "enc": "A128CBC-HS256"}


NOTE = "sign with RS256"  # a sentence, not a name
LOWER = "rs256"           # JOSE names are case-sensitive
