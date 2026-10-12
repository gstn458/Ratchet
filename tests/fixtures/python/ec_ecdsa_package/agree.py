from ecdsa import ECDH, NIST256p, SigningKey

local = SigningKey.generate(curve=NIST256p)
ecdh = ECDH(curve=NIST256p, private_key=local)
