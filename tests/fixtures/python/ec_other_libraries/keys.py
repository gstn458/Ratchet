import ecdsa
from Crypto.PublicKey import ECC

sk = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)
key = ECC.generate(curve="P-256")
