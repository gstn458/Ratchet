from Crypto.Hash import SHAKE128
from Crypto.Protocol.DH import key_agreement
from Crypto.PublicKey import ECC


def kdf(x):
    return SHAKE128.new(x).read(32)


static = ECC.generate(curve="P-256")
peer = ECC.generate(curve="P-256").public_key()
session_key = key_agreement(static_priv=static, static_pub=peer, kdf=kdf)
