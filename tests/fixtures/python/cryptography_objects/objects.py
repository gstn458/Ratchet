from cryptography.hazmat.decrepit.ciphers import algorithms as decrepit
from cryptography.hazmat.primitives import hashes, hmac, padding as symmetric
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.hashes import SHA1

digest = hashes.Hash(hashes.MD5())
mac = hmac.HMAC(b"key", SHA1())
modern = hashes.Hash(hashes.SHA256())

tdes = Cipher(algorithms.TripleDES(b"k" * 24), mode=None)
rc4 = Cipher(algorithms.ARC4(b"key"), mode=None)
tdes_decrepit = Cipher(decrepit.TripleDES(b"k" * 24), mode=None)
rc4_decrepit = Cipher(decrepit.ARC4(b"key"), mode=None)


def sign(key, data):
    return key.sign(data, padding.PKCS1v15(), hashes.SHA256())


def sign_pss(key, data):
    return key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


OAEP_SHA1 = padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None)

# Symmetric block padding is not RSA.
padder = symmetric.PKCS7(128).padder()
