import rsa
from Crypto.PublicKey import RSA

pub, priv = rsa.newkeys(2048)
key = RSA.generate(3072)
