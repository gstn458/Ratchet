from ecdsa import NIST256p, SigningKey

sk = SigningKey.generate(curve=NIST256p)
signature = sk.sign(b"message")
vk = sk.get_verifying_key()
vk.verify(signature, b"message")
