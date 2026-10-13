from nacl.public import PrivateKey
from nacl.signing import SigningKey

signing_key = SigningKey.generate()
box_key = PrivateKey.generate()
