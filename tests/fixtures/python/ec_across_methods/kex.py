# Shaped like paramiko's kex_ecdh_nist.py and ecdsakey.py: the key is bound to
# an attribute in one method and used in another.
from cryptography.hazmat.primitives.asymmetric import ec


class KexNistp256:
    def start(self):
        self.P = ec.generate_private_key(ec.SECP256R1())
        self.Q_C = self.P.public_key()

    def parse_reply(self, server_key):
        return self.P.exchange(ec.ECDH(), server_key)
