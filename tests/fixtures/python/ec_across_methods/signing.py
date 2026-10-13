from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


class ECDSAKey:
    @classmethod
    def generate(cls):
        # Returned, never bound to a name that is used here. Every usage in
        # this file is signing, so it takes that.
        return cls(ec.generate_private_key(ec.SECP256R1()))

    def sign_ssh_data(self, data):
        return self.signing_key.sign(data, ec.ECDSA(hashes.SHA256()))

    def verify_ssh_sig(self, data, sig):
        self.verifying_key.verify(sig, data, ec.ECDSA(hashes.SHA256()))
