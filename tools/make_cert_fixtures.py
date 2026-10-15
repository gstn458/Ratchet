#!/usr/bin/env python3
"""Write the certificate and key fixtures under tests/fixtures/certs.

    python3 tools/make_cert_fixtures.py

Needs the cryptography package, which Ratchet itself never imports. Keys are
random, so a rerun writes different bytes; the goldens then need
regenerating, and the findings must not change. Every key here is a
throwaway made for these tests and protects nothing.
"""

import datetime
import os
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, mldsa, mlkem, rsa, x25519
from cryptography.x509.oid import NameOID

OUT = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "certs"
PEM, DER = serialization.Encoding.PEM, serialization.Encoding.DER
OPENSSH = serialization.Encoding.OpenSSH
PKCS8, TRAD = serialization.PrivateFormat.PKCS8, serialization.PrivateFormat.TraditionalOpenSSL
SPKI = serialization.PublicFormat.SubjectPublicKeyInfo
NONE = serialization.NoEncryption()
START = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
END = datetime.datetime(2036, 1, 1, tzinfo=datetime.timezone.utc)


def usage(**bits):
    names = ("digital_signature", "content_commitment", "key_encipherment", "data_encipherment",
             "key_agreement", "key_cert_sign", "crl_sign", "encipher_only", "decipher_only")
    return x509.KeyUsage(**{n: bits.get(n, False) for n in names})


def cert(key, cn, signer=None, key_usage=None, algorithm=hashes.SHA256()):
    """A certificate for key's public half, self-signed unless signer is given."""
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
               .public_key(key.public_key()).serial_number(1000 + len(cn))
               .not_valid_before(START).not_valid_after(END))
    if key_usage is not None:
        builder = builder.add_extension(key_usage, critical=True)
    signer = signer or key
    if isinstance(signer, (ed25519.Ed25519PrivateKey, mldsa.MLDSA65PrivateKey)):
        algorithm = None
    return builder.sign(signer, algorithm)


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def main():
    rsa2048 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa4096 = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    rsa1024 = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    p256 = ec.generate_private_key(ec.SECP256R1())
    p384 = ec.generate_private_key(ec.SECP384R1())
    p256b = ec.generate_private_key(ec.SECP256R1())
    edkey = ed25519.Ed25519PrivateKey.generate()
    dsakey = dsa.generate_private_key(key_size=2048)
    mlkey = mldsa.MLDSA65PrivateKey.generate()

    x = OUT / "x509"
    # RSA, a CA and a leaf it signed, in one file as a chain is usually kept.
    leaf = cert(rsa2048, "www.example.test", key_usage=usage(digital_signature=True, key_encipherment=True))
    ca = cert(rsa4096, "Example Test CA", key_usage=usage(key_cert_sign=True, crl_sign=True))
    write(x / "chain.pem", leaf.public_bytes(PEM) + ca.public_bytes(PEM))
    # EC: the key usage says whether the key signs or agrees keys.
    write(x / "ec_signing.crt", cert(p256, "signer.example.test", key_usage=usage(digital_signature=True))
          .public_bytes(PEM))
    write(x / "ec_agreement.pem", cert(p384, "kex.example.test", signer=rsa2048,
                                       key_usage=usage(key_agreement=True)).public_bytes(PEM))
    write(x / "ec_no_usage.der", cert(p256b, "unknown.example.test").public_bytes(DER))
    write(x / "ed25519.cer", cert(edkey, "ed.example.test").public_bytes(PEM))
    write(x / "dsa.crt", cert(dsakey, "dsa.example.test", key_usage=usage(digital_signature=True))
          .public_bytes(PEM))
    write(x / "mldsa65.pem", cert(mlkey, "pq.example.test").public_bytes(PEM))

    k = OUT / "keys"
    write(k / "server.key", p256.private_bytes(PEM, PKCS8, NONE))
    write(k / "legacy_rsa.key", rsa1024.private_bytes(PEM, TRAD, NONE))
    write(k / "ec_sec1.key", p384.private_bytes(PEM, TRAD, NONE))
    write(k / "encrypted.key", rsa2048.private_bytes(
        PEM, PKCS8, serialization.BestAvailableEncryption(b"fixture passphrase")))
    write(k / "public.pem", rsa4096.public_key().public_bytes(PEM, SPKI))
    write(k / "x25519.pem", x25519.X25519PrivateKey.generate().private_bytes(PEM, PKCS8, NONE))
    write(k / "mlkem768.pub", mlkem.MLKEM768PrivateKey.generate().public_key().public_bytes(PEM, SPKI))
    write(k / "id_rsa", rsa2048.private_bytes(PEM, serialization.PrivateFormat.OpenSSH, NONE))
    write(k / "id_ed25519.pub", edkey.public_key().public_bytes(OPENSSH, serialization.PublicFormat.OpenSSH)
          + b" fixture@example.test\n")
    write(k / "authorized_keys",
          b"# throwaway test keys\n"
          + rsa4096.public_key().public_bytes(OPENSSH, serialization.PublicFormat.OpenSSH) + b" ops@example.test\n"
          + p256.public_key().public_bytes(OPENSSH, serialization.PublicFormat.OpenSSH) + b" ci@example.test\n")
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "csr.example.test")]))
           .sign(p256b, hashes.SHA256()))
    write(k / "request.csr", csr.public_bytes(PEM))

    m = OUT / "malformed"
    write(m / "bad_base64.pem", b"-----BEGIN CERTIFICATE-----\nnot base64 at all!\n-----END CERTIFICATE-----\n")
    write(m / "truncated.der", cert(p256b, "cut.example.test").public_bytes(DER)[:120])
    write(m / "keynote.key", b"PK\x03\x04 a zip archive, as a Keynote .key file is")
    write(m / "translations.key", b"greeting=Hello\nfarewell=Goodbye\n")
    print(f"wrote fixtures under {OUT}", file=sys.stderr)


if __name__ == "__main__":
    main()
