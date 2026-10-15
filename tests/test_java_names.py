"""JCA algorithm names to registry algorithms, one per primitive.

Names follow the Java Security Standard Algorithm Names specification; JCA
matches them without regard to case. These need no parser, so they run
whether or not tree-sitter is installed.
"""

import pytest

import ratchet

CASES = [
    # key pair generators, key factories, key agreement
    ("RSA", ["RSA"]), ("rsa", ["RSA"]), ("RSASSA-PSS", ["RSA"]),
    ("EC", ["EC"]), ("ECDSA", ["ECDSA"]), ("ECDH", ["ECDH"]),
    ("DSA", ["DSA"]), ("DH", ["DH"]), ("DiffieHellman", ["DH"]),
    ("Ed25519", ["Ed25519"]), ("X25519", ["X25519"]),
    # signatures: the key algorithm, then the hash when the registry has it
    ("SHA1withRSA", ["RSA", "SHA-1"]), ("SHA256withRSA", ["RSA", "SHA-256"]),
    ("SHA256withECDSA", ["ECDSA", "SHA-256"]), ("SHA1withDSA", ["DSA", "SHA-1"]),
    ("MD5withRSA", ["RSA", "MD5"]), ("NONEwithRSA", ["RSA"]),
    ("SHA512withRSA", ["RSA"]), ("SHA384withECDSA", ["ECDSA"]),
    ("SHA256withRSA/PSS", ["RSA", "SHA-256"]), ("SHA256withRSAandMGF1", ["RSA", "SHA-256"]),
    ("SHA256withECDSAinP1363Format", ["ECDSA", "SHA-256"]), ("SHA512/256withRSA", ["RSA"]),
    # Cipher transformations
    ("RSA/ECB/PKCS1Padding", ["RSA"]), ("RSA/ECB/OAEPWithSHA-1AndMGF1Padding", ["RSA", "SHA-1"]),
    ("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", ["RSA", "SHA-256"]),
    ("DESede/CBC/PKCS5Padding", ["3DES"]), ("DES/ECB/NoPadding", ["DES"]),
    ("AES/GCM/NoPadding", ["AES"]), ("AES_256/GCM/NoPadding", ["AES"]), ("RC4", ["RC4"]),
    ("ARCFOUR", ["RC4"]),
    # digests, MACs, key derivation, password-based encryption
    ("MD5", ["MD5"]), ("SHA-1", ["SHA-1"]), ("SHA1", ["SHA-1"]), ("SHA", ["SHA-1"]),
    ("SHA-256", ["SHA-256"]), ("SHA-512", []), ("HmacMD5", ["MD5"]), ("HmacSHA1", ["SHA-1"]),
    ("HmacSHA256", ["SHA-256"]), ("PBKDF2WithHmacSHA1", ["SHA-1"]),
    ("PBEWithMD5AndDES", ["MD5", "DES"]), ("PBEWithSHA1AndDESede", ["SHA-1", "3DES"]),
    ("PBEWithHmacSHA256AndAES_256", ["SHA-256", "AES"]),
    # the start of a name built at run time ("HmacSHA" + bits), not SHA-1
    ("HmacSHA", []), ("PBKDF2WithHmacSHA", []), ("SHAwithRSA", ["RSA"]),
    # not in the registry yet, or not an algorithm name
    ("EdDSA", []), ("XDH", []), ("Ed448", []), ("X448", []), ("", []), ("Banana", []),
]


@pytest.mark.parametrize("name,expected", CASES)
def test_jca_algorithms(name, expected):
    assert ratchet.jca_algorithms(name) == expected


def test_every_mapped_algorithm_is_in_the_registry():
    for algo in ratchet.JCA_NAMES.values():
        assert algo in ratchet.ALGORITHMS
    for algo in ratchet.JAVA_IMPORTS.values():
        assert algo in ratchet.ALGORITHMS


@pytest.mark.parametrize("literal,expected", [
    ("SHA256withRSA", [("RSA", None), ("SHA-256", None)]),
    ("RSASSA-PSS", [("RSA", None)]),
    ("DESede/CBC/PKCS5Padding", [("3DES", None)]),
    ("secp256r1", [("EC", "SECP256R1")]), ("prime256v1", [("EC", "SECP256R1")]),
    ("X25519", [("X25519", None)]), ("HmacSHA1", [("SHA-1", None)]),
    # too short or too common to claim outside getInstance
    ("RSA", []), ("EC", []), ("MD5", []), ("SHA-1", []), ("DES", []), ("AES", []),
    # not names at all
    ("use SHA256withRSA for new keys", []), ("rsa/keys/private", []), ("RSA/ECB", []),
])
def test_unambiguous_names(literal, expected):
    assert ratchet.jca_named(literal) == expected


def test_algorithm_names_never_fail_the_build():
    name = ratchet.Finding("RSA", "A.java", 1, 'x = "SHA256withRSA";', kind=ratchet.NAME)
    call = ratchet.Finding("RSA", "A.java", 2, 'Signature.getInstance("SHA256withRSA")')
    assert ratchet.ci_gate_count(ratchet.Scan([name], 1, [], False)) == 0
    assert ratchet.ci_gate_count(ratchet.Scan([name, call], 1, [], False)) == 1
