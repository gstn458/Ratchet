"""Certificates and key files: the parts the goldens under tests/fixtures/certs
do not reach on their own."""

import base64
import json
import subprocess
import sys

import pytest

import ratchet
from conftest import FIXTURES, REPO_ROOT

RATCHET = str(REPO_ROOT / "ratchet.py")
CERTS = FIXTURES / "certs"


def tlv(tag, content):
    n = len(content)
    length = bytes([n]) if n < 0x80 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes(
        (n.bit_length() + 7) // 8, "big")
    return bytes([tag]) + length + content


def oid(dotted):
    parts = [int(p) for p in dotted.split(".")]
    out = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.append(0x80 | (p & 0x7F))
            p >>= 7
        out += bytes(reversed(chunk))
    return tlv(0x06, out)


def pem(label, der):
    body = base64.encodebytes(der).decode()
    return f"-----BEGIN {label}-----\n{body}-----END {label}-----\n"


def scan(tmp_path, name, content):
    path = tmp_path / name
    path.write_bytes(content.encode() if isinstance(content, str) else content)
    return ratchet.scan_key_file(str(path))


def test_key_file_names():
    for name in ("server.pem", "ca.CRT", "site.cer", "a.der", "tls.key", "id_ed25519.pub", "req.csr",
                 "id_rsa", "authorized_keys", "key.p8"):
        assert ratchet.is_key_file(name), name
    for name in ("keys.py", "known_hosts", "id_rsa.txt", "README", "cert.go"):
        assert not ratchet.is_key_file(name), name


def test_key_oids_come_from_the_registry():
    assert ratchet.KEY_OIDS["1.2.840.113549.1.1.1"] == ("RSA", None)
    assert ratchet.KEY_OIDS["1.2.840.10045.2.1"] == ("EC", None)
    assert ratchet.KEY_OIDS["2.16.840.1.101.3.4.3.18"] == ("ML-DSA", "65")
    assert ratchet.KEY_OIDS["2.16.840.1.101.3.4.4.2"] == ("ML-KEM", "768")
    # Hash and cipher OIDs are not key algorithms.
    assert "1.3.14.3.2.26" not in ratchet.KEY_OIDS


def test_unknown_key_algorithm_is_unparsed_not_guessed(tmp_path):
    # dhpublicnumber (RFC 3279) is not in the registry: say so, claim nothing.
    spki = tlv(0x30, tlv(0x30, oid("1.2.840.10046.2.1")) + tlv(0x03, b"\x00\x02\x01\x05"))
    with pytest.raises(ratchet.Unparsed, match="1.2.840.10046.2.1 is not in the registry"):
        scan(tmp_path, "dh.pem", pem("PUBLIC KEY", spki))


def test_unknown_key_algorithm_in_der_is_unparsed_with_its_oid(tmp_path):
    spki = tlv(0x30, tlv(0x30, oid("1.2.840.10046.2.1")) + tlv(0x03, b"\x00\x02\x01\x05"))
    with pytest.raises(ratchet.Unparsed, match="1.2.840.10046.2.1 is not in the registry"):
        scan(tmp_path, "dh.key", spki)


def test_python_error_wording_does_not_reach_the_output(tmp_path):
    with pytest.raises(ratchet.Unparsed, match="^CERTIFICATE at line 2 is not valid base64$"):
        scan(tmp_path, "x.pem", "\n-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n")
    with pytest.raises(ratchet.Unparsed, match="^PUBLIC KEY at line 1 could not be read: "):
        scan(tmp_path, "y.pem", pem("PUBLIC KEY", b"\x30\x02\x30\x00"))


def test_ec_key_with_explicit_curve_parameters(tmp_path):
    # SEC 1 lets [0] hold the curve itself instead of naming it (RFC 5915 forbids
    # it for new keys, but files like this exist): EC, curve unknown.
    explicit = tlv(0x30, tlv(0x02, b"\x01") + tlv(0x30, b""))
    key = tlv(0x30, tlv(0x02, b"\x01") + tlv(0x04, b"\x07" * 32) + tlv(0xA0, explicit))
    found = scan(tmp_path, "ec.pem", pem("EC PRIVATE KEY", key))
    assert [(f.algorithm, f.params, f.kind) for f in found] == [("EC", None, ratchet.PRIVATE_KEY)]


def test_legacy_encrypted_pem_names_its_algorithm(tmp_path):
    text = ("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\n"
            "QUJDREVGR0g=\n-----END RSA PRIVATE KEY-----\n")
    found = scan(tmp_path, "old.key", text)
    assert [(f.algorithm, f.params, f.kind, f.snippet) for f in found] == [
        ("RSA", None, ratchet.PRIVATE_KEY, "RSA PRIVATE KEY (encrypted)")]


def test_encrypted_pkcs8_key_is_recorded_without_an_algorithm(tmp_path):
    found = ratchet.scan_key_file(str(CERTS / "keys" / "encrypted.key"))
    assert list(found) == []
    assert found.encrypted == [(1, "ENCRYPTED PRIVATE KEY")]


def test_private_key_material_never_reaches_the_output():
    path = CERTS / "keys" / "legacy_rsa.key"
    body = "".join(path.read_text().splitlines()[1:-1])
    for f in ratchet.scan_key_file(str(path)):
        assert f.snippet == "RSA PRIVATE KEY"
    r = subprocess.run([sys.executable, RATCHET, str(CERTS / "keys"), "--json"], capture_output=True, text=True)
    assert body[:40] not in r.stdout and body[-40:] not in r.stdout


def test_pem_among_other_text(tmp_path):
    cert = (CERTS / "x509" / "ec_signing.crt").read_text()
    found = scan(tmp_path, "bundle.pem", "# issued for the signer\nsubject=CN signer\n\n" + cert)
    assert [(f.algorithm, f.params, f.line) for f in found] == [("ECDSA", "SECP256R1", 4)]


def test_ssh_options_and_certificate_types(tmp_path):
    line = (CERTS / "keys" / "id_ed25519.pub").read_text().split()
    found = scan(tmp_path, "authorized_keys",
                 f'from="10.0.0.0/8",no-pty {line[0]} {line[1]} deploy\n# a comment\n\nnot a key line\n')
    assert [(f.algorithm, f.line, f.snippet) for f in found] == [("Ed25519", 1, "ssh-ed25519 key deploy")]


def test_ssh_line_with_mismatched_type_is_ignored(tmp_path):
    line = (CERTS / "keys" / "id_ed25519.pub").read_text().split()
    assert list(scan(tmp_path, "keys.pub", f"ssh-rsa {line[1]} liar\n")) == []


def test_files_that_are_not_key_material_are_passed_over(tmp_path):
    assert list(scan(tmp_path, "slides.key", b"PK\x03\x04\x00\x00binary")) == []
    assert list(scan(tmp_path, "strings.key", "hello=world\n")) == []
    assert list(scan(tmp_path, "blob.key", b"\x30\x03\x02\x01\x00")) == []  # DER-ish, not a key


def test_truncated_der_with_a_der_extension_is_unparsed(tmp_path):
    with pytest.raises(ratchet.Unparsed, match="not a DER certificate or key"):
        scan(tmp_path, "cut.cer", b"\x30\x82\x01\x00\x30")


@pytest.mark.parametrize("data", [b"\x30\x84\xff\xff\xff\xff", b"\x30\x05\x02\x01", b"\x1f\x01\x00", b"\x30"])
def test_der_reader_rejects_malformed_input(data):
    with pytest.raises(ratchet.DerError):
        ratchet.der_sequence(data, ratchet.der_children(data, 0, len(data))[0])


def test_key_material_never_gates(tmp_path):
    (tmp_path / "server.key").write_bytes((CERTS / "keys" / "server.key").read_bytes())
    (tmp_path / "chain.pem").write_bytes((CERTS / "x509" / "chain.pem").read_bytes())
    r = subprocess.run([sys.executable, RATCHET, str(tmp_path), "--fail-on-vulnerable"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout
    scan_ = ratchet.walk(str(tmp_path))
    assert ratchet.ci_gate_count(scan_) == 0
    levels = {r["level"] for r in ratchet.build_sarif(scan_)["runs"][0]["results"]}
    assert levels == {"note"}


def test_private_keys_are_listed_in_report_and_cbom(tmp_path):
    for name in ("server.key", "encrypted.key", "public.pem"):
        (tmp_path / name).write_bytes((CERTS / "keys" / name).read_bytes())
    r = subprocess.run([sys.executable, RATCHET, str(tmp_path)], capture_output=True, text=True)
    assert "private keys  2 files hold a private key; anyone who can read this repository has them:" in r.stdout
    assert "  encrypted.key (ENCRYPTED PRIVATE KEY at line 1, encrypted: algorithm not visible)" in r.stdout
    assert "  public.pem" not in r.stdout.split("private keys")[1].split("=====")[0]
    props = json.loads(subprocess.run([sys.executable, RATCHET, str(tmp_path), "--json"],
                                      capture_output=True, text=True).stdout)["metadata"]["properties"]
    found = sorted(p["value"] for p in props if p["name"] == "ratchet:private_key_file")
    assert found == ["encrypted.key (ENCRYPTED PRIVATE KEY at line 1, encrypted: algorithm not visible)",
                     "server.key"]
    assert {"name": "ratchet:private_key_file_count", "value": "2"} in props


def test_key_files_in_test_directories_are_test_code(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "ca.pem").write_bytes((CERTS / "x509" / "chain.pem").read_bytes())
    assert all(f.in_test for f in ratchet.walk(str(tmp_path)).findings)
