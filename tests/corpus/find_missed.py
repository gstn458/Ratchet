#!/usr/bin/env python3
"""Search the corpus for cryptographic uses Ratchet does not report.

    python3 tests/corpus/find_missed.py

Recall cannot be measured by labelling what the scanner found, so this runs a
fixed list of precise searches, one per known blind spot, and records every
hit that Ratchet did not report for that algorithm at that line. Each entry
names the search that found it. The searches are not exhaustive: anything
outside them is unmeasured, and the summary says which searches ran.

Entries written here carry "source": "search" and are regenerated on every
run; entries added by reading code carry "source": "read" and are kept.
"""

import json
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import run  # noqa: E402

import ratchet  # noqa: E402

# (id, file suffixes, pattern, algorithm, why it is missed)
SEARCHES = [
    ("py-cryptography-hash", (".py",), r"\bhashes\.(MD5|SHA1)\s*\(", None,
     "hash object from cryptography.hazmat.primitives.hashes is not recognised"),
    ("py-cryptography-cipher", (".py",), r"\balgorithms\.(TripleDES|ARC4|Blowfish|CAST5|IDEA|SEED)\s*\(", None,
     "legacy cipher from cryptography.hazmat.primitives.ciphers is not recognised"),
    ("py-rsa-padding", (".py",), r"\bpadding\.(PKCS1v15|OAEP|PSS)\s*\(", "RSA",
     "RSA operation identified only by its padding object"),
    ("py-renamed-keygen", (".py",), None, None,
     "key generation through a renamed from-import (generate_private_key as ...)"),
    ("go-crypto-hash-constant", (".go",), r"\bcrypto\.(MD5|SHA1)\b", None,
     "crypto.MD5 or crypto.SHA1 passed to a signature or hash API"),
    ("go-x509-signature-algorithm", (".go",),
     r"\bx509\.(MD2WithRSA|MD5WithRSA|SHA1WithRSA|DSAWithSHA1|ECDSAWithSHA1)\b", None,
     "certificate signature algorithm constant"),
    ("go-tls-cipher-suite", (".go",), r"\btls\.TLS_RSA_WITH_\w+|\btls\.TLS_\w*(RC4|3DES)\w*", None,
     "TLS cipher suite constant (configuration scanning is a later Phase 1 step)"),
    ("go-ecdh-method", (".go",), r"\.ECDH\s*\(\s*[A-Za-z_]", "ECDH",
     "key agreement through the ecdh.PrivateKey.ECDH method"),
    ("java-jca", (".java",),
     r'getInstance\(\s*"(RSA|EC|DSA|DH|DiffieHellman|ECDH|ECDSA|MD5|SHA-?1|DES|DESede|TripleDES|RC4|ARCFOUR|'
     r'\w*with(RSA|ECDSA|DSA)\w*)[/"]', None, "Java is not scanned yet"),
    ("java-jca-name", (".java",),
     r'"(MD5|SHA1|SHA224|SHA256|SHA384|SHA512)with(RSA|ECDSA|DSA)(andMGF1)?"|"RSASSA-PSS"|"RSA/ECB/\w+"', None,
     "JCA signature or cipher name held as a string constant; Java is not scanned yet"),
    ("js-node-crypto", (".js", ".ts", ".mjs", ".cjs"),
     r"\b(createHash|createHmac)\(\s*['\"](md5|sha1)['\"]|\bcreate(Sign|Verify)\(\s*['\"](RSA-)?SHA|"
     r"\bgenerateKeyPair(Sync)?\(\s*['\"](rsa|rsa-pss|ec|dsa|dh|ed25519|x25519)['\"]|"
     r"\b(publicEncrypt|privateDecrypt|privateEncrypt|publicDecrypt)\(",
     None, "JavaScript is not scanned yet"),
    ("js-forge", (".js",),
     r"\bforge\.(pki\.rsa|rsa)\.\w+|\bforge\.md\.(md5|sha1)\b|\bforge\.(cipher\.create(De)?cipher)\(\s*['\"](3?DES|RC2)|"
     r"\bforge\.(des|rc2)\.\w+",
     None, "JavaScript is not scanned yet"),
]

NAME_ALGO = [
    (r"publicEncrypt|privateDecrypt|privateEncrypt|publicDecrypt", "RSA"),
    (r"ECDSA", "ECDSA"), (r"withRSA|RSASSA|RSA/", "RSA"), (r"withDSA", "DSA"),
    (r"md5|MD5", "MD5"), (r"sha-?1|SHA-?1|SHA1", "SHA-1"), (r"TripleDES|DESede|3DES", "3DES"),
    (r"\bDES\b|\bdes\b|'DES|\"DES", "DES"), (r"ARC4|RC4|ARCFOUR", "RC4"), (r"ECDSA", "ECDSA"),
    (r"ECDH", "ECDH"), (r"DiffieHellman|\bDH\b|['\"]dh['\"]", "DH"), (r"DSA|['\"]dsa['\"]", "DSA"),
    (r"rc2|RC2", "RC2 (not in the registry)"), (r"[Ee]d25519", "Ed25519"), (r"[Xx]25519", "X25519"), (r"RSA|rsa", "RSA"), (r"\bEC\b|['\"]ec['\"]", "EC"),
]


def algorithm_of(text, fixed):
    if fixed:
        return fixed
    for pattern, algo in NAME_ALGO:
        if re.search(pattern, text):
            return algo
    return "unknown"


RENAMED = re.compile(r"from\s+cryptography\.hazmat\.primitives\.asymmetric\.(rsa|dsa|ec)\s+import\s+[^\n]*"
                     r"\bgenerate_private_key\s+as\s+(\w+)")
RENAMED_ALGO = {"rsa": "RSA", "dsa": "DSA", "ec": "EC"}


def source_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if not ratchet.skip_reason(d, False))
        for fn in sorted(filenames):
            yield Path(dirpath) / fn


def search(repo):
    root = run.CACHE / repo["name"]
    result = json.loads((HERE / "results" / f"{repo['name']}.json").read_text())
    reported = {(f["path"], f["line"], f["algorithm"]) for f in result["findings"]}
    reported_lines = {(f["path"], f["line"]) for f in result["findings"]}
    hits = []
    for path in source_files(root):
        rel = path.relative_to(root).as_posix()
        searches = [s for s in SEARCHES if rel.endswith(s[1])]
        if not searches:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        for sid, _, pattern, fixed, why in searches:
            if sid == "py-renamed-keygen":
                for module, alias in RENAMED.findall(text):
                    for i, line in enumerate(lines, 1):
                        if re.search(rf"(?<![\w.]){alias}\s*\(", line) and "import" not in line:
                            hits.append((rel, i, RENAMED_ALGO[module], sid, why, line))
                continue
            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith(("//", "#", "*", "/*")):
                    continue
                m = re.search(pattern, line)
                if m:
                    hits.append((rel, i, algorithm_of(m.group(0), fixed), sid, why, line))
    missed = []
    for rel, i, algo, sid, why, line in hits:
        if (rel, i, algo) in reported:
            continue
        if sid == "py-rsa-padding" and (rel, i) in reported_lines:
            continue
        missed.append({"path": rel, "line": i, "algorithm": algo, "source": "search", "search": sid,
                       "note": why, "test": ratchet.is_test_path(rel), "snippet": line.strip()[:160]})
    return sorted(missed, key=lambda m: (m["path"], m["line"], m["algorithm"], m["search"]))


def main():
    manifest = json.loads((HERE / "manifest.json").read_text())
    for repo in manifest["repositories"]:
        labels = run.load_labels(repo["name"])
        kept = [m for m in labels.get("missed", []) if m.get("source") == "read"]
        labels["missed"] = kept + search(repo)
        labels["searched"] = [s[0] for s in SEARCHES]
        (HERE / "labels" / f"{repo['name']}.json").write_text(json.dumps(labels, indent=2) + "\n")
        print(f"{repo['name']}: {len(labels['missed'])} missed", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
