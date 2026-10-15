#!/usr/bin/env python3
"""Draft corpus labels from evidence in the source, and list what needs reading.

    python3 tests/corpus/assist.py              # write drafts for unlabelled call sites
    python3 tests/corpus/assist.py --review     # print the call sites that need a human

This does not decide anything the scanner decided. Each rule below checks the
scanned source independently (the call's text, the file's imports, names that
could shadow a package) and proposes "tp" only when that evidence is
unambiguous. Everything else is left unlabelled and listed for reading.
Existing labels are never changed. Every draft carries a note naming the rule
it came from, so a reviewer can audit a whole class at once.

Checkouts come from the same cache as run.py ($RATCHET_CORPUS_DIR).
"""

import argparse
import ast
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import run  # noqa: E402

GO_IMPORT = re.compile(r'^\s*(?:import\s+)?(?:(\w+|\.)\s+)?"([^"]+)"', re.M)


def go_imports(source):
    """{local package name: import path} for unaliased and aliased imports."""
    names = {}
    for alias, path in GO_IMPORT.findall(source):
        names[alias or path.rsplit("/", 1)[-1]] = path
    return names


def go_shadowed(source, name):
    """True if anything in the file could rebind the package name."""
    return bool(re.search(
        rf"\b{name}\s*:?=[^=]|\bvar\s+{name}\b|[(,]\s*{name}\s+[\w*\[]|\bfunc\s+{name}\b", source))


GO_RULES = {
    # algorithm -> (package, functions, extra check)
    "RSA": ("crypto/rsa", r"GenerateKey|GenerateMultiPrimeKey|SignPKCS1v15|VerifyPKCS1v15|SignPSS|VerifyPSS"
                          r"|EncryptOAEP|DecryptOAEP|EncryptPKCS1v15|DecryptPKCS1v15|DecryptPKCS1v15SessionKey"),
    "ECDSA": ("crypto/ecdsa", r"Sign|SignASN1|Verify|VerifyASN1|GenerateKey"),
    "Ed25519": ("crypto/ed25519", r"GenerateKey|NewKeyFromSeed|Sign|Verify|VerifyWithOptions"),
    "DSA": ("crypto/dsa", r"GenerateParameters|GenerateKey|Sign|Verify"),
    "MD5": ("crypto/md5", r"Sum|New"),
    "SHA-1": ("crypto/sha1", r"Sum|New"),
    "SHA-256": ("crypto/sha256", r"Sum256|New"),
    "AES": ("crypto/aes", r"NewCipher"),
    "RC4": ("crypto/rc4", r"NewCipher"),
    "DES": ("crypto/des", r"NewCipher"),
    "3DES": ("crypto/des", r"NewTripleDESCipher"),
    "ECDH": ("crypto/ecdh", r"P256|P384|P521"),
}
KEY_AGREEMENT_HINTS = re.compile(r"ScalarMult\s*\(|ECDH|ecdh", re.I)


def draft_go(finding, source, line):
    algo = finding["algorithm"]
    if algo == "X25519":
        for pkg, path, funcs in (("curve25519", "golang.org/x/crypto/curve25519", "X25519|ScalarMult|ScalarBaseMult"),
                                 ("ecdh", "crypto/ecdh", "X25519")):
            if go_imports(source).get(pkg) == path and re.search(rf"\b{pkg}\.({funcs})\s*\(", line) \
                    and not go_shadowed(source, pkg):
                return f"rule go-package-call: {pkg}.X25519-family call, {path} imported, name not shadowed"
        return None
    if algo not in GO_RULES:
        return None  # EC and anything new: read it
    path, funcs = GO_RULES[algo]
    pkg = path.rsplit("/", 1)[-1]
    imports = go_imports(source)
    if algo == "Ed25519" and imports.get(pkg) == "golang.org/x/crypto/ed25519":
        path = "golang.org/x/crypto/ed25519"
    if imports.get(pkg) != path or go_shadowed(source, pkg):
        return None
    m = re.search(rf"\b{pkg}\.({funcs})\s*\(", line)
    if not m:
        return None
    if finding["label"] != algo:  # a recorded parameter set must appear in the call
        param = finding["label"][len(algo) + 1:]
        if not re.search(rf"\b{re.escape(param)}\b", line):
            return None
    if algo == "ECDSA" and m.group(1) == "GenerateKey" and KEY_AGREEMENT_HINTS.search(source):
        return None  # the key may be used for key agreement: read it
    note = f"rule go-package-call: {pkg}.{m.group(1)}, {path} imported, name not shadowed"
    if algo == "ECDSA" and m.group(1) == "GenerateKey":
        note += "; no key-agreement use in the file"
    return note


PY_HASH = {"MD5": "md5", "SHA-1": "sha1"}
WRAPPERS = {
    "django.utils.crypto": "Django wrapper over hashlib",
    "ansible.module_utils.common.text.converters": None,
}


# algorithm -> (module the object is imported as, its parent packages, object names)
PY_OBJECTS = {
    "MD5": ("hashes", r"cryptography\.hazmat\.primitives", "MD5"),
    "SHA-1": ("hashes", r"cryptography\.hazmat\.primitives", "SHA1"),
    "3DES": ("algorithms", r"cryptography\.hazmat\.(?:primitives|decrepit)\.ciphers", "TripleDES"),
    "RC4": ("algorithms", r"cryptography\.hazmat\.(?:primitives|decrepit)\.ciphers", "ARC4"),
    "RSA": ("padding", r"cryptography\.hazmat\.primitives\.asymmetric", "PKCS1v15|OAEP|PSS"),
}


def py_bindings(source, name):
    """Every way the file binds a name: ("from", module) for each import of it,
    ("other", None) for an assignment, parameter, loop target or plain import."""
    found = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if (alias.asname or alias.name) == name:
                    found.append(("from", node.module if alias.asname is None else None))
        elif isinstance(node, ast.Import):
            found += [("other", None) for a in node.names if (a.asname or a.name.split(".")[0]) == name]
        elif isinstance(node, ast.Name) and node.id == name and isinstance(node.ctx, ast.Store):
            found.append(("other", None))
        elif isinstance(node, ast.arg) and node.arg == name:
            found.append(("other", None))
    return found


def draft_python_object(algo, source, line):
    """hashes.SHA1(), algorithms.ARC4(...), padding.PKCS1v15(): the module is
    imported once, unaliased, from cryptography, and bound nowhere else."""
    module, parent, objects = PY_OBJECTS[algo]
    m = re.search(rf"(?<![\w.]){module}\.({objects})\s*\(", line)
    if not m:
        return None
    bindings = py_bindings(source, module)
    if len(bindings) != 1 or bindings[0][0] != "from" or not re.fullmatch(parent, bindings[0][1] or ""):
        return None
    return (f"rule py-cryptography-object: {module}.{m.group(1)}(), {module} imported once from "
            f"{bindings[0][1]}, bound nowhere else")


def draft_python(finding, source, line):
    algo = finding["algorithm"]
    if algo in PY_OBJECTS:
        rule = draft_python_object(algo, source, line)
        if rule or algo not in PY_HASH:
            return rule  # anything else in Python: read it
    if algo not in PY_HASH:
        return None  # asymmetric findings in Python: read them
    name = PY_HASH[algo]
    if re.search(rf"\bhashlib\.{name}\s*\(", line):
        return f"rule py-hashlib: hashlib.{name}() call"
    if re.search(rf"\bhashlib\.new\(\s*['\"]{name}['\"]", line, re.I) or \
            re.search(rf"\bhashlib\.new\(\s*['\"]{'sha-1' if name == 'sha1' else name}['\"]", line, re.I):
        return f"rule py-hashlib: hashlib.new('{name}') call"
    if re.search(rf"(?<![\w.]){name}\s*\(", line):
        if re.search(rf"^\s*from\s+hashlib\s+import\s+[^\n]*\b{name}\b", source, re.M):
            return f"rule py-hashlib-import: {name} imported from hashlib"
        if re.search(rf"^\s*from\s+django\.utils\.crypto\s+import\s+[^\n]*\b{name}\b", source, re.M):
            return f"rule py-wrapper: {name} from django.utils.crypto, a thin wrapper over hashlib"
    return None


def drafts_for(repo):
    result = json.loads((HERE / "results" / f"{repo['name']}.json").read_text())
    labels = run.load_labels(repo["name"])
    root = run.CACHE / repo["name"]
    drafted, review = {}, []
    for f in result["findings"]:
        if f["kind"] != "call site":
            continue
        key = run.finding_key(f)
        if key in labels["findings"]:
            continue
        source = (root / f["path"]).read_text(encoding="utf-8", errors="replace")
        line = source.splitlines()[f["line"] - 1]
        rule = draft_go(f, source, line) if f["path"].endswith(".go") else draft_python(f, source, line)
        if rule:
            drafted[key] = {"verdict": "tp", "note": rule}
        else:
            review.append(f)
    return labels, drafted, review


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--review", action="store_true", help="print call sites that need reading")
    p.add_argument("--only", action="append")
    args = p.parse_args(argv)
    manifest = json.loads((HERE / "manifest.json").read_text())
    total_drafted = total_review = 0
    for repo in manifest["repositories"]:
        if args.only and repo["name"] not in args.only:
            continue
        labels, drafted, review = drafts_for(repo)
        total_drafted += len(drafted)
        total_review += len(review)
        if args.review:
            for f in review:
                print(f"{repo['name']}\t{run.finding_key(f)}\t{f['snippet']}")
        elif drafted:
            labels["findings"].update(drafted)
            labels["findings"] = dict(sorted(labels["findings"].items()))
            (HERE / "labels" / f"{repo['name']}.json").write_text(json.dumps(labels, indent=2) + "\n")
    print(f"drafted {total_drafted}, left for reading {total_review}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
