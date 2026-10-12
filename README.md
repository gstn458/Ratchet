# Ratchet

Find quantum-breakable cryptography in a codebase and get a CycloneDX CBOM out of it.

Executive Order 14412 gives federal agencies until 31 December 2030 to migrate key
establishment and 31 December 2031 for digital signatures, and directs CISA and NIST
to publish minimum elements for a Cryptographic Bill of Materials. A proposed FAR rule
extends the underlying requirement to federal contractors. Most organizations cannot
currently answer the first question that follows from any of this, which is where their
cryptography actually lives.

Ratchet answers that question for source code.

## Install

There is nothing to install. Python 3.9 or newer, standard library only.

```
python3 ratchet.py /path/to/repo
python3 ratchet.py /path/to/repo --cbom cbom.json
python3 ratchet.py /path/to/repo --json > cbom.json
python3 ratchet.py /path/to/repo --fail-on-vulnerable   # exit 1 for CI
python3 ratchet.py /path/to/repo --include-vendored     # also scan vendor/, node_modules/, testdata/...
```

`ratchet.py` runs on its own. The algorithm registry, which holds every claim Ratchet
makes about an algorithm, is maintained in `registry.json` and embedded in the script.
If `registry.json` sits next to `ratchet.py` it is used instead of the embedded copy.
A `registry.json` that is present but unreadable is an error, not a silent fallback.

## Tests

The scanner needs nothing installed. The test suite needs pytest and jsonschema:

```
pip install -r requirements-dev.txt
pytest
```

Tests compare scans of small fixtures against committed golden output and validate
every CBOM against the CycloneDX 1.6 schema vendored in `tests/schema`.

## What it found on real repositories

Two libraries, scanned at the commits shown. Call sites are calls into a cryptographic
API; imports show a library is present without proving it is used, and are counted
separately.

paramiko, the Python SSH library, at `d87f9c0` (2026-10-10), 70 files scanned:

```
QUANTUM VULNERABLE
  X25519    4 call sites, 3 imports
  RSA       1 call site,  4 imports
  ECDH      3 call sites, 1 import
  ECDSA     3 call sites, 1 import
  Ed25519   2 imports
USAGE UNDETERMINED
  EC        3 imports
ALREADY BROKEN
  SHA-1     3 call sites
  MD5       1 call site

11 quantum-vulnerable call sites and 14 imports across 10 files.
```

The ECDH and ECDSA lines are worth a second look. Both come from the same
`cryptography` module, and Ratchet separates them by what the key is used for:
`kex_ecdh_nist.py` exchanges keys, so it migrates to ML-KEM, and `ecdsakey.py` signs,
so it migrates to ML-DSA. The three undetermined imports are files where that use is
not visible. The full CBOM is in [`paramiko-cbom.json`](paramiko-cbom.json).

golang-jwt/jwt at `73c870b` (2026-09-14), 46 files scanned: 8 quantum-vulnerable call
sites and 13 imports across 13 files. RSA has 5 call sites (PKCS #1 v1.5 and PSS
signing and verification, and one key generation whose 2048-bit size the scanner read
from the call), ECDSA 2 and Ed25519 1.

Neither of these is a criticism of either library. Both are doing exactly what every
library does today. That is the point.

## How it works

Python goes through the standard library `ast` module. It tracks import aliases, so
`from cryptography.hazmat.primitives.asymmetric import ec` followed by
`ec.generate_private_key(...)` is recognised rather than being missed. It reads
key sizes and curves from each call's documented argument position or keyword, so
`rsa.generate_private_key(65537, 2048)` records RSA-2048 rather than just the
algorithm family.

Elliptic-curve keys are classified by what they are used for, because the migration
target depends on it: `.sign()` or `.verify()` makes a key ECDSA, `.exchange()` makes
it ECDH. A key whose use is not visible is reported as EC, usage undetermined, under
its own heading. It still counts as quantum vulnerable, and it is never reported as
confirmed ECDSA.

Go is pattern matched on import declarations and call sites, after a small lexer has
removed comments and string contents. There is no Go AST here yet.

Every finding is classified three ways. Quantum broken means Shor's algorithm defeats
it outright and it has to be migrated. Already broken means it is weak today and
quantum has nothing to do with it, which is usually the more urgent finding. Reduced
means Grover halves the effective security margin, which at AES-256 and SHA-256 is
acceptable and is recorded rather than flagged.

## Output

CycloneDX 1.6, `cryptographic-asset` components with `cryptoProperties`, OIDs, and
`nistQuantumSecurityLevel` set to 0 for anything Shor breaks. Occurrences carry file
and line references. Ratchet-specific rationale and recommended replacement are
attached as properties so the file stays valid against the spec.

Every CBOM records which registry produced it, as `ratchet:scan_registry_version` and
`ratchet:scan_registry_sha256` in the metadata properties. When a migration target
changes in a later registry version, a CBOM made before that change still says which
claims it was built on, and a CBOM made with a locally edited registry is identifiable
by its hash. Output is deterministic: two scans of the same tree differ only in
timestamp and serial number.

## Limitations, stated plainly

Because they will come up in the first conversation with anyone technical.

Dynamically constructed cryptography is missed. If the algorithm name arrives as a
variable or from configuration, static analysis will not see it. This is the false
negative case and it is the reason the roadmap has a language model triage step.

Hand-rolled cryptography is missed. paramiko implements Diffie-Hellman with raw
modular exponentiation rather than calling a library, and Ratchet does not flag it.
Anything not routed through a recognized library or import is invisible.

Only Python and Go. Java, C, C#, JavaScript, Rust and Terraform are not covered.

Source code only. Certificates, TLS configuration, hardware security modules, and
anything on the network are out of scope. A complete cryptographic inventory needs
all of those, which is why the incumbent tools use network probes.

RSA and RSA-2048 are reported as separate components when key size is known for some
call sites and not others. Correct per the spec, since they are different parameter
sets, and noisy in the report.

Imports are reported, and kept in the CBOM marked as imports, because a library that
is present matters for the inventory even when no call is visible. They are counted
separately from call sites; v0 counted them together, which overstated its figures.

Go call sites are recognised for the package-level functions of the standard crypto
packages: key generation, signing, verification, encryption and the hash and cipher
constructors. Methods called on a key value, such as `key.Sign(...)` through the
`crypto.Signer` interface, are not attributed, so a Go file that signs only that way
shows up through its import alone.

Files that fail to parse are skipped silently. A Python 2 file, or anything else
`ast.parse` rejects, contributes nothing, and neither the report nor the CBOM says
it was skipped.

The CBOM lists at most 50 occurrence locations per component. The rest are dropped,
though `ratchet:occurrence_count` still gives the full number.

Parameter sets are read only from literal values in calls whose signature Ratchet
knows: `cryptography`'s RSA, DSA, DH and EC key generation and PyCryptodome's RSA and
DSA. A key size or curve held in a variable is not resolved. See
`tests/fixtures/README.md` for the full list of known gaps.

Go is read by a small lexer and regular expressions, not a parser. It separates code
from comments and strings and recognises import declarations, but a call through an
aliased import (`gorsa.GenerateKey`) is not matched, and a key size held in a variable
is not captured. In a Go file that does a raw `ScalarMult` and never signs,
`crypto/ecdsa` findings are reported as usage undetermined, because pre-1.20 code
generated ECDH keys with `ecdsa.GenerateKey`. A file that both signs and does
key agreement with such keys is reported as ECDSA.

Elliptic-curve usage is followed within one file and by name only. A key is tracked
through the variable or attribute it is assigned to and through `.public_key()`, but
not through function arguments, return values or other files. A key that cannot be
followed takes its file's usage only when every usage in that file agrees, and is
otherwise reported as usage undetermined. Two unrelated keys that share a name in one
file are treated as the same key.

Vendored and test-data directories (`vendor`, `node_modules`, `site-packages`, `venv`,
`.venv`, `testdata`) are skipped by default for speed, although vendored code is where
unmaintained cryptography tends to live. Every report says how many directories were
skipped and which, and every CBOM lists them; `--include-vendored` scans them. Build
output (`build`, `dist`), caches and dot-directories are always skipped, and listed.

No remediation yet. The scanner finds things. Opening a pull request that migrates
to ML-KEM or ML-DSA without silently breaking production is the actual hard problem
and the actual product.

## Roadmap

1. Java and JavaScript detection, since that is where most enterprise code is
2. Certificate and TLS configuration scanning
3. Language model triage to cut false positives on wrapped and dynamic calls
4. GitHub App that posts the CBOM diff as a check on every pull request
5. Remediation pull requests, hybrid mode first, behind a test suite gate

## License

Pick one before publishing. Apache 2.0 is the conventional choice for security
tooling that wants enterprise adoption.
