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

paramiko, the Python SSH library, 70 files scanned:

```
QUANTUM VULNERABLE
  X25519    9 occurrences
  ECDSA     7 occurrences
  RSA       5 occurrences
  Ed25519   2 occurrences
ALREADY BROKEN
  SHA-1     3 occurrences
  MD5       1 occurrence

23 quantum-vulnerable call sites across 10 files.
```

golang-jwt/jwt, 46 files scanned: 14 quantum-vulnerable call sites across 13 files,
including an RSA-2048 key generation the scanner picked the key size out of.

Neither of these is a criticism of either library. Both are doing exactly what every
library does today. That is the point.

## How it works

Python goes through the standard library `ast` module. It tracks import aliases, so
`from cryptography.hazmat.primitives.asymmetric import ec` followed by
`ec.generate_private_key(...)` is recognised rather than being missed. It reads
key sizes out of keyword arguments, so `rsa.generate_private_key(key_size=2048)`
records the parameter set rather than just the algorithm family.

Elliptic-curve keys are classified by what they are used for, because the migration
target depends on it: `.sign()` or `.verify()` makes a key ECDSA, `.exchange()` makes
it ECDH. A key whose use is not visible is reported as EC, usage undetermined, under
its own heading. It still counts as quantum vulnerable, and it is never reported as
confirmed ECDSA.

Go is pattern matched on import paths and call sites. There is no Go AST here yet.

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

Imports are counted as occurrences. Every recognised import line is recorded alongside
real call sites, and the summary line calls the total "call sites", so it overstates.
The paramiko and golang-jwt figures above are counted this way.

Files that fail to parse are skipped silently. A Python 2 file, or anything else
`ast.parse` rejects, contributes nothing, and neither the report nor the CBOM says
it was skipped.

The CBOM lists at most 50 occurrence locations per component. The rest are dropped,
though `ratchet:occurrence_count` still gives the full number.

Known misclassifications, each pinned by a fixture in `tests/fixtures` until fixed:
`rsa.generate_private_key(65537, 2048)` with positional arguments is recorded as
RSA-65537; Go's `des.NewTripleDESCipher` is recorded as DES rather than 3DES; Go
string literals containing a crypto package path are recorded as imports. See
`tests/fixtures/README.md` for the full list, including false negatives.

Elliptic-curve usage is followed within one file and by name only. A key is tracked
through the variable or attribute it is assigned to and through `.public_key()`, but
not through function arguments, return values or other files. A key that cannot be
followed takes its file's usage only when every usage in that file agrees, and is
otherwise reported as usage undetermined. Two unrelated keys that share a name in one
file are treated as the same key.

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
