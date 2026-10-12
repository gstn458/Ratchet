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
`ec.generate_private_key(...)` resolves to ECDSA rather than being missed. It reads
key sizes out of keyword arguments, so `rsa.generate_private_key(key_size=2048)`
records the parameter set rather than just the algorithm family.

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
