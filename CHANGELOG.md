# Changelog

Changes to the scanner, its output and the GitHub Action. Changes to the algorithm
registry's claims are recorded with their sources in `REGISTRY_CHANGELOG.md`; each
release below names the registry version it ships.

The release workflow publishes the section for a version as that release's notes, so
every version in `ratchet.py` needs a section here before it is tagged.

## Unreleased

Registry 2026.10.4.

### Scanning

- Certificates and key files: X.509 certificates and requests, PKCS#8, PKCS#1 and SEC 1
  keys in PEM or DER, and OpenSSH keys, read with a built-in DER decoder. Each records
  its algorithm from the key's OID as the registry lists it, with its size or curve.
  EC keys in certificates are ECDSA or ECDH when the key usage says which.
- A certificate also records the algorithm and hash its issuer signed it with, so an
  MD5-signed certificate reports MD5 as already broken.
- Every file holding a private key is named at the top of the report and in the CBOM;
  nothing is read past the key's algorithm and size.
- Certificates and keys are inventory: they never fail `--fail-on-vulnerable` and are
  notes in SARIF.
- ML-DSA and ML-KEM report under their own post-quantum heading.

## 0.1.0

First release. Registry 2026.10.3.

### Scanning

- Python through the standard library `ast` module, with import aliases, key sizes and
  curves from documented argument positions, `cryptography` objects that name one
  algorithm, and PyCryptodome `.new()`.
- Go through a dependency-free lexer, or tree-sitter when installed, with identical
  findings. Calls are matched through the name each import binds, so a project package
  that happens to be called `rsa` is not reported as crypto.
- Java, JavaScript and TypeScript with tree-sitter: JCA `getInstance`, BouncyCastle,
  Node `crypto`, WebCrypto and node-forge. Without tree-sitter these files are counted
  and listed as not scanned, never dropped.
- Algorithm names: JCA names and JOSE `alg`/`enc` values in string literals, in every
  language, counted apart from call sites.
- Elliptic-curve keys are ECDSA or ECDH when their use is visible and EC, usage
  undetermined, otherwise.
- `.ratchetignore` excludes paths and suppresses findings, each with a required reason.
  Suppressed findings stay in the output, marked.
- 100,000 files in about 36 seconds on four CPUs, the same output for any `--jobs`.

### Output

- A CycloneDX 1.6 CBOM, validated against the vendored schema, recording the registry
  version and hash and the parser for each language.
- SARIF 2.1.0 (`--sarif`) for code scanning: quantum-vulnerable call sites as errors,
  classically broken call sites as warnings, imports and names as notes.
- `ratchet diff OLD NEW` compares two CBOMs file by file;
  `--fail-on-new-vulnerable` fails when a file gains quantum-vulnerable call sites.
- `--fail-on-vulnerable` fails on any unsuppressed quantum-vulnerable call site.
  Imports and names never fail a build.
- Output is byte-identical between runs apart from the CBOM's timestamp and serial
  number.

### Packaging and CI

- `pip install .` installs a `ratchet` command with no dependencies; the
  `tree-sitter` extra adds the grammars. The package is `ratchet-cbom`.
- A GitHub Action (`uses: gstn458/Ratchet@v0.1.0`) that fails a pull request only when
  it adds quantum-vulnerable call sites, writes the comparison to the job summary,
  annotates the call sites, and can upload the SARIF to code scanning.
