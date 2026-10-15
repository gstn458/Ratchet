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
`ratchet.py` runs as it is, or it can be installed as the `ratchet` command (the
package is `ratchet-cbom`; it is not on PyPI yet, so install from a checkout):

```
pip install .                  # the ratchet command, no dependencies
pip install '.[tree-sitter]'   # plus tree-sitter for Go, Java, JavaScript and TypeScript
```

```
python3 ratchet.py /path/to/repo
python3 ratchet.py /path/to/repo --cbom cbom.json
python3 ratchet.py /path/to/repo --json > cbom.json
python3 ratchet.py /path/to/repo --sarif ratchet.sarif     # SARIF 2.1.0 for code scanning
python3 ratchet.py diff old.cbom.json new.cbom.json --fail-on-new-vulnerable
python3 ratchet.py /path/to/repo --fail-on-vulnerable   # exit 1 on a quantum-vulnerable call site
python3 ratchet.py /path/to/repo --include-vendored     # also scan vendor/, node_modules/, build/...
python3 ratchet.py /path/to/repo --jobs 1                # one process (default: one worker per CPU)
```

tree-sitter is optional. With it, Go is parsed by tree-sitter instead of the built-in
regex backend, and Java is scanned at all; without it, Java files are listed as not
scanned:

```
pip install -r requirements-treesitter.txt
python3 ratchet.py /path/to/repo                         # tree-sitter if installed
python3 ratchet.py /path/to/repo --backend regex         # never load it
python3 ratchet.py /path/to/repo --backend tree-sitter   # fail if any grammar is missing
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
every CBOM against the CycloneDX 1.6 schema vendored in `tests/schema`. Goldens are
written with the regex Go backend; with `requirements-treesitter.txt` installed as
well, `tests/test_backends.py` scans every Go fixture again with tree-sitter and
requires identical output. CI runs the suite both ways.

`tests/corpus` measures Ratchet against 20 real repositories pinned to commits.
`python3 tests/corpus/run.py` fetches them (the only network access anywhere in the
project, and only in this test tool), scans them, writes results and prints the
measurement to `tests/corpus/SUMMARY.md`. It uses tree-sitter at the versions pinned in
`requirements-treesitter.txt`, which Java needs; `run.py --check --backend regex`
confirms the regex Go backend finds the same in Go. Precision is measured over hand-labelled call
sites; see `tests/corpus/LABELLING.md`. `tests/corpus/review.py` writes the review sheet,
`tests/corpus/REVIEW.md`: every false positive and a fixed-seed 10% sample of the rest.

## What it found on real repositories

Two libraries, scanned at the commits shown. Call sites are calls into a cryptographic
API; imports show a library is present without proving it is used, and are counted
separately.

paramiko, the Python SSH library, at `d87f9c0` (2026-10-10), 70 files scanned:

```
QUANTUM VULNERABLE
  RSA       3 call sites, 4 imports
  X25519    4 call sites, 3 imports
  ECDH      3 call sites, 1 import
  ECDSA     3 call sites, 1 import
  Ed25519   2 imports
USAGE UNDETERMINED
  EC        3 imports
ALREADY BROKEN
  SHA-1     3 call sites
  MD5       1 call site

13 quantum-vulnerable call sites and 14 imports across 10 files.
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

Objects from `cryptography` that name one algorithm are call sites too: `hashes.MD5()`
and `hashes.SHA1()`, `algorithms.TripleDES` and `ARC4` (including the `decrepit`
module), and the RSA padding schemes `PKCS1v15`, `OAEP` and `PSS`, which exist only for
RSA operations. So is PyCryptodome's `.new(...)` on a cipher or hash module, such as
`DES.new(key, DES.MODE_CBC)` or `MD5.new(data)`, which is how every one of them is
instantiated.

Elliptic-curve keys are classified by what they are used for, because the migration
target depends on it: `.sign()` or `.verify()` makes a key ECDSA, `.exchange()` makes
it ECDH. A key whose use is not visible is reported as EC, usage undetermined, under
its own heading. It still counts as quantum vulnerable, and it is never reported as
confirmed ECDSA.

Go is pattern matched on import declarations and call sites, after comments and
string contents have been removed. Two backends do that removal: tree-sitter, when it
is installed, and a small lexer that needs nothing. They feed the same rules, and on
the 26 Go fixtures and the eight Go repositories in the corpus they produce identical
findings. Every report and CBOM names the backend that ran, with tree-sitter's
version, and says why when it fell back to the lexer.

Every finding is classified three ways. Quantum broken means Shor's algorithm defeats
it outright and it has to be migrated. Already broken means it is weak today and
quantum has nothing to do with it, which is usually the more urgent finding. Reduced
means Grover halves the effective security margin, which at AES-256 and SHA-256 is
acceptable and is recorded rather than flagged.

## Speed

The target is a 100,000-file repository in under a minute on a laptop.
`tools/bench.py` builds a tree of 100,000 links to the corpus's Python and Go
sources and times a scan. On a 4-CPU machine with a warm file cache it takes
36 seconds with the built-in Go lexer and 51 seconds with tree-sitter, which parses
more slowly than the lexer reads; in a single process, 132 seconds.

Three things make that possible, none of which changes a finding. Files are scanned
by one worker process per CPU and the results are put back in order, so the output is
identical with any number of workers. Go rules run only on lines that mention the
package they look for. And a Python file that names no cryptographic module or hash is
parsed, so a syntax error is still reported, but its syntax tree is not walked. The
test suite checks each shortcut against the rules it skips.

## Excluding and suppressing

A `.ratchetignore` at the root of the scanned directory excludes paths and suppresses
findings. Every rule needs a reason after ` -- `; a rule without one stops the scan.

```
# Exclude paths from the scan (gitignore-style globs)
docs/examples/ -- sample code shown in the documentation, not shipped

# Findings that are not a problem here: recorded as not_affected
suppress MD5 src/cache/** -- cache keys and ETags, never compared against secrets

# Findings that are scanner mistakes: recorded as false_positive
false-positive MD5 legacy/local.py -- project function named md5, not hashlib
```

Nothing excluded or suppressed disappears. Every report lists each rule, its reason and
what it matched, and prints the number of suppressed findings on every run. In the
CBOM, suppressed occurrences move to a component of their own for each rule, and a
CycloneDX vulnerability entry, with an ID such as `ratchet-pqc-rsa` or
`ratchet-classical-md5` and the rule's analysis state and reason, points at that
component only. Occurrences of the same algorithm that the rule did not match stay in
the main component with no analysis, so a suppression never reads as covering code it
was not written for. Suppressed findings do not count toward `--fail-on-vulnerable`.

Negated rules (`!`) are not supported. Only a `.ratchetignore` at the scan root is read.

## Output

CycloneDX 1.6, `cryptographic-asset` components with `cryptoProperties`, OIDs, and
`nistQuantumSecurityLevel` set to 0 for anything Shor breaks. Occurrences carry file
and line references. Ratchet-specific rationale and recommended replacement are
attached as properties so the file stays valid against the spec.

Every CBOM records which registry produced it, as `ratchet:scan_registry_version` and
`ratchet:scan_registry_sha256` in the metadata properties. When a migration target
changes in a later registry version, a CBOM made before that change still says which
claims it was built on, and a CBOM made with a locally edited registry is identifiable
by its hash. The parser that read each language is recorded the same way, as
`ratchet:parser`, and printed at the top of every report. Output is deterministic: two scans of the same tree differ only in
timestamp and serial number.

### SARIF

`--sarif FILE` writes SARIF 2.1.0 for GitHub code scanning and other SARIF tools. It
is an alert list, not an inventory, so it holds less than the CBOM:

| Finding | Level |
| --- | --- |
| Quantum-vulnerable call site (RSA, ECDSA, ECDH, Ed25519, DH, DSA, ...) | `error` |
| Classically broken call site (MD5, SHA-1, DES, 3DES, RC4) | `warning` |
| Import or algorithm name of either | `note` |
| Reduced margin under Grover (AES, SHA-256, ...) | left out |

There is one rule per algorithm, with the same id as the CBOM's vulnerability
(`ratchet-pqc-rsa`, `ratchet-classical-md5`). Findings suppressed in `.ratchetignore`
stay in the file with an external suppression giving the rule and its reason, so code
scanning shows them as dismissed rather than dropping them. Each result has a
`ratchet/v1` partial fingerprint built from the rule, the file, the kind and the code
on the line, so an alert keeps its identity when lines above it move. Files that could
not be parsed, and languages that were not scanned, are listed as tool notifications.
Paths are relative to the scan root (`%SRCROOT%`); scan from the repository root so
they match the repository. Like the CBOM, the file has no timestamp, and two scans of
the same tree give identical SARIF.

### Comparing two scans

`ratchet diff OLD NEW` compares two CBOMs written by ratchet, typically one from the
base branch and one from a pull request:

```
git switch main      && ratchet . --cbom /tmp/old.cbom.json
git switch my-branch && ratchet . --cbom /tmp/new.cbom.json
ratchet diff /tmp/old.cbom.json /tmp/new.cbom.json --fail-on-new-vulnerable
```

It counts occurrences per algorithm, file and kind (call site, import, algorithm name)
and lists every count that went up or down, with the lines where the occurrences are
now. Line numbers are not compared, so code that only moves within a file is no
change. Suppressed findings are listed apart. `--fail-on-new-vulnerable` exits 1 when
any file has more unsuppressed quantum-vulnerable call sites than before; like
`--fail-on-vulnerable`, it ignores imports, algorithm names and suppressed findings,
and counts test code. `--json` prints the comparison as JSON.

The diff warns when the two scans were made differently: another ratchet or registry
version, another parser for a language, a different `--include-vendored`, or files
the new scan could not parse or did not scan. Each of those can change findings with
no change to the code. Scan both sides from the repository root so the paths match.
To scan a directory called `diff`, write it as `./diff`.

## Limitations, stated plainly

Because they will come up in the first conversation with anyone technical.

Dynamically constructed cryptography is missed. If the algorithm name arrives as a
variable or from configuration, static analysis will not see it. This is the false
negative case and it is the reason the roadmap has a language model triage step.

Hand-rolled cryptography is missed. paramiko implements Diffie-Hellman with raw
modular exponentiation rather than calling a library, and Ratchet does not flag it.
Anything not routed through a recognized library or import is invisible.

Python, Go, and Java with tree-sitter installed. Java has no fallback parser: without
`tree-sitter-java`, every Java file is counted and listed as not scanned, in the report
and the CBOM. Java detection covers imports of the JDK's key interfaces and specs and
of BouncyCastle classes, and JCA `getInstance` calls (KeyPairGenerator, Signature,
Cipher, KeyAgreement, MessageDigest, Mac, SecretKeyFactory and the rest) whose name is
a literal or a constant declared once in the same file. A compound name counts once per
primitive: `SHA1withRSA` is RSA and SHA-1. A name built at run time, held in another
file, or passed in from outside is not resolved, which in libraries such as JWT
implementations is most of them. SHA-384 and SHA-512 are not in the registry, so the
hash in `SHA512withRSA` records nothing. The generic `EdDSA` and `XDH` are reported as
such, with the curve (25519 or 448) not visible. Key sizes and curves are read from
`initialize(2048)`, `RSAKeyGenParameterSpec`, `DSAGenParameterSpec`, `ECGenParameterSpec`
and `KeyGenerator.init(256)` when the value is a literal or a same-file constant and
the generator is held in a variable bound once in the file. An EC generator
initialized with a size leaves the curve to the provider, so nothing is claimed, and
`NamedParameterSpec` does not yet narrow EdDSA or XDH to a curve.

JavaScript is likewise scanned only with `tree-sitter-javascript` (`.js`, `.mjs`, `.cjs`,
`.jsx`). Calls are matched through the module their receiver was bound to: Node's
`crypto` (by `require`, `import` or destructuring), WebCrypto's `crypto.subtle`, and
node-forge. Key sizes and curves are read from literal options (`modulusLength`,
`namedCurve`, `bits`) and cipher names (`aes-256-gcm`). Node's `crypto.sign` and
`createSign('sha256')` name only the hash, so the key algorithm is not claimed;
forge's `forge.des` does DES or 3DES by key length and is not claimed; and a `subtle`
object held in a variable is not followed.

JOSE algorithm names, the `alg` and `enc` values of JWT, JWS and JWE (`RS256`, `ES256`,
`PS256`, `EdDSA`, `RSA-OAEP`, `ECDH-ES`, `A256GCM` and the rest of RFC 7518, 8037 and
8812), are algorithm-name occurrences in every language when a string literal is exactly
one of them, case and all. Each records the primitives it fixes: `ES256` is ECDSA on
P-256 with SHA-256. `RSA-OAEP` records RSA only: JOSE fixes SHA-1 for it, but WebCrypto
and node-forge use the same string with a hash chosen elsewhere. A JWT library that accepts a name
from configuration or a token header at run time is not seen, which is also why a
verifier's `algorithms=` allow-list shows what it accepts, not what any token uses. TypeScript (`.ts`, `.mts`, `.cts`, `.tsx`) is scanned with the same
rules through `tree-sitter-typescript`, including `import x = require(...)` and receivers
wrapped in `as`, `!` or `satisfies`; types themselves are not followed, so a variable
typed as Node's `Hash` but assigned elsewhere is not traced. In the corpus only vault's
web UI is TypeScript. C, C#, Rust and Terraform are not covered.

Source code only. Certificates, TLS configuration, hardware security modules, and
anything on the network are out of scope. A complete cryptographic inventory needs
all of those, which is why the incumbent tools use network probes.

The CBOM keeps RSA, RSA-2048 and RSA-4096 as separate components, because the spec
treats them as different parameter sets. The terminal report groups them into one
entry per algorithm with the distribution of key sizes, so the two views count the
same occurrences differently by design.

Imports are reported, and kept in the CBOM marked as imports, because a library that
is present matters for the inventory even when no call is visible. They are counted
separately from call sites; v0 counted them together, which overstated its figures.
Java code adds a third kind, algorithm names: an unambiguous JCA name such as
`SHA256withRSA`, `RSASSA-PSS`, `DESede/CBC/PKCS5Padding` or `secp256r1` held in a string
literal outside a `getInstance` call, which is how JWT libraries keep their algorithm
tables. A name shows the algorithm is used somewhere in the program, not where, so it
is counted apart as well. Short names such as `"RSA"`, `"EC"` or `"MD5"` are too often
plain labels to count outside `getInstance`.
`--fail-on-vulnerable` counts only unsuppressed quantum-vulnerable call sites, so a
library that is imported but never called, or an algorithm only named, does not fail
a build. That is deliberate:
anything that gates CI favours precision, while the inventory favours recall.

`ratchet diff` counts per file, so renaming or moving a file that has a
quantum-vulnerable call site reads as a new call site in the new path, and fails
`--fail-on-new-vulnerable`. Counting per file is what lets it catch one file dropping
RSA while another starts using it; renames are the cost. The report then shows the
same count leaving the old path, which is how a reviewer tells a rename from new use.

Findings in test code are marked as such, by each language's convention: Go `_test.go`
files, Python `test_*.py`, `*_test.py` and `conftest.py`, and anything under a `test`,
`tests`, `testing` or `testdata` directory. The report counts them apart and the CBOM
says so in each occurrence's `additionalContext`. They still count toward
`--fail-on-vulnerable`; a helper package outside those conventions is not recognised
as test code.

Go call sites are recognised for the package-level functions of the standard crypto
packages: key generation, signing, verification, encryption and the hash and cipher
constructors. Methods called on a key value, such as `key.Sign(...)` through the
`crypto.Signer` interface, are not attributed, so a Go file that signs only that way
shows up through its import alone.

Files that cannot be parsed contribute no findings. A Python 2 file, or anything else
`ast.parse` rejects, is listed with the reason in every report and every CBOM, but the
cryptography in it is not detected. A low-confidence fallback for such files is planned
for Phase 2.

MD5 and SHA-1 are reported wherever they are used, including in HMAC, in PBKDF2, in
OCSP certificate identifiers and in the MGF1 mask of RSA-OAEP and PSS, where collision
resistance is not what the construction relies on. Those uses are not broken in the
way a signature over a SHA-1 digest is, and the registry's rationale for both
algorithms describes the signature case. Ratchet does not tell them apart; a reviewer
can record them with `suppress`.

Parameter sets are read only from literal values in calls whose signature Ratchet
knows: `cryptography`'s RSA, DSA, DH and EC key generation and PyCryptodome's RSA and
DSA. A key size or curve held in a variable is not resolved. See
`tests/fixtures/README.md` for the full list of known gaps.

Go rules are regular expressions over code with comments and strings removed, with
either backend. Calls are matched through the name each import binds, so
`gorsa.GenerateKey` counts when `crypto/rsa` is imported as `gorsa`, a dot import's bare
`Sum(...)` counts, and a project package that happens to be called `rsa` does not. A
key size held in a variable is not captured, and a package reached any other way than
through its import name, such as a function value passed around, is not followed. Because pre-1.20 Go code generated ECDH keys with
`ecdsa.GenerateKey`, often doing the key agreement in another file,
`crypto/ecdsa` findings in a file that never signs are reported as usage
undetermined when that file shows ECDH, or when another production file in the
same package does. Test files do not lend their evidence to the rest of the
package. A file that both signs and does key agreement is reported as ECDSA.

Elliptic-curve usage is followed within one file and by name only. A key is tracked
through the variable or attribute it is assigned to and through `.public_key()`, but
not through function arguments, return values or other files. A key that cannot be
followed takes its file's usage only when every usage in that file agrees, and is
otherwise reported as usage undetermined. Two unrelated keys that share a name in one
file are treated as the same key.

Vendored, test-data and build-output directories (`vendor`, `node_modules`,
`site-packages`, `venv`, `.venv`, `testdata`, `build`, `dist`) are skipped by default for
speed, although vendored code is where unmaintained cryptography tends to live and
build output can bundle it. Every report says how many directories were skipped and
which, and every CBOM lists them; `--include-vendored` scans them. Version control,
caches and other dot-directories are always skipped, and listed.

No remediation yet. The scanner finds things. Opening a pull request that migrates
to ML-KEM or ML-DSA without silently breaking production is the actual hard problem
and the actual product.

## Roadmap

1. Certificate, TLS configuration and dependency manifest scanning
2. Language model triage to cut false positives on wrapped and dynamic calls
3. GitHub App that posts the CBOM diff as a check on every pull request
4. Remediation pull requests, hybrid mode first, behind a test suite gate

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
