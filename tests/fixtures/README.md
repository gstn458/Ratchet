# Fixtures

Each `<group>/<case>/` directory is one scan root: a few lines of source, plus
`expected.cbom.json` and `expected.report.txt`, which are what Ratchet produces
when run from inside that directory. An optional `options.json` holds scan
options for that fixture, such as `{"include_vendored": true}`. `tests/test_golden.py` compares them
byte for byte, after replacing the timestamp and serial number with fixed values.
`tests/test_schema.py` validates every expected CBOM against CycloneDX 1.6.

The goldens record what Ratchet does **today**, including behaviour that is
wrong. A fixture marked "wrong" is a test that will fail on purpose when the fix
lands, and the fixing commit updates the golden so the diff shows the
correction. Regenerate with `pytest tests/test_golden.py --update-golden` and
review the diff before committing it.

Every bug fixed from here on gets a fixture that would have caught it.

## Status key

Step numbers follow the agreed Phase 0 order, including the additions approved
after the fixtures were first written:

1. Tests and schema validation
2. Remove `PY_CALLS`
3. Registry to JSON
4. ECDH versus ECDSA, including the mappings in note 2
5. Go import regex, including 3DES and comment handling
6. Key size from positional arguments
7. RSA grouping in the report, with imports counted apart from call sites
8. `--include-vendored`, and report skipped directories
9. Report files that fail to parse
10. Remove the 50-occurrence cap in the CBOM
11. `.ratchetignore`, with required reasons and suppressions as separate components

- **ok**: the output is correct and should not change.
- **wrong → step N**: a known defect, scheduled for that Phase 0 step.
- **wrong, unscheduled**: a known defect not on the Phase 0 list.
- **gap**: a false negative, recorded so that closing it shows up as a diff.

## python/

| Case | Pins down | Status |
| --- | --- | --- |
| `hashlib` | `hashlib.md5`, `hashlib.sha1`, `hashlib.new("md5")`, case-insensitive `hashlib.new("SHA1")`, `hashlib.new("sha256")` | ok |
| | `hashlib.sha256()` called by name is not recorded, but `hashlib.new("sha256")` is | gap |
| `rsa_cryptography` | `key_size=` keyword captured as RSA-2048 and RSA-4096; key size from a variable falls back to plain RSA | ok |
| | The report shows one RSA entry with `key sizes: 2048: 1, 4096: 1, not stated: 1` and the import counted apart; the CBOM keeps RSA, RSA-2048 and RSA-4096 as separate components | ok (step 7) |
| `rsa_positional_args` | `rsa.generate_private_key(65537, 2048)` is RSA-2048: the key size is read from its documented position, not the first argument | ok (was RSA-65537 before step 6) |
| `keysize_signatures` | Positional and keyword parameters for every key-generation call with a known signature: RSA, DSA and DH in `cryptography` (DH was recorded as DH-2, the generator), `curve=` and curve classes for `ec`, and PyCryptodome `RSA`/`DSA`; a variable key size or `self.curve` claims nothing | ok |
| `rsa_other_libraries` | PyCryptodome `RSA.generate(3072)` captured as RSA-3072 | ok |
| | python-rsa `rsa.newkeys(2048)` is not recognised as a call, only the import is | gap |
| `ec_sign` | A key used with `.sign()` and `.public_key().verify()` is ECDSA-SECP256R1; each `ec.ECDSA(...)` is an ECDSA call site; the unbound key and the import take the file's single usage | ok |
| `ec_exchange` | `.exchange(ec.ECDH(), ...)` makes the key, its peer and the import ECDH | ok (was ECDSA before step 4) |
| `ec_undetermined` | A key that is generated and serialised but never used is EC, usage undetermined, under its own report heading | ok |
| `ec_mixed_usage` | One signing key and one key-agreement key in the same file are each labelled by their own usage; the peer passed to `exchange()` is ECDH; an unused key and the import stay undetermined because the file's usages disagree | ok |
| `ec_across_methods` | paramiko's shapes: a key bound to `self.P` in one method and exchanged in another is ECDH; a key returned from a classmethod in a file whose only usage is signing is ECDSA | ok |
| `ec_from_import` | `import ... ec as curves` and a from-imported `ECDH()` are both recognised | ok |
| `ec_other_libraries` | `import ecdsa` and PyCryptodome `ECC` with no visible usage are EC, usage undetermined; `ECC.generate(curve="P-256")` loses the curve; `ecdsa.SigningKey.generate(...)` is not seen as a call | ok, gaps on curve and the dotted call |
| `ec_pycryptodome` | `DSS.new(key, ...)` makes a PyCryptodome `ECC` key ECDSA; `key_agreement(static_priv=..., static_pub=...)` makes both keys ECDH; an exported, unused key is undetermined | ok |
| `ec_ecdsa_package` | `sk.sign()` and `sk.get_verifying_key().verify()` make an `ecdsa` key ECDSA; `ECDH(private_key=...)` makes it ECDH | ok |
| | `from ecdsa import ECDH, NIST256p, SigningKey` is one import occurrence, not one per imported name | ok (was three before step 7) |
| `dh` | `dh.generate_parameters(key_size=2048)` captured as DH-2048 | ok |
| `dsa` | `dsa.generate_private_key(key_size=1024)` captured as DSA-1024 | ok |
| `ed25519` | `Ed25519PrivateKey.generate()` resolved through an imported class name | ok |
| `x25519` | `X25519PrivateKey.generate()` resolved the same way | ok |
| `nacl` | PyNaCl `SigningKey` → Ed25519, `PrivateKey` → X25519 | ok |
| `legacy_ciphers` | PyCryptodome DES, DES3, ARC4, AES, MD5, SHA1 recorded from their imports, including a renamed module and a from-imported `new`; `RSA.import_key` adds nothing | ok |
| | Each `.new(...)` on those modules is a call site of the module's algorithm, through a renamed module or a from-imported `new` | ok (added nothing before) |
| `cryptography_objects` | `cryptography` hash, cipher and RSA padding objects: `hashes.MD5()`, a from-imported `SHA1()`, `algorithms.TripleDES`/`ARC4` from `primitives` and `decrepit`, `padding.PKCS1v15()`/`PSS()`/`OAEP()`; `hashes.SHA256()` and symmetric `padding.PKCS7` are not flagged | ok (only imports of other modules were seen before) |
| `keygen_from_import` | `generate_private_key` from-imported, plain or renamed (`as rsa_generate_private_key`), from `rsa`, `dsa` and `ec`, is a key-generation call site with its key size or curve | ok (only the imports were recorded before) |
| `import_only` | Importing `rsa` and `ec` with no calls yields two imports and no call sites; the `ec` import is EC, usage undetermined | ok (counted as call sites before step 7) |
| `name_collision` | A project's own function named `md5()` is reported as MD5 | wrong, unscheduled (precision, Phase 1) |
| `syntax_error` | A Python 2 file is listed as `not valid Python 3 syntax at line 3` in the report and the CBOM, and the closing line says the result covers only parsed files; the `RSA.generate(1024)` in it is still not detected | ok, gap on the file's contents (skipped silently before step 9) |
| `null_bytes` | A file containing null bytes is listed as such, with a reason that is the same on every Python version; the other file in the tree is still scanned | ok |

## go/

| Case | Pins down | Status |
| --- | --- | --- |
| `rsa` | `rsa.GenerateKey(rand.Reader, 2048)` captured as RSA-2048 | ok |
| | With a variable key size the call is an RSA call site with no stated key size | ok (only the import was recorded before) |
| `ecdsa` | `crypto/ecdsa` import and `ecdsa.GenerateKey` call; `elliptic.P256()` passed to it is curve selection, not direct `crypto/elliptic` use | ok |
| `ecdsa_keys_for_ecdh` | x/crypto/ssh's idiom: keys from `ecdsa.GenerateKey` used for ECDH through `curve.ScalarMult`, with no signing in the file, are EC, usage undetermined; `x.Sign()` on a big.Int is not signing | ok (was ECDSA) |
| `ecdsa_keys_ecdh_elsewhere` | A key from `ecdsa.GenerateKey` in one file, used for ECDH-ES in another production file of the same package, is EC, usage undetermined; a signing file in the package, a test file in the package and a separate package (`signer/`) stay ECDSA | ok (all ECDSA before) |
| `ecdsa_signs_and_multiplies` | A file that signs with `ecdsa.SignASN1` stays ECDSA even though it also does a raw `ScalarMult` | ok |
| `ecdh` | `crypto/ecdh` maps to ECDH; `ecdh.P256()` is an ECDH call site and `ecdh.X25519()` an X25519 one; with both curves in the file the import stays ECDH | ok |
| `ecdh_x25519_only` | When every curve a file takes from `crypto/ecdh` is X25519, the import is X25519 too | ok |
| `elliptic_direct` | Direct `crypto/elliptic` use (`curve.ScalarBaseMult`, `elliptic.Marshal`) is EC, usage undetermined; `curve25519.ScalarBaseMult` in the same file is not | ok (was no finding before step 4) |
| | `curve25519.ScalarBaseMult` is an X25519 call site | ok |
| `ed25519` | `crypto/ed25519` import and `GenerateKey` call | ok |
| `x25519` | `golang.org/x/crypto/curve25519` maps to X25519 | ok |
| `dsa` | `dsa.GenerateParameters(..., dsa.L2048N256)` is DSA-L2048N256 | ok (parameter set was not captured before) |
| `hashes` | `crypto/md5`, `crypto/sha1` imports and calls; `crypto/sha256` from its import only | ok |
| `des_3des` | `des.NewCipher` is DES and `des.NewTripleDESCipher` is 3DES; with both in the file the `crypto/des` import stays DES | ok (3DES was reported as DES before step 5) |
| `tripledes_only` | When every `crypto/des` call in a file is 3DES, the import is 3DES too | ok |
| `rc4_aes` | `crypto/rc4` and `crypto/aes` | ok |
| `sign_verify_encrypt` | RSA, ECDSA and Ed25519 signing and verification, RSA encryption and decryption, DSA parameter generation, X25519, AES and SHA-256 calls are call sites, each only when the file imports the package | ok (only imports were recorded before) |
| `string_literal` | `"crypto/rsa"` and `"crypto/md5"` in ordinary strings are not imports | ok (were reported before step 5) |
| `import_forms` | Single-line, aliased, grouped, blank and raw-string imports are found; a commented-out import, an import path in a block comment, a raw string, a struct tag and an escaped string are not | ok |
| `aliased_import` | `gorsa "crypto/rsa"` import and `gorsa.GenerateKey(..., 2048)` as RSA-2048 | ok (the call was missed before) |
| `import_names` | Calls are matched through the name each import binds: `gorsa.SignPKCS1v15` (aliased crypto/rsa), `ell.Marshal` (aliased crypto/elliptic, EC) and `ec.GenerateKey`/`ec.SignASN1` (aliased crypto/ecdsa, which signs, so ECDSA); a project package bound to the name `rsa` beside an aliased crypto/rsa is not crypto/rsa; a blank import is an import finding with no calls; a dot import's bare `Sum(...)` is MD5 | ok (before: the project package was RSA-1024 and every aliased or dot-imported call was missed) |
| `variant_imports` | crypto/des and crypto/ecdh calls only through the name their import binds: a project package called `des` or `ecdh` is not crypto; the aliased `goecdh.P256()` is ECDH and `stddes.NewTripleDESCipher` is 3DES, which makes the aliased import 3DES too | ok (before: the project packages were DES and X25519, and the aliased calls were missed) |
| `comments` | Calls inside `//` comments, `/* */` blocks and after a trailing `//` are not matched | ok (block and trailing comments matched before step 5) |

## java/

Java is parsed only with tree-sitter, so these fixtures set `{"backend": "tree-sitter"}`
and are skipped when the grammars are not installed; CI installs them.

| Case | Pins down | Status |
| --- | --- | --- |
| `imports` | Imports of JDK key interfaces and specs and BouncyCastle classes map to their algorithm by the longest matching prefix (`RSAPublicKey` RSA, `ECPrivateKey` and `ECGenParameterSpec` EC, `DESedeKeySpec` 3DES, `ECDSASigner` ECDSA, `SHA1Digest` SHA-1, `EdECPublicKey` EdDSA, `XECPrivateKeySpec` XDH, `Ed448Signer` Ed448); a static import of an RSA class counts; package wildcards, `java.util`, a commented-out import and an import written in a string do not; `KeysTest.java` under `src/test` is test code | ok |
| `jca_calls` | JCA `getInstance` calls with a literal or same-file constant name, compound signature and Cipher transformation names, Mac and PBKDF2 names, case-insensitive matching, a provider argument, a fully qualified class, one finding per primitive (`SHA1withRSA` is RSA and SHA-1); `SHA512withRSA` is RSA only (SHA-512 is not in the registry); `EdDSA` is EdDSA with the curve not visible; a dynamic name, a reassigned field and a non-JCA class's `getInstance` claim nothing; `Jca.java` both signs with ECDSA and agrees keys with ECDH, so its EC generator stays EC, while `Signer.java` only signs, so its EC generator and ECPublicKey import are ECDSA | ok (only the import was found before) |
| `algorithm_names` | Unambiguous JCA names held in string literals outside `getInstance` (an enum of JWT algorithms, a curve constant, `X25519`) are algorithm-name occurrences, counted apart from call sites; `"RSA"`, `"MD5"` and a sentence that mentions a name are not; the literal passed straight to `getInstance` is the call site only; the curve name is EC with `SECP256R1` as its parameter set, and stays EC because name occurrences are not usage evidence | ok (only the direct call was found before) |
| `key_sizes` | Key sizes from `initialize(2048)`, `initialize(4096, random)`, `RSAKeyGenParameterSpec(3072, ...)`, an int constant, `ECGenParameterSpec` with a curve constant and AES `KeyGenerator.init(256)`, through the variable the `getInstance` result is assigned to; an EC size (the provider picks the curve), a parameter, and a variable declared twice in the file claim nothing | gap: no size is read |

## walk/

| Case | Pins down | Status |
| --- | --- | --- |
| `skipped_dirs` | `vendor`, `testdata`, `node_modules`, `venv`, `site-packages`, `build` and `dist` are skipped by default and dot-directories always; the report lists each kind and the CBOM records every skipped directory, the count and `ratchet:include_vendored` | ok (skipped silently before step 8) |
| `include_vendored` | The same tree with `--include-vendored` (via `options.json`): vendored, test-data and build-output code is scanned, and dot-directories are still skipped and listed | ok |
| `ignore_paths` | `.ratchetignore` path rules with required reasons: a directory rule, a no-slash rule matching at any depth, and a rule that matches nothing; each rule and each ignored file is listed in the report and the CBOM | ok |
| `suppressions` | MD5 suppressed under `src/cache/**` while MD5 in `src/auth/legacy.py` stays unsuppressed in its own component; a `false-positive` rule; an RSA rule covering two parameter sets; a rule matching nothing; vulnerability entries point only at the suppressed components, and the closing line says what was suppressed | ok |
| `test_code` | Test code by convention (`tests/`, `test_*.py`, `conftest.py`, `_test.go`) is counted apart and marked in each occurrence's context; `latest.py`, `contest.py` and Go's `testutil.go` are not test code | ok |
| `occurrence_cap` | 51 MD5 call sites in one file: the CBOM lists all 51 locations, matching `occurrence_count` | ok (50 listed before step 10) |
| `mixed` | Python and Go in one tree, relative paths, the report sections, RSA grouped across both languages, and a summary counting call sites and imports apart | ok |

## Notes

1. **Imports and call sites.** v0 counted every recognised import as a call site.
   Since step 7 each occurrence is marked as an import or a call site, in the
   report and in the CBOM's `additionalContext`, and a statement importing several
   names from one library is one import. The report groups each algorithm's
   parameter sets into one entry with the distribution of key sizes; the CBOM keeps
   one component per parameter set. Imports still count toward
   `--fail-on-vulnerable` until Phase 2's confidence levels.
2. **Elliptic-curve usage.** `cryptography`'s `ec`, PyCryptodome's `ECC`, the
   `ecdsa` package and Go's `crypto/elliptic` produce keys that can sign or agree
   keys. Since step 4 they are ECDSA or ECDH when the usage is visible and EC,
   usage undetermined, otherwise; Go's `ecdh.X25519()` is X25519.
3. **Unparseable files.** Since step 9 they are listed with a reason in every
   report and CBOM. Their contents are still not scanned; Phase 2 adds a
   low-confidence fallback that pattern-matches imports and known calls in
   them, while the file stays listed as unparsed.
