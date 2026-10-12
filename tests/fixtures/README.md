# Fixtures

Each `<group>/<case>/` directory is one scan root: a few lines of source, plus
`expected.cbom.json` and `expected.report.txt`, which are what Ratchet produces
when run from inside that directory. `tests/test_golden.py` compares them
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
11. `.ratchetignore`

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
| | The import line is counted as an RSA occurrence, so plain RSA appears even though every call has a size | wrong → step 7, see note 1 |
| `rsa_positional_args` | `rsa.generate_private_key(65537, 2048)` is recorded as **RSA-65537**: the public exponent is read as the key size | wrong → step 6 |
| `rsa_other_libraries` | PyCryptodome `RSA.generate(3072)` captured as RSA-3072 | ok |
| | python-rsa `rsa.newkeys(2048)` is not recognised as a call, only the import is | gap |
| `ec_sign` | `ec.generate_private_key(ec.SECP256R1())` captured as ECDSA-SECP256R1 | ok, until step 4 relabels by usage |
| | `curve=` keyword is not read, so the curve is lost | gap |
| `ec_exchange` | `.exchange(ec.ECDH(), ...)` is reported as **ECDSA** | wrong → step 4 |
| `ec_other_libraries` | `import ecdsa` and PyCryptodome `ECC` map to ECDSA; `ECC.generate(curve="P-256")` loses the curve; `ecdsa.SigningKey.generate(...)` is not seen as a call | step 4, see note 2 |
| `dh` | `dh.generate_parameters(key_size=2048)` captured as DH-2048 | ok |
| `dsa` | `dsa.generate_private_key(key_size=1024)` captured as DSA-1024 | ok |
| `ed25519` | `Ed25519PrivateKey.generate()` resolved through an imported class name | ok |
| `x25519` | `X25519PrivateKey.generate()` resolved the same way | ok |
| `nacl` | PyNaCl `SigningKey` → Ed25519, `PrivateKey` → X25519 | ok |
| `legacy_ciphers` | PyCryptodome DES, DES3, ARC4, AES, MD5, SHA1 recorded from their imports; `.new(...)` calls add nothing | ok |
| `import_only` | Importing `rsa` and `ec` with no calls still yields two quantum-broken "call sites" | wrong → step 7, see note 1 |
| `name_collision` | A project's own function named `md5()` is reported as MD5 | wrong, unscheduled (precision, Phase 1) |
| `syntax_error` | A Python 2 file that `ast.parse` rejects is skipped **without any notice**, along with the `RSA.generate(1024)` in it | wrong → step 9, see note 3 |

## go/

| Case | Pins down | Status |
| --- | --- | --- |
| `rsa` | `rsa.GenerateKey(rand.Reader, 2048)` captured as RSA-2048 | ok |
| | With a variable key size, the call pattern does not match at all, and only the import is recorded | gap |
| `ecdsa` | `crypto/ecdsa` import and `ecdsa.GenerateKey` call | ok |
| `ecdh` | `crypto/ecdh` maps to ECDH | ok |
| | `ecdh.X25519()` is reported as ECDH, not X25519 | step 4, see note 2 |
| `elliptic_direct` | `crypto/elliptic` used directly (`ScalarBaseMult`) produces no finding | gap → step 4 (EC, usage undetermined) |
| `ed25519` | `crypto/ed25519` import and `GenerateKey` call | ok |
| `x25519` | `golang.org/x/crypto/curve25519` maps to X25519 | ok |
| `dsa` | `crypto/dsa` import; the `L2048N256` parameter set is not captured | ok, gap on parameters |
| `hashes` | `crypto/md5`, `crypto/sha1` imports and calls; `crypto/sha256` from its import only | ok |
| `des_3des` | `des.NewTripleDESCipher` is reported as **DES**, not 3DES, so it gets the wrong OID and rationale | wrong → step 5 |
| `rc4_aes` | `crypto/rc4` and `crypto/aes` | ok |
| `string_literal` | `"crypto/rsa"` and `"crypto/md5"` in ordinary strings are reported as imports | wrong → step 5 |
| `aliased_import` | `gorsa "crypto/rsa"` import is seen, but `gorsa.GenerateKey(..., 2048)` is not, so the key size is lost | gap (tree-sitter, Phase 1) |
| `comments` | Lines starting with `//` are skipped; code inside `/* */` blocks and after a trailing `//` is still matched | wrong → step 5 |

## walk/

| Case | Pins down | Status |
| --- | --- | --- |
| `skipped_dirs` | `vendor`, `testdata`, `node_modules`, `build`, `dist`, `venv`, `site-packages` and dot-directories are skipped without a word in the report | wrong → step 8 |
| `occurrence_cap` | 51 MD5 call sites in one file: the CBOM lists 50 locations, silently drops the 51st, and still reports `occurrence_count` 51 | wrong → step 10 |
| `mixed` | Python and Go in one tree, relative paths, the three report sections and the summary line | ok, but see note 1 on the summary count |

## Notes

1. **Imports are counted as call sites.** Every recognised import becomes an
   occurrence, in both languages, and the summary line calls the total
   "quantum-vulnerable call sites". In `mixed`, 3 of the 7 reported call sites
   are import lines. The README's paramiko and golang-jwt figures are counted
   the same way. This also explains most RSA vs RSA-2048 splits: the import
   produces a size-less RSA occurrence even when every call has a key size.
   Step 7 keeps imports in the CBOM, since the inventory favours recall, but
   counts them apart from call sites in the report. Phase 2's confidence
   model, where import-only is medium and a call site is high, is the full fix.
2. **More mapping decisions like `ec`.** PyCryptodome's `ECC` keys and the
   `ecdsa` package both also do ECDH. Go's `ecdh.X25519()` is X25519 key
   agreement, which the registry has as its own entry. These are detection
   mappings, not registry entries, but they decide which registry entry a
   finding lands on. Scheduled for step 4; the exact treatment is confirmed
   with the owner before that step is built.
3. **Unparseable files vanish.** No count, no warning, no CBOM record. Old
   repositories with Python 2 files are exactly where legacy crypto is.
