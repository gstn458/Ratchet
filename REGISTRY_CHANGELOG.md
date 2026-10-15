# Registry changelog

Every change to `registry.json`, with the claim it makes and the primary source for
it, as `CONTRIBUTING.md` requires. Each CBOM records the `registry_version` and
content hash it was produced with, so this file says what any given CBOM was built on.

## 2026.10.3 (registry schema 2)

**Four new entries: Ed448, X448, and EdDSA and XDH with the curve not visible.** Java's
JCA names these (`Ed448`, `X448`, and the generic `EdDSA` and `XDH`, which take
Ed25519 or Ed448 and X25519 or X448 keys). Until this version they recorded nothing.

All four are quantum broken: their security rests on an elliptic-curve discrete
logarithm, which Shor's algorithm solves. None is broken classically, and each has
security level 0, as every Shor-broken entry does.

| Entry | Primitive | OID | Migration target |
| --- | --- | --- | --- |
| Ed448 | signature | 1.3.101.113, id-Ed448 | ML-DSA-87 (FIPS 204) |
| X448 | key agreement | 1.3.101.111, id-X448 | hybrid X448+ML-KEM-1024, then ML-KEM-1024 alone |
| EdDSA | signature | none: Ed25519 1.3.101.112 or Ed448 1.3.101.113 | ML-DSA-65 (FIPS 204), or ML-DSA-87 if the curve is Ed448 |
| XDH | key agreement | none: X25519 1.3.101.110 or X448 1.3.101.111 | ML-KEM-768 (FIPS 203), or ML-KEM-1024 if the curve is X448 |

Sources:

- Ed448: RFC 8032, *Edwards-Curve Digital Signature Algorithm (EdDSA)*, section 5.2;
  approved for signatures in NIST FIPS 186-5 (2023), section 7.
- X448: RFC 7748, *Elliptic Curves for Security*, section 5.
- OIDs: RFC 8410, *Algorithm Identifiers for Ed25519, Ed448, X25519, and X448*,
  section 3.
- Migration targets: ML-DSA from FIPS 204 and ML-KEM from FIPS 203. Ed448 and X448
  are chosen for a security margin above Ed25519 and X25519 (RFC 7748 section 1
  puts Curve448 near 224-bit classical security), so they map to the highest NIST
  category, 5: ML-DSA-87 (FIPS 204, section 4, Table 1) and ML-KEM-1024 (FIPS 203,
  section 8). This is a judgement, matching the 2026.10.1 practice of tying targets
  to categories; the generic entries name both targets because the curve decides.

EdDSA and XDH are separate entries with `oid` null, like EC, usage undetermined, so a
CBOM never claims a curve the scanner did not see. Their primitive is known, so
they report under quantum vulnerable, not usage undetermined.

## 2026.10.2 (registry schema 2)

**New entry: EC, usage undetermined.** An elliptic-curve key whose use the scanner
cannot see. The `ec` module in `cryptography`, PyCryptodome's `ECC`, the `ecdsa`
package and Go's `crypto/elliptic` all produce keys that can either sign or agree
keys, and the migration target differs: ML-DSA for signatures, ML-KEM for key
establishment. Detection assigns ECDSA or ECDH when it sees the usage, and this entry
otherwise.

- Bucket: quantum broken. The primitive is broken by Shor's algorithm whatever it is
  used for, and under-reporting is the worse error.
- OID: 1.2.840.10045.2.1, id-ecPublicKey (RFC 5480, section 2.1.1). It identifies an
  elliptic-curve public key without restricting its use, which is exactly the
  ambiguity being recorded.
- Primitive and functions: CycloneDX `unknown` ("the primitive is not known").
- Security level: 0, as for every Shor-broken entry.
- Migration target: "determine usage before migrating, ML-DSA-65 if signing,
  ML-KEM-768 if key agreement". ML-DSA-65 from FIPS 204 and ML-KEM-768 from FIPS
  203, matching the ECDSA and ECDH entries.

It is a separate entry, not a null state on ECDSA, so it reports under its own
heading and is never counted as confirmed ECDSA.

## 2026.10.1 (registry schema 2)

**Security levels are per algorithm, not per bucket.** In 2026.10.0 the CycloneDX
`nistQuantumSecurityLevel` was derived from the quantum bucket alone: broken 0,
reduced 1, safe 3. Two of those three were wrong for some entries. Each entry now
carries its own level, and `parameter_sets` overrides it when the parameter set is
known. With the parameter set unknown, the level is the lowest category any of the
algorithm's standard parameter sets reaches, so it never overstates.

Source for the categories themselves: NIST, *Submission Requirements and Evaluation
Criteria for the Post-Quantum Cryptography Standardization Process* (2016), section
4.A.5. Category 1 is key search on AES-128, 2 is collision search on SHA-256, 3 is
key search on AES-192, 4 is collision search on SHA-384, 5 is key search on AES-256.
CycloneDX defines 0 as meeting none of them.

| Entry | Was | Now | Reason |
| --- | --- | --- | --- |
| MD5, SHA-1 | 1 | 0 | Practical collisions; neither reaches category 2's collision bar, nor category 1. |
| DES | 1 | 0 | 56-bit key, below AES-128 key search even classically. |
| 3DES | 1 | 0 | At most 112-bit key strength, below AES-128; disallowed for encryption (see below). |
| RC4 | 1 | 0 | Keystream biases make it classically broken (RFC 7465). |
| SHA-256 | 1 | 2 | Category 2 is defined as collision search on SHA-256. |
| AES | 1 | 1, or 1 / 3 / 5 for 128 / 192 / 256 | Unchanged when key size is unknown; the floor is AES-128. |
| ML-KEM | 3 | 1, or 1 / 3 / 5 for 512 / 768 / 1024 | FIPS 203, section 8. 3 overstated ML-KEM-512. |
| ML-DSA | 3 | 2, or 2 / 3 / 5 for 44 / 65 / 87 | FIPS 204, section 4, Table 1. 3 overstated ML-DSA-44. |
| RSA, ECDSA, ECDH, Ed25519, X25519, DH, DSA | 0 | 0 | Unchanged. Shor-broken meets no category. |

The test suite now enforces that anything quantum-broken or classically broken has
level 0 at every parameter set, that post-quantum entries reach at least 1, and that
the default level equals the lowest parameter-set level.

**OIDs that were parent arcs are no longer claimed.** A parent arc in the `oid` field
reads as the algorithm's identifier and is not one. Where no single OID identifies
the algorithm without information Ratchet does not detect, `oid` is now `null`, the
CBOM omits it, and `oid_note` in the registry records why.

| Entry | Was | Now | Source |
| --- | --- | --- | --- |
| ECDSA | 1.2.840.10045.4 (arc) | none | Signature OIDs pair ECDSA with a hash, for example ecdsa-with-SHA256 1.2.840.10045.4.3.2 (RFC 5758, section 3.2). The hash is not detected. |
| AES | 2.16.840.1.101.3.4.1 (arc) | none | AES OIDs pair key size with mode, for example aes128-GCM 2.16.840.1.101.3.4.1.6 (NIST CSOR, RFC 5084). Mode is not detected. |
| ML-KEM | 2.16.840.1.101.3.4.4 (arc) | per parameter set: .4.1, .4.2, .4.3 | id-alg-ml-kem-512/768/1024, NIST CSOR. |
| ML-DSA | 2.16.840.1.101.3.4.3 (NIST sigAlgs arc, shared with DSA, ECDSA, RSA and SLH-DSA variants) | per parameter set: .3.17, .3.18, .3.19 | id-ml-dsa-44/65/87, NIST CSOR, RFC 9881. |

**3DES rationale.** "Deprecated by NIST after 2023" becomes "Disallowed by NIST for
encryption after 2023". Source: NIST SP 800-131A Rev. 2 (2019), section 2: three-key
TDEA encryption was deprecated through 2023 and is disallowed after 2023; decryption
is allowed for legacy use.

Migration targets and buckets are unchanged in this version.

## 2026.10.0 (registry schema 1)

Initial registry, moved unchanged from the `ALGORITHMS` dict in Ratchet v0.
