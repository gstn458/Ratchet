# Registry changelog

Every change to `registry.json`, with the claim it makes and the primary source for
it, as `CONTRIBUTING.md` requires. Each CBOM records the `registry_version` and
content hash it was produced with, so this file says what any given CBOM was built on.

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
