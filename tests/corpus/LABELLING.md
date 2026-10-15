# Labelling corpus findings

`labels/<name>.json` records hand verification for one repository:

```json
{
  "findings": {
    "path/to/file.py:42:RSA-2048": {"verdict": "tp", "note": "key generation for test fixtures"}
  },
  "missed": [
    {"path": "path/to/dh.py", "line": 88, "algorithm": "DH", "note": "hand-rolled modular exponentiation"}
  ]
}
```

Keys are `path:line:label` exactly as in `results/<name>.json`. Only call sites are
labelled; imports are true by construction and are counted separately.

## What a verdict means

- **tp**: the line really uses the named algorithm, at the parameter set recorded if
  one is recorded. This includes use through a thin wrapper, such as Django's
  `md5(usedforsecurity=False)` or Ansible's `module.sha1(path)`, and use in test code.
  Whether the use is security-relevant is not part of the verdict; note it instead.
- **fp**: the line does not use that algorithm. A different algorithm, a wrong
  parameter set, or no cryptography at all, such as a project function that happens
  to be called `md5`.

A finding with the right algorithm but the wrong usage label (ECDSA where the key
does ECDH) is **fp**: the migration target it implies is wrong. An ECDSA or ECDH label
whose usage cannot be confirmed from the code is also **fp**, because it claims a
migration target without evidence. "EC, usage undetermined" claims no usage, so it
is **tp** when the primitive is right; the note records the actual usage where it
can be seen, which measures how often the scanner could have resolved it.

## How the labels were made

1. `assist.py` drafts a verdict only where the source gives unambiguous evidence,
   checked independently of the scanner: a Go package-level call whose package is
   imported under its own name with nothing in the file able to shadow that name, a
   recorded parameter set that appears literally in the call, a `hashlib` call, or a
   hash function imported from `hashlib` or Django's wrapper, or a `cryptography`
   object (`hashes.SHA1()`, `algorithms.ARC4()`, `padding.PKCS1v15()`) whose module is
   imported once, unaliased, from `cryptography` and bound nowhere else. Go `ecdsa.GenerateKey`
   is never drafted in a file that mentions ECDH or does `ScalarMult`. Each draft's
   note names its rule. A random sample of 40 drafts was read to confirm the rules,
   and all 32 drafts of the `cryptography` object rule were read when it was added.
2. Everything else was read in context and given a verdict by hand; those notes start
   with "read by hand".
3. A reviewer checks every **fp** and a random 10% of the **tp** labels, listed in
   `REVIEW.md` by `review.py`.

## Algorithm names

Java's algorithm-name occurrences (an unambiguous JCA name in a string literal) are not
labelled one by one, because they never gate a build. When the kind was added, all 95 in
the corpus were read: three were `"HmacSHA" + bits` and `"PBKDF2WithHmacSHA" + bits`, the
start of a name built at run time, wrongly read as SHA-1. That was fixed before the
measurement, leaving 92, all naming the algorithm they claim. Registry 2026.10.3 added
Ed448, X448, EdDSA and XDH, which brought 11 more in jjwt; all 11 were read and are correct.

JOSE algorithm names (`RS256`, `ES256`, `RSA-OAEP` and the rest) are algorithm names in
every language. When they were added, every one outside the eight JWT libraries was
read (158 at the time, 150 after the fix below, in certbot, twisted, scapy, x-crypto,
cfssl, vault and forge), along with a
fixed-seed sample of 30 of the 1,477 inside them. forge's `'RSA-OAEP'` is its own OAEP
scheme name with the hash passed separately, so `RSA-OAEP` was changed to record RSA
only, not JOSE's implied SHA-1. Everything else names the algorithm it claims; outside
JWT code, most are key type names (`"Ed25519"`) in SSH, DNSSEC and X.509 code.

## Missed findings

`missed` lists false negatives: uses of a quantum-broken or classically broken
primitive that Ratchet does not report at that line. Entries with `"source":
"search"` come from `find_missed.py`, a fixed list of precise searches for known
blind spots, recorded in each file's `searched` list; they are regenerated on every
run. Entries with `"source": "read"` were found by reading code and are kept. The
searches are not exhaustive, so anything outside them is unmeasured. Where a constant
names two algorithms (`x509.ECDSAWithSHA1`), the entry carries the first one matched.

Labels are claims, like registry entries. A change to a verdict says why in its
commit message.
