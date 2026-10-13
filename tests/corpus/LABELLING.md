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
does ECDH) is **fp**: the migration target it implies is wrong.

## Missed findings

`missed` lists false negatives found by reading the code: cryptographic use of a
quantum-broken or classically broken primitive that Ratchet does not report. Note why,
for example a call through an aliased import, a key passed between functions, or
hand-rolled arithmetic.

Labels are claims, like registry entries. A change to a verdict says why in its
commit message.
