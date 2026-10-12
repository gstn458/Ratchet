# Contributing to Ratchet

## Changing the algorithm registry

The registry is the part of Ratchet that makes a claim about cryptography. Everything
else is plumbing. A wrong entry does not produce a crash, it produces a confident,
plausible, wrong answer in a document somebody files for compliance. That is the worst
failure mode this project has, so registry changes are held to a different standard
than code changes.

Any pull request touching the registry must state, for each entry it adds or changes:

- The algorithm, and the exact parameter set where that matters.
- The claim being made. Which of the three buckets it lands in, and why.
- A citation to a NIST publication, an RFC, or equivalent primary source. Not a blog
  post, not a vendor page, not an AI-generated summary.
- The migration target, with the standard it comes from.

The three buckets are not interchangeable and a PR that blurs them will be rejected:

**Quantum broken.** Shor's algorithm defeats it outright. RSA, ECDSA, ECDH, Ed25519,
X25519, finite-field Diffie-Hellman, DSA.

**Already broken.** Weak today, independent of quantum. MD5, SHA-1, DES, 3DES, RC4.
These are usually the more urgent finding, and conflating them with the first bucket
is the most common mistake people make in this space.

**Reduced.** Grover gives a quadratic speedup only. AES-256, SHA-256. Recorded, not
flagged. Reporting these as vulnerabilities destroys the tool's credibility with
exactly the people whose opinion matters.

If you are not sure which bucket something belongs in, open an issue rather than a PR.
Being unsure is useful information and I would rather discuss it than review a guess.

The registry lives in `registry.json`. To change it:

1. Edit `registry.json`.
2. Bump `registry_version`, and add the new version's content hash to
   `REGISTRY_CONTENT` in `tests/test_registry.py`. The test prints a failure until you
   do, so a CBOM's recorded registry version always names exactly one set of claims.
3. Run `python3 tools/embed_registry.py` to refresh the copy embedded in `ratchet.py`.
   CI fails if the two differ.

Do not edit the embedded copy in `ratchet.py` by hand.

## Changing detection rules

Every detection change needs a fixture in `tests/fixtures` that would have caught the
bug, committed in the same PR. A rule without a fixture will be asked for one.

Precision matters more than recall for anything that gates CI or generates a pull
request. Recall matters more for the inventory. These are separate code paths with
separate thresholds, and a change that improves one at the cost of the other should
say so explicitly.

## Known limitations

The limitations section of the README is load-bearing, not boilerplate. If your change
removes a limitation, delete it from that list. If your change adds one, add it. A
security tool that overstates its coverage is worse than one that admits a gap.

## Reporting a false positive or false negative

Open an issue with the smallest source snippet that reproduces it, the language, and
what you expected. False negatives are more valuable to me than false positives, and
hand-rolled cryptography that Ratchet walks straight past is the most valuable of all.
