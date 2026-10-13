# Vendored CycloneDX schema

These files are the official CycloneDX 1.6 JSON schema, committed so tests never
make a network call and so the exact schema Ratchet is validated against is part
of the repository history.

Source: https://github.com/CycloneDX/specification, tag `1.6.2`, commit
`e833d732337dd33aceb45ff1991f896796f1e5e7`, directory `schema/`.

| File | SHA-256 |
| --- | --- |
| bom-1.6.schema.json | `18f57f7482593bad9f21b4feed09084640cbeff419d62ad5090c5ceccca5b37d` |
| spdx.schema.json | `c41917196639055e9f9670811bac23ef777732144f3ff5a2f39686f61580dbe6` |
| jsf-0.82.schema.json | `8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae` |

`bom-1.6.schema.json` references the other two by relative `$ref`, so all three
are needed. `tests/test_schema.py` checks these hashes, so an accidental edit
fails the build. To move to a newer 1.6.x patch release, download the three files
from the new tag, update the hashes here and in `test_schema.py`, and say why in
the commit message.

Format keywords such as `iri-reference` are only enforced when jsonschema's
optional format packages are installed. Structure, types and enums are always
enforced.
