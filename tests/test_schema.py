"""Every CBOM Ratchet produces must validate against the CycloneDX 1.6 schema.

The schema is committed under tests/schema and never fetched at test time.
"""

import hashlib
import json

import pytest

import ratchet
from conftest import REPO_ROOT, SCHEMA_DIR, fixture_dirs, fixture_id

# Pinned to CycloneDX/specification tag 1.6.2 (commit e833d73). If one of these
# changes, someone edited the vendored schema; see tests/schema/README.md.
SCHEMA_SHA256 = {
    "bom-1.6.schema.json": "18f57f7482593bad9f21b4feed09084640cbeff419d62ad5090c5ceccca5b37d",
    "spdx.schema.json": "c41917196639055e9f9670811bac23ef777732144f3ff5a2f39686f61580dbe6",
    "jsf-0.82.schema.json": "8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae",
}


def errors(validator, doc):
    return [f"{list(e.absolute_path)}: {e.message}" for e in validator.iter_errors(doc)]


def test_vendored_schema_is_unmodified():
    found = {
        p.name: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in SCHEMA_DIR.glob("*.schema.json")
    }
    assert found == SCHEMA_SHA256


def test_validator_rejects_invalid_cbom(cbom_validator):
    # Proves the validator is wired up and not vacuously passing.
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"type": "nonsense"}]}
    assert errors(cbom_validator, doc)


@pytest.mark.parametrize("root", fixture_dirs(), ids=fixture_id)
def test_golden_cbom_is_valid(root, cbom_validator):
    doc = json.loads((root / "expected.cbom.json").read_text())
    assert errors(cbom_validator, doc) == []


@pytest.mark.parametrize("root", fixture_dirs(), ids=fixture_id)
def test_fresh_scan_is_valid(root, cbom_validator):
    # Covers the real timestamp and serial number formats, which goldens normalise.
    findings, _ = ratchet.walk(str(root))
    assert errors(cbom_validator, ratchet.build_cbom(findings, str(root))) == []


@pytest.mark.parametrize("root", fixture_dirs(), ids=fixture_id)
def test_bom_refs_are_unique(root):
    # JSON Schema cannot express this; the CycloneDX spec requires it.
    doc = json.loads((root / "expected.cbom.json").read_text())
    refs = [c["bom-ref"] for c in doc.get("components", [])]
    refs.append(doc["metadata"]["component"]["bom-ref"])
    assert len(refs) == len(set(refs))


def test_example_cbom_is_valid(cbom_validator):
    doc = json.loads((REPO_ROOT / "paramiko-cbom.json").read_text())
    assert errors(cbom_validator, doc) == []
