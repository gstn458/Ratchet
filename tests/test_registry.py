"""The registry is data. These tests keep registry.json, the copy embedded in
ratchet.py, and the detection tables that point into it consistent."""

import json
import re
import shutil
import subprocess
import sys

import pytest

import ratchet
from conftest import FIXTURES, REPO_ROOT, SCHEMA_DIR

sys.path.insert(0, str(REPO_ROOT / "tools"))
import embed_registry  # noqa: E402

REGISTRY_FILE = REPO_ROOT / "registry.json"

# Content hash of each registry_version. Changing any entry without bumping
# registry_version fails here, so a CBOM's recorded version always identifies
# exactly one set of claims. To change the registry: edit registry.json, bump
# registry_version, add the new hash below, run tools/embed_registry.py.
REGISTRY_CONTENT = {
    "2026.10.0": "4590536946952fb0683ea948055fc00c736efb79f57ac96064022fe3a4150029",
    "2026.10.1": "ced35b2338a8b06fae7249629ed17b3a62c34309eaaf86341aff98e182a427c2",
}

ENTRY_FIELDS = {
    "primitive", "quantum", "classical", "oid", "nist_quantum_security_level",
    "functions", "replacement", "why",
}
OPTIONAL_FIELDS = {"oid_note", "parameter_sets"}
OID = r"[0-2](\.(0|[1-9][0-9]*))+"


@pytest.fixture(scope="module")
def registry():
    return json.loads(REGISTRY_FILE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def cyclonedx_enums():
    bom = json.loads((SCHEMA_DIR / "bom-1.6.schema.json").read_text())
    props = bom["definitions"]["cryptoProperties"]["properties"]["algorithmProperties"]["properties"]
    level = props["nistQuantumSecurityLevel"]
    return {
        "primitive": set(props["primitive"]["enum"]),
        "functions": set(props["cryptoFunctions"]["items"]["enum"]),
        "level_range": (level["minimum"], level["maximum"]),
    }


# --- the embedded copy -------------------------------------------------------

def test_embedded_copy_matches_registry_json():
    assert embed_registry.main(["--check"]) == 0, (
        "ratchet.py's embedded registry has drifted from registry.json; "
        "run python3 tools/embed_registry.py"
    )


def test_embedded_copy_parses_to_the_same_registry(registry):
    assert json.loads(ratchet._EMBEDDED_REGISTRY) == registry


def test_tests_load_registry_json_not_the_embedded_copy():
    assert ratchet.REGISTRY_SOURCE == str(REGISTRY_FILE)


def test_embed_refuses_unembeddable_text():
    with pytest.raises(ValueError):
        embed_registry.render('{"why": "\'\'\'"}\n')


# --- runtime loading ---------------------------------------------------------

def run_copy(script_dir, *args):
    return subprocess.run(
        [sys.executable, "-I", str(script_dir / "ratchet.py"), *args],
        capture_output=True, text=True,
    )


def strip_volatile(doc):
    doc.pop("serialNumber")
    doc["metadata"].pop("timestamp")
    return doc


def test_single_file_falls_back_to_embedded_registry(tmp_path):
    # curl-one-file-and-run: ratchet.py alone, no registry.json beside it.
    shutil.copy(REPO_ROOT / "ratchet.py", tmp_path)
    target = str(FIXTURES / "walk" / "mixed")
    alone = run_copy(tmp_path, target, "--json")
    assert alone.returncode == 0, alone.stderr
    with_file = run_copy(REPO_ROOT, target, "--json")
    assert strip_volatile(json.loads(alone.stdout)) == strip_volatile(json.loads(with_file.stdout))


@pytest.mark.parametrize("content, message", [
    ("{not json", "not valid JSON"),
    ('{"schema_version": 1, "algorithms": {}}', "schema_version 1 is not supported"),
    ("[]", "schema_version None is not supported"),
])
def test_unusable_registry_file_is_an_error_not_a_fallback(tmp_path, content, message):
    shutil.copy(REPO_ROOT / "ratchet.py", tmp_path)
    (tmp_path / "registry.json").write_text(content)
    r = run_copy(tmp_path, str(FIXTURES / "go" / "rsa"), "--json")
    assert r.returncode != 0
    assert message in r.stderr
    assert r.stdout == ""


# --- structure ---------------------------------------------------------------

def test_registry_version_pins_content(registry):
    version = registry["registry_version"]
    assert version in REGISTRY_CONTENT, (
        f"registry_version {version} has no pinned hash in tests/test_registry.py"
    )
    assert ratchet.registry_digest(registry) == REGISTRY_CONTENT[version], (
        "registry.json content changed without a registry_version bump"
    )


def test_every_entry_has_exactly_the_expected_fields(registry):
    for name, entry in registry["algorithms"].items():
        assert ENTRY_FIELDS <= set(entry) <= ENTRY_FIELDS | OPTIONAL_FIELDS, name


def test_statuses_are_documented_values(registry):
    notes = registry["field_notes"]
    for name, entry in registry["algorithms"].items():
        assert entry["quantum"] in notes["quantum"], name
        assert entry["classical"] in notes["classical"], name


def test_primitives_and_functions_are_cyclonedx_values(registry, cyclonedx_enums):
    for name, entry in registry["algorithms"].items():
        assert entry["primitive"] in cyclonedx_enums["primitive"], name
        assert set(entry["functions"]) <= cyclonedx_enums["functions"], name
        assert entry["functions"], name


def all_levels(entry):
    yield entry["nist_quantum_security_level"]
    for ps in entry.get("parameter_sets", {}).values():
        if "nist_quantum_security_level" in ps:
            yield ps["nist_quantum_security_level"]


def test_security_levels_are_within_cyclonedx_range(registry, cyclonedx_enums):
    low, high = cyclonedx_enums["level_range"]
    for name, entry in registry["algorithms"].items():
        for level in all_levels(entry):
            assert isinstance(level, int) and low <= level <= high, name


def test_broken_algorithms_meet_no_security_category(registry):
    # Shor-broken or classically broken cannot meet even category 1.
    for name, entry in registry["algorithms"].items():
        if entry["quantum"] == "broken" or entry["classical"] == "broken":
            assert set(all_levels(entry)) == {0}, name


def test_post_quantum_algorithms_meet_a_category(registry):
    for name, entry in registry["algorithms"].items():
        if entry["quantum"] == "safe":
            assert min(all_levels(entry)) >= 1, name


def test_default_level_is_the_floor_of_known_parameter_sets(registry):
    # With the parameter set unknown, claim no more than the weakest one.
    for name, entry in registry["algorithms"].items():
        levels = [ps["nist_quantum_security_level"]
                  for ps in entry.get("parameter_sets", {}).values()
                  if "nist_quantum_security_level" in ps]
        if levels:
            assert entry["nist_quantum_security_level"] == min(levels), name


def test_oids_are_dotted_decimal_or_explained(registry):
    for name, entry in registry["algorithms"].items():
        if entry["oid"] is None:
            assert entry.get("oid_note", "").strip(), f"{name}: null oid needs an oid_note"
        else:
            assert re.fullmatch(OID, entry["oid"]), name
            assert "oid_note" not in entry, name
        for ps_name, ps in entry.get("parameter_sets", {}).items():
            assert set(ps) <= {"oid", "nist_quantum_security_level"}, (name, ps_name)
            if "oid" in ps:
                assert re.fullmatch(OID, ps["oid"]), (name, ps_name)


def test_parameter_set_overrides_reach_the_cbom():
    assert ratchet.parameter_claims("ML-DSA", "65") == ("2.16.840.1.101.3.4.3.18", 3)
    assert ratchet.parameter_claims("ML-DSA", None) == (None, 2)
    assert ratchet.parameter_claims("AES", "256") == (None, 5)
    assert ratchet.parameter_claims("RSA", "2048") == ("1.2.840.113549.1.1.1", 0)


def test_no_empty_text(registry):
    # An empty field in a compliance document reads as an oversight.
    for name, entry in registry["algorithms"].items():
        assert entry["replacement"].strip(), name
        assert entry["why"].strip(), name


def test_detection_tables_only_name_registry_entries(registry):
    names = set(registry["algorithms"])
    referenced = (
        set(ratchet.PY_MODULES.values())
        | set(ratchet.PY_HASH_NAMES.values())
        | set(ratchet.GO_IMPORTS.values())
        | {algo for _, algo, _ in ratchet.GO_CALL_PATTERNS}
    )
    assert referenced <= names, referenced - names


# --- provenance in the output ------------------------------------------------

def metadata_properties(doc):
    return {p["name"]: p["value"] for p in doc["metadata"]["properties"]}


def test_cbom_records_which_registry_produced_it(registry):
    findings, _ = ratchet.walk(str(FIXTURES / "go" / "rsa"))
    props = metadata_properties(ratchet.build_cbom(findings, "."))
    assert props["ratchet:scan_registry_version"] == registry["registry_version"]
    assert props["ratchet:scan_registry_sha256"] == REGISTRY_CONTENT[registry["registry_version"]]


def test_edited_registry_is_visible_in_the_cbom(tmp_path, registry):
    # Same registry_version, different content: the hash must give it away.
    shutil.copy(REPO_ROOT / "ratchet.py", tmp_path)
    edited = json.loads(json.dumps(registry))
    edited["algorithms"]["RSA"]["replacement"] = "something else"
    (tmp_path / "registry.json").write_text(json.dumps(edited))
    r = run_copy(tmp_path, str(FIXTURES / "go" / "rsa"), "--json")
    props = metadata_properties(json.loads(r.stdout))
    assert props["ratchet:scan_registry_version"] == registry["registry_version"]
    assert props["ratchet:scan_registry_sha256"] != REGISTRY_CONTENT[registry["registry_version"]]


def test_report_names_the_registry_source(tmp_path, registry):
    version = registry["registry_version"]
    shutil.copy(REPO_ROOT / "ratchet.py", tmp_path)
    alone = run_copy(tmp_path, str(FIXTURES / "go" / "rsa"))
    assert f"registry {version}  from embedded copy" in alone.stdout
    beside = run_copy(REPO_ROOT, str(FIXTURES / "go" / "rsa"))
    assert f"registry {version}  from registry.json" in beside.stdout
