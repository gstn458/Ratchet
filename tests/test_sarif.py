"""SARIF 2.1.0 output, for GitHub code scanning and other SARIF consumers.

Every fixture's SARIF must validate against the vendored OASIS schema. The walk
fixtures also keep a golden expected.sarif.json; regenerate with

    pytest tests/test_sarif.py --update-golden

and review the diff.
"""

import hashlib
import json
import os
import subprocess
import sys

import pytest

import ratchet
from conftest import FIXTURES, REPO_ROOT, fixture_dirs, fixture_id, fixture_options, skip_without_tree_sitter

SARIF_SCHEMA = REPO_ROOT / "tests" / "schema" / "sarif-2.1.0" / "sarif-schema-2.1.0.json"
# OASIS SARIF 2.1.0 Errata 01, from oasis-tcs/sarif-spec commit d825fb7.
# See tests/schema/README.md.
SARIF_SCHEMA_SHA256 = "c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e"

WALK_FIXTURES = [root for root in fixture_dirs() if root.parent.name == "walk"]


@pytest.fixture(scope="module")
def validator():
    import jsonschema

    schema = json.loads(SARIF_SCHEMA.read_text())
    return jsonschema.Draft4Validator(schema, format_checker=jsonschema.Draft4Validator.FORMAT_CHECKER)


def errors(validator, doc):
    return [f"{list(e.absolute_path)}: {e.message}" for e in validator.iter_errors(doc)]


def walk_in(root, **options):
    """Scan root from inside it, as the CLI does, so paths are relative."""
    skip_without_tree_sitter(root)
    options = {"backend": "regex", **fixture_options(root), **options}
    old = os.getcwd()
    os.chdir(root)
    try:
        return ratchet.walk(".", **options)
    finally:
        os.chdir(old)


def sarif(root, **options):
    return ratchet.build_sarif(walk_in(root, **options))


def dumps(doc):
    return json.dumps(doc, indent=2) + "\n"


def results(doc):
    return doc["runs"][0]["results"]


def test_vendored_schema_is_unmodified():
    assert hashlib.sha256(SARIF_SCHEMA.read_bytes()).hexdigest() == SARIF_SCHEMA_SHA256


def test_validator_rejects_invalid_sarif(validator):
    # Proves the validator is wired up and not vacuously passing.
    doc = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "ratchet"}},
                                        "results": [{"message": {"text": "x"}, "level": "fatal"}]}]}
    assert errors(validator, doc)


def test_walk_fixtures_exist():
    assert len(WALK_FIXTURES) >= 5


@pytest.mark.parametrize("root", fixture_dirs(), ids=fixture_id)
def test_sarif_is_valid(root, validator):
    assert errors(validator, sarif(root)) == []


@pytest.mark.parametrize("root", WALK_FIXTURES, ids=fixture_id)
def test_golden_sarif(root, update_golden):
    doc = dumps(sarif(root))
    golden = root / "expected.sarif.json"
    if update_golden:
        golden.write_text(doc)
        return
    assert doc == golden.read_text()


@pytest.mark.parametrize("root", fixture_dirs(), ids=fixture_id)
def test_reduced_margin_algorithms_are_left_out(root):
    # AES and SHA-256 are in the CBOM but are not code-scanning alerts.
    scan = walk_in(root)
    doc = ratchet.build_sarif(scan)
    for r in results(doc):
        spec = ratchet.ALGORITHMS[doc["runs"][0]["tool"]["driver"]["rules"][r["ruleIndex"]]["name"]]
        assert "broken" in (spec["quantum"], spec["classical"])
    expected = [f for f in scan.findings if "broken" in (ratchet.ALGORITHMS[f.algorithm]["quantum"],
                                                         ratchet.ALGORITHMS[f.algorithm]["classical"])]
    assert len(results(doc)) == len(expected)


@pytest.mark.parametrize("algorithm, kind, level", [
    ("RSA", ratchet.CALL, "error"),
    ("RSA", ratchet.IMPORT, "note"),
    ("RSA", ratchet.NAME, "note"),
    ("MD5", ratchet.CALL, "warning"),
    ("MD5", ratchet.IMPORT, "note"),
    ("MD5", ratchet.NAME, "note"),
    ("AES", ratchet.CALL, None),
    ("SHA-256", ratchet.CALL, None),
])
def test_levels(algorithm, kind, level):
    assert ratchet.sarif_level(ratchet.Finding(algorithm, "a.py", 1, "x", kind=kind)) == level


@pytest.mark.parametrize("root", fixture_dirs(), ids=fixture_id)
def test_rule_index_names_the_rule(root):
    doc = sarif(root)
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == sorted({r["id"] for r in rules})
    for r in results(doc):
        assert rules[r["ruleIndex"]]["id"] == r["ruleId"]


@pytest.mark.parametrize("root", fixture_dirs(), ids=fixture_id)
def test_fingerprints_are_unique(root):
    prints = [r["partialFingerprints"]["ratchet/v1"] for r in results(sarif(root))]
    assert len(prints) == len(set(prints))


def test_fingerprints_survive_a_line_move(tmp_path):
    code = "import hashlib\nhashlib.md5(b'a')\nhashlib.md5(b'a')\n"
    (tmp_path / "a.py").write_text(code)
    before = [r["partialFingerprints"] for r in results(ratchet.build_sarif(ratchet.walk(str(tmp_path))))]
    (tmp_path / "a.py").write_text("\n\n# moved\n" + code)
    after = [r["partialFingerprints"] for r in results(ratchet.build_sarif(ratchet.walk(str(tmp_path))))]
    assert before == after
    # The same line twice is told apart by its ordinal.
    assert [p["ratchet/v1"][-2:] for p in after] == [":1", ":2"]


def test_suppressed_findings_carry_suppressions():
    scan = walk_in(FIXTURES / "walk" / "suppressions")
    doc = ratchet.build_sarif(scan)
    suppressed = [r for r in results(doc) if "suppressions" in r]
    assert len(suppressed) == sum(f.suppressed_by is not None and ratchet.sarif_level(f) is not None
                                  for f in scan.findings)
    assert suppressed
    justifications = {s["justification"] for r in suppressed for s in r["suppressions"]}
    assert ("suppress RSA tools/** -- generates throwaway keys for the test suite; never shipped "
            "(.ratchetignore line 2, not_affected)") in justifications
    assert ("false-positive MD5 legacy/local.py -- project function named md5, not hashlib "
            "(.ratchetignore line 3, false_positive)") in justifications
    for r in suppressed:
        assert r["suppressions"][0]["kind"] == "external"
        assert r["suppressions"][0]["status"] == "accepted"
    assert any("suppressions" not in r for r in results(doc))


def test_test_code_is_marked():
    doc = sarif(FIXTURES / "walk" / "test_code")
    flags = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]: r["properties"]["ratchet:testCode"]
             for r in results(doc)}
    assert flags["pkg/test_hashing.py"] is True
    assert flags["app/latest.py"] is False
    assert all(r["message"]["text"].split(". ")[0].endswith(" in test code") == r["properties"]["ratchet:testCode"]
               for r in results(doc))


def test_unparsed_files_are_notifications(tmp_path):
    (tmp_path / "bad.py").write_text("def broken(:\n")
    doc = ratchet.build_sarif(ratchet.walk(str(tmp_path)))
    notes = doc["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    assert notes[0]["message"]["text"] == "bad.py was not parsed: not valid Python 3 syntax at line 1"
    assert notes[0]["level"] == "warning"


def test_paths_are_uri_encoded(tmp_path, validator):
    (tmp_path / "my dir").mkdir()
    (tmp_path / "my dir" / "a#b.py").write_text("import hashlib\nhashlib.md5(b'a')\n")
    doc = ratchet.build_sarif(ratchet.walk(str(tmp_path)))
    assert results(doc)[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "my%20dir/a%23b.py"
    assert errors(validator, doc) == []


def test_cli_writes_sarif(tmp_path):
    (tmp_path / "a.py").write_text("import hashlib\nhashlib.md5(b'a')\n")
    out = tmp_path / "out.sarif"
    r = subprocess.run([sys.executable, str(REPO_ROOT / "ratchet.py"), str(tmp_path), "--sarif", str(out)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert f"SARIF written to {out}" in r.stdout
    assert results(json.loads(out.read_text()))[0]["ruleId"] == "ratchet-classical-md5"
    # With --json, stdout is the CBOM alone.
    r = subprocess.run([sys.executable, str(REPO_ROOT / "ratchet.py"), str(tmp_path), "--json", "--sarif", str(out)],
                       capture_output=True, text=True)
    assert json.loads(r.stdout)["bomFormat"] == "CycloneDX"
