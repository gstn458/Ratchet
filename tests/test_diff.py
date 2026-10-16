"""ratchet diff: two CBOMs compared file by file.

Each directory under tests/diff holds an old/ and a new/ source tree. Both are
scanned, and the comparison of the two CBOMs must match expected.diff.txt and
expected.diff.json. Regenerate with

    pytest tests/test_diff.py --update-golden

and review the diff.
"""

import io
import json
import os
import subprocess
import sys
from contextlib import redirect_stdout
from pathlib import Path

import pytest

import ratchet
from conftest import REPO_ROOT

CASES_DIR = REPO_ROOT / "tests" / "diff"
CASES = sorted(p for p in CASES_DIR.iterdir() if p.is_dir())


def cbom(root):
    old = os.getcwd()
    os.chdir(root)
    try:
        return ratchet.build_cbom(ratchet.walk(".", backend="regex"), ".")
    finally:
        os.chdir(old)


def write_pair(case, tmp_path):
    for side in ("old", "new"):
        (tmp_path / f"{side}.cbom.json").write_text(json.dumps(cbom(case / side), indent=2))


def run_diff(tmp_path, *args):
    """ratchet diff old.cbom.json new.cbom.json in tmp_path, in this process.
    Returns (exit code, stdout)."""
    old = os.getcwd()
    os.chdir(tmp_path)
    out = io.StringIO()
    try:
        with redirect_stdout(out):
            code = ratchet.main(["diff", "old.cbom.json", "new.cbom.json", *args])
    finally:
        os.chdir(old)
    return code, out.getvalue()


def test_cases_exist():
    assert {c.name for c in CASES} >= {"added", "moved", "removed", "renamed", "suppressed"}


@pytest.mark.parametrize("case", CASES, ids=lambda p: p.name)
def test_golden_diff(case, tmp_path, update_golden):
    write_pair(case, tmp_path)
    _, text = run_diff(tmp_path)
    _, as_json = run_diff(tmp_path, "--json")
    if update_golden:
        (case / "expected.diff.txt").write_text(text)
        (case / "expected.diff.json").write_text(as_json)
        return
    assert text == (case / "expected.diff.txt").read_text()
    assert as_json == (case / "expected.diff.json").read_text()


@pytest.mark.parametrize("case, code", [
    ("added", 1),       # one more RSA call site in keys.py
    ("moved", 0),       # lines moved within the file: no change
    ("removed", 0),
    ("renamed", 1),     # counted per file, so a rename reads as new; see README
    ("suppressed", 0),  # the new call site is under a suppress rule
])
def test_fail_on_new_vulnerable(case, code, tmp_path):
    write_pair(CASES_DIR / case, tmp_path)
    assert run_diff(tmp_path, "--fail-on-new-vulnerable")[0] == code
    assert run_diff(tmp_path)[0] == 0


def test_imports_and_classical_calls_do_not_fail(tmp_path):
    (tmp_path / "old").mkdir()
    (tmp_path / "new").mkdir()
    (tmp_path / "new" / "a.py").write_text(
        "import hashlib\nfrom cryptography.hazmat.primitives.asymmetric import rsa\nhashlib.md5(b'x')\n")
    for side in ("old", "new"):
        (tmp_path / f"{side}.cbom.json").write_text(json.dumps(cbom(tmp_path / side)))
    code, text = run_diff(tmp_path, "--fail-on-new-vulnerable")
    assert code == 0
    assert "RSA import  a.py  0 -> 1" in text
    assert "MD5 call site  a.py  0 -> 1" in text


def test_test_code_counts_like_the_scan_gate(tmp_path):
    # --fail-on-vulnerable counts call sites in test code, so the diff does too.
    (tmp_path / "old" / "tests").mkdir(parents=True)
    (tmp_path / "new" / "tests").mkdir(parents=True)
    (tmp_path / "new" / "tests" / "test_keys.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
    for side in ("old", "new"):
        (tmp_path / f"{side}.cbom.json").write_text(json.dumps(cbom(tmp_path / side)))
    assert run_diff(tmp_path, "--fail-on-new-vulnerable")[0] == 1


def edited(tmp_path, change):
    write_pair(CASES_DIR / "moved", tmp_path)
    path = tmp_path / "new.cbom.json"
    doc = json.loads(path.read_text())
    change(doc)
    path.write_text(json.dumps(doc))
    return run_diff(tmp_path)[1]


def set_property(doc, name, value):
    for p in doc["metadata"]["properties"]:
        if p["name"] == name:
            p["value"] = value


def test_registry_mismatch_is_a_warning(tmp_path):
    text = edited(tmp_path, lambda d: set_property(d, "ratchet:scan_registry_version", "2099.1.1"))
    assert f"warning: registry version differs: {ratchet.REGISTRY['registry_version']} -> 2099.1.1" in text


def test_parser_mismatch_is_a_warning(tmp_path):
    def change(doc):
        for p in doc["metadata"]["properties"]:
            if p["name"] == "ratchet:parser" and p["value"].startswith("Go: "):
                p["value"] = "Go: tree-sitter 0.23.2 with tree-sitter-go 0.23.4"
    text = edited(tmp_path, change)
    assert "warning: Go parser differs: regex (requested) -> tree-sitter 0.23.2 with tree-sitter-go 0.23.4" in text


def test_new_unparsed_file_is_a_warning(tmp_path):
    def change(doc):
        doc["metadata"]["properties"].append(
            {"name": "ratchet:unparsed_file", "value": "bad.py (not valid Python 3 syntax at line 1)"})
    text = edited(tmp_path, change)
    assert ("warning: the new scan could not parse bad.py (not valid Python 3 syntax at line 1), "
            "so any findings in it are missing") in text


def test_identical_cboms_have_no_changes(tmp_path):
    write_pair(CASES_DIR / "added", tmp_path)
    (tmp_path / "old.cbom.json").write_text((tmp_path / "new.cbom.json").read_text())
    code, text = run_diff(tmp_path, "--fail-on-new-vulnerable")
    assert code == 0
    assert "\nno changes\n" in text
    assert "warning" not in text


@pytest.mark.parametrize("content, message", [
    (None, "cannot read"),
    ("{not json", "is not JSON"),
    ('{"bomFormat": "CycloneDX", "metadata": {"tools": {"components": [{"name": "other"}]}}}',
     "is not a CBOM written by ratchet"),
    ('[1, 2]', "is not a CBOM written by ratchet"),
    ('{"bomFormat": "CycloneDX", "metadata": {"tools": {"components": [{"name": "ratchet"}]}}, '
     '"components": [{"type": "cryptographic-asset", "name": "RSA"}]}', "is not a CBOM written by ratchet"),
])
def test_bad_input_exits_2(tmp_path, content, message):
    write_pair(CASES_DIR / "moved", tmp_path)
    if content is None:
        (tmp_path / "new.cbom.json").unlink()
    else:
        (tmp_path / "new.cbom.json").write_text(content)
    r = subprocess.run([sys.executable, str(REPO_ROOT / "ratchet.py"), "diff", "old.cbom.json", "new.cbom.json"],
                       capture_output=True, text=True, cwd=tmp_path)
    assert r.returncode == 2
    assert message in r.stderr


def test_scan_still_works_beside_diff(tmp_path):
    # A directory named diff is scanned when given as ./diff.
    (tmp_path / "diff").mkdir()
    (tmp_path / "diff" / "a.py").write_text("import hashlib\nhashlib.md5(b'a')\n")
    r = subprocess.run([sys.executable, str(REPO_ROOT / "ratchet.py"), "./diff", "--json"],
                       capture_output=True, text=True, cwd=tmp_path)
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout)["components"][0]["name"] == "MD5"
