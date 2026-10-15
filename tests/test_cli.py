"""End-to-end behaviour of the command line, run as a subprocess."""

import json
import subprocess
import sys

from conftest import FIXTURES, REPO_ROOT

RATCHET = str(REPO_ROOT / "ratchet.py")


def run(*args, cwd=None):
    # -I: isolated mode, so nothing from the environment or cwd leaks in.
    return subprocess.run(
        [sys.executable, "-I", RATCHET, *args],
        cwd=cwd, capture_output=True, text=True,
    )


def test_missing_directory_exits_2(tmp_path):
    r = run(str(tmp_path / "nope"))
    assert r.returncode == 2
    assert "not a directory" in r.stderr


def test_report_exits_0_by_default():
    r = run(str(FIXTURES / "python" / "rsa_cryptography"))
    assert r.returncode == 0
    assert "QUANTUM VULNERABLE" in r.stdout


def test_fail_on_vulnerable_exits_1_when_quantum_broken():
    r = run(str(FIXTURES / "python" / "rsa_cryptography"), "--fail-on-vulnerable")
    assert r.returncode == 1


def test_fail_on_vulnerable_ignores_classically_broken_only():
    # Current behaviour: the CI gate is quantum-broken only. MD5 and SHA-1
    # alone do not fail the build.
    r = run(str(FIXTURES / "python" / "hashlib"), "--fail-on-vulnerable")
    assert r.returncode == 0
    assert "ALREADY BROKEN" in r.stdout


def test_fail_on_vulnerable_exits_0_when_clean(tmp_path):
    (tmp_path / "clean.py").write_text("print('hello')\n")
    r = run(str(tmp_path), "--fail-on-vulnerable")
    assert r.returncode == 0
    assert "No quantum-vulnerable primitives found." in r.stdout


def test_json_prints_cbom_only():
    r = run(str(FIXTURES / "go" / "rsa"), "--json")
    assert r.returncode == 0
    doc = json.loads(r.stdout)
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.6"


def test_json_with_fail_on_vulnerable():
    r = run(str(FIXTURES / "go" / "rsa"), "--json", "--fail-on-vulnerable")
    assert r.returncode == 1
    json.loads(r.stdout)


def test_cbom_file_matches_json_output(tmp_path):
    out = tmp_path / "cbom.json"
    r = run(str(FIXTURES / "walk" / "mixed"), "--cbom", str(out))
    assert r.returncode == 0
    assert f"CBOM written to {out}" in r.stdout
    written = json.loads(out.read_text())
    printed = json.loads(run(str(FIXTURES / "walk" / "mixed"), "--json").stdout)
    for doc in (written, printed):
        doc.pop("serialNumber")
        doc["metadata"].pop("timestamp")
    assert written == printed


def test_runs_with_no_third_party_packages():
    # The zero-dependency promise: -I plus -S drops site-packages entirely,
    # so any non-stdlib import in ratchet.py fails here.
    r = subprocess.run(
        [sys.executable, "-I", "-S", RATCHET, str(FIXTURES / "walk" / "mixed"), "--json"],
        capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stderr
    json.loads(r.stdout)


def test_include_vendored_scans_vendored_directories():
    target = str(FIXTURES / "walk" / "skipped_dirs")
    default = json.loads(run(target, "--json").stdout)
    included = json.loads(run(target, "--json", "--include-vendored").stdout)
    names = lambda doc: {c["name"] for c in doc["components"]}
    assert names(default) == {"SHA-1"}
    assert {"MD5", "DES"} <= names(included)
    props = lambda doc: {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
    assert props(default)["ratchet:include_vendored"] == "false"
    assert props(included)["ratchet:include_vendored"] == "true"


def test_report_always_states_skipped_directories(tmp_path):
    (tmp_path / "app.py").write_text("print('hello')\n")
    assert "skipped no directories" in run(str(tmp_path)).stdout
    (tmp_path / "vendor").mkdir()
    assert "skipped 1 directory:" in run(str(tmp_path)).stdout


def test_unreadable_file_is_reported_not_dropped(tmp_path):
    (tmp_path / "ok.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    (tmp_path / "gone.py").symlink_to(tmp_path / "missing.py")
    r = run(str(tmp_path), "--json")
    assert r.returncode == 0, r.stderr
    props = [(p["name"], p["value"]) for p in json.loads(r.stdout)["metadata"]["properties"]]
    assert ("ratchet:unparsed_file", "gone.py (could not be read: No such file or directory)") in props
    assert "could not parse 1 of 2 files" in run(str(tmp_path)).stdout


def test_invalid_ratchetignore_stops_the_scan(tmp_path):
    (tmp_path / "app.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    (tmp_path / ".ratchetignore").write_text("app.py\n")
    r = run(str(tmp_path), "--json")
    assert r.returncode == 2
    assert ".ratchetignore line 1: every rule needs a reason" in r.stderr
    assert r.stdout == ""


def test_suppressed_findings_do_not_fail_ci(tmp_path):
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "gen.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "rsa.generate_private_key(65537, 2048)\n")
    assert run(str(tmp_path), "--fail-on-vulnerable").returncode == 1
    (tmp_path / ".ratchetignore").write_text("suppress RSA tools/** -- test keys only\n")
    for args in ((), ("--json",)):
        r = run(str(tmp_path), "--fail-on-vulnerable", *args)
        assert r.returncode == 0, r.stdout
    assert "2 quantum-vulnerable findings suppressed" in run(str(tmp_path)).stdout


def test_ci_gate_counts_call_sites_not_imports():
    # Imports belong to the inventory, not the CI gate.
    r = run(str(FIXTURES / "python" / "import_only"), "--fail-on-vulnerable")
    assert r.returncode == 0
    assert "No quantum-vulnerable call sites and 2 imports" in r.stdout
    r = run(str(FIXTURES / "python" / "import_only"), "--fail-on-vulnerable", "--json")
    assert r.returncode == 0
    # An undetermined EC call site is still quantum vulnerable and does fail.
    assert run(str(FIXTURES / "python" / "ec_undetermined"), "--fail-on-vulnerable").returncode == 1
