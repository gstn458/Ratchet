"""The two Go backends: tree-sitter when installed, regex always.

Goldens are written with the regex backend. Every fixture with Go source is
scanned again with tree-sitter here, and the output must be identical apart
from the parser it names. The tests that need tree-sitter are skipped when it
is not installed; CI runs the suite both without and with it.
"""

import json
import subprocess
import sys

import pytest

import ratchet
from conftest import FIXTURES, REPO_ROOT, dumps, fixture_dirs, fixture_id, scan

RATCHET = str(REPO_ROOT / "ratchet.py")


def has_tree_sitter():
    try:
        ratchet.TreeSitterGo()
    except (ImportError, RuntimeError):
        return False
    return True


needs_tree_sitter = pytest.mark.skipif(not has_tree_sitter(), reason="tree-sitter-go not installed")

GO_FIXTURES = [root for root in fixture_dirs() if any(root.rglob("*.go"))]


def without_parser(cbom, report):
    """CBOM and report with the parsers that depend on tree-sitter taken out."""
    cbom["metadata"]["properties"] = [
        p for p in cbom["metadata"]["properties"]
        if not (p["name"] == "ratchet:parser" and p["value"].startswith(("Go: ", "Java: ", "JavaScript: ")))
    ]
    lines = [line for line in report.splitlines() if not line.startswith("parsers  ")]
    return dumps(cbom), "\n".join(lines)


def test_go_fixtures_exist():
    assert len(GO_FIXTURES) >= 15


@needs_tree_sitter
@pytest.mark.parametrize("root", GO_FIXTURES, ids=fixture_id)
def test_tree_sitter_matches_regex(root):
    assert without_parser(*scan(root, backend="tree-sitter")) == without_parser(*scan(root))


@needs_tree_sitter
def test_tree_sitter_names_itself_and_its_versions():
    _, report = scan(FIXTURES / "go" / "rsa", backend="tree-sitter")
    line = next(l for l in report.splitlines() if l.startswith("parsers  "))
    assert "Go tree-sitter " in line and " with tree-sitter-go " in line


@needs_tree_sitter
def test_auto_prefers_tree_sitter():
    assert ratchet.go_backend("auto")[1].startswith("tree-sitter ")


def test_regex_when_requested():
    lex, description = ratchet.go_backend("regex")
    assert lex is ratchet.regex_go_lex
    assert description == "regex (requested)"


def test_auto_falls_back_when_tree_sitter_is_missing(monkeypatch):
    def missing():
        raise ImportError("No module named 'tree_sitter'")
    monkeypatch.setattr(ratchet, "TreeSitterGo", missing)
    lex, description = ratchet.go_backend("auto")
    assert lex is ratchet.regex_go_lex
    assert description == "regex (tree-sitter not installed)"
    with pytest.raises(ratchet.BackendError, match="not installed"):
        ratchet.go_backend("tree-sitter")


def test_auto_falls_back_when_the_grammar_cannot_load(monkeypatch):
    def broken():
        raise RuntimeError("tree-sitter could not load the Go grammar")
    monkeypatch.setattr(ratchet, "TreeSitterGo", broken)
    assert ratchet.go_backend("auto")[1] == "regex (tree-sitter could not load the Go grammar)"
    with pytest.raises(ratchet.BackendError, match="could not load"):
        ratchet.go_backend("tree-sitter")


def test_unknown_backend_is_an_error():
    with pytest.raises(ratchet.BackendError):
        ratchet.go_backend("antlr")


def run_bare(*args):
    # -S drops site-packages, so tree-sitter is unavailable even if installed.
    return subprocess.run([sys.executable, "-I", "-S", RATCHET, *args], capture_output=True, text=True)


def test_bare_interpreter_reports_the_regex_fallback():
    r = run_bare(str(FIXTURES / "go" / "rsa"), "--json")
    assert r.returncode == 0, r.stderr
    parsers = [p["value"] for p in json.loads(r.stdout)["metadata"]["properties"]
               if p["name"] == "ratchet:parser"]
    assert parsers == ["Go: regex (tree-sitter not installed)",
                       "Java: not scanned (tree-sitter-java not installed)",
                       "JavaScript: not scanned (tree-sitter-javascript not installed)", "Python: ast"]


def test_java_without_tree_sitter_is_counted_not_dropped(tmp_path):
    (tmp_path / "Keys.java").write_text('class Keys { Object k = java.security.KeyPairGenerator.getInstance("RSA"); }')
    (tmp_path / "keys.py").write_text("import hashlib\nhashlib.md5()\n")
    r = run_bare(str(tmp_path))
    assert r.returncode == 0, r.stderr
    assert "not scanned  1 Java file: tree-sitter-java not installed" in r.stdout
    assert "1 Java file was not scanned (tree-sitter-java not installed)" in r.stdout
    r = run_bare(str(tmp_path), "--json")
    props = {(p["name"], p["value"]) for p in json.loads(r.stdout)["metadata"]["properties"]}
    assert ("ratchet:not_scanned_file", "Keys.java (Java: tree-sitter-java not installed)") in props
    assert ("ratchet:not_scanned_file_count", "1") in props


def test_requiring_tree_sitter_without_it_exits_2():
    r = run_bare(str(FIXTURES / "go" / "rsa"), "--backend", "tree-sitter")
    assert r.returncode == 2
    assert "not installed" in r.stderr
