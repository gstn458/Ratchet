"""Parsing and matching for .ratchetignore."""

import re

import pytest

import ratchet


def rule(pattern):
    return ratchet.IgnoreRule(1, pattern, "reason")


@pytest.mark.parametrize("pattern, path, expected", [
    ("docs/", "docs/a.py", True),
    ("docs/", "docs/deep/a.py", True),
    ("docs/", "src/docs/a.py", True),          # no leading slash: any depth
    ("docs/", "docs.py", False),               # trailing slash: directories only
    ("/docs/", "src/docs/a.py", False),        # leading slash: anchored
    ("*_pb.go", "a/b/x_pb.go", True),
    ("*_pb.go", "x_pb.go.bak", False),
    ("src/*.py", "src/a.py", True),
    ("src/*.py", "src/sub/a.py", False),       # * stays within a directory
    ("src/**/*.py", "src/sub/deep/a.py", True),
    ("src/**/*.py", "src/a.py", True),         # **/ matches zero directories too
    ("src/cache/**", "src/cache/a.py", True),
    ("src/cache/**", "src/cachex/a.py", False),
    ("a?.py", "ab.py", True),
    ("a?.py", "a/b.py", False),
    ("legacy.py", "x/legacy.py", True),
])
def test_glob_semantics(pattern, path, expected):
    assert rule(pattern).matches(path) is expected


def test_parses_rules_with_reasons_and_skips_comments():
    rules, suppressions = ratchet.parse_ignore_file("# comment\n\ndocs/ -- not shipped\n  *.gen.py  --  generated \n")
    assert suppressions == []
    assert [(r.line, r.pattern, r.reason) for r in rules] == [
        (3, "docs/", "not shipped"), (4, "*.gen.py", "generated"),
    ]


@pytest.mark.parametrize("text, message", [
    ("docs/\n", "line 1: every rule needs a reason"),
    ("docs/ -- \n", "line 1: every rule needs a reason"),
    ("ok/ -- fine\n!docs/keep.py -- keep it\n", "line 2: negation (!) is not supported"),
    ("docs/ more -- why\n", "line 1: expected '<glob> -- <reason>'"),
])
def test_rejects_rules_without_a_usable_reason_or_form(text, message):
    with pytest.raises(ratchet.IgnoreFileError, match=message.replace("(", r"\(").replace(")", r"\)")):
        ratchet.parse_ignore_file(text)


def test_parses_suppressions():
    _, rules = ratchet.parse_ignore_file(
        "suppress md5 src/cache/** -- cache keys\n"
        "false-positive RSA tools/x.py -- a help string, not a call\n")
    assert [(r.line, r.algorithm, r.pattern, r.state, r.reason) for r in rules] == [
        (1, "MD5", "src/cache/**", "not_affected", "cache keys"),
        (2, "RSA", "tools/x.py", "false_positive", "a help string, not a call"),
    ]


@pytest.mark.parametrize("text, message", [
    ("suppress MD5 src/** \n", "line 1: every rule needs a reason"),
    ("suppress MD5 -- why\n", "line 1: expected 'suppress <ALGORITHM> <glob> -- <reason>'"),
    ("suppress BLOWFISH src/** -- why\n", "line 1: BLOWFISH is not an algorithm in the registry"),
    ("suppress AES src/** -- why\n", "line 1: Ratchet does not flag AES"),
    ("suppress MD5 !src/** -- why\n", "line 1: negation"),
])
def test_rejects_bad_suppressions(text, message):
    with pytest.raises(ratchet.IgnoreFileError, match=re.escape(message)):
        ratchet.parse_ignore_file(text)


def test_vulnerability_ids_are_namespaced_by_bucket():
    assert ratchet.vulnerability_id("RSA") == "ratchet-pqc-rsa"
    assert ratchet.vulnerability_id("EC") == "ratchet-pqc-ec"
    assert ratchet.vulnerability_id("MD5") == "ratchet-classical-md5"
    assert ratchet.vulnerability_id("SHA-1") == "ratchet-classical-sha-1"
    assert ratchet.vulnerability_id("3DES") == "ratchet-classical-3des"
