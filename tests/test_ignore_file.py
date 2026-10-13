"""Parsing and matching for .ratchetignore."""

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
    rules = ratchet.parse_ignore_file("# comment\n\ndocs/ -- not shipped\n  *.gen.py  --  generated \n")
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
