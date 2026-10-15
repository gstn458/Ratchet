"""Shortcuts the scanner takes for speed, checked against the rules they skip.

A shortcut that skips code is only safe if no rule could have matched that
code. These tests tie each shortcut to the rules it stands in for, so a new
rule that a shortcut would hide fails here rather than going quietly blind.
"""

import re

import ratchet


def test_go_call_patterns_contain_their_package_token():
    for import_path, pattern, _, _ in ratchet.GO_CALL_PATTERNS:
        token = ratchet.GO_PACKAGE_TOKEN[import_path]
        assert pattern.pattern.startswith(r"\b" + token[:-1] + r"\."), (import_path, pattern.pattern)


def test_go_variant_patterns_contain_their_package_token():
    for import_path, patterns in ratchet.GO_VARIANT_CALLS.items():
        token = import_path.rsplit("/", 1)[-1]
        assert token + "." in ratchet.GO_VARIANT_TOKENS
        for pattern, _ in patterns:
            assert pattern.pattern.startswith(r"\b" + token + r"\."), pattern.pattern


def test_go_elliptic_patterns_contain_a_token():
    for pattern in ratchet.GO_ELLIPTIC_DIRECT:
        assert r"elliptic\." in pattern.pattern or "Scalar" in pattern.pattern, pattern.pattern
    assert ratchet.GO_ELLIPTIC_TOKENS == {"elliptic.", "Scalar"}


def test_go_usage_patterns_contain_their_tokens():
    # scan_go checks "ECDH"/"ecdh.", "ScalarMult" and "ecdsa."/".Sign" before
    # running these; each alternative must contain one of them.
    assert ratchet.GO_ECDH_NAME.pattern == r"ECDH|\becdh\."
    assert "ScalarMult" in ratchet.GO_SCALAR_MULT.pattern
    signing = ratchet.GO_ECDSA_SIGNING.pattern
    first, second = signing.split(r"\(|", 1)
    assert first.startswith(r"\becdsa\.") and second.startswith(r"\.Sign"), signing
