"""Two runs over the same tree must produce identical output, apart from the
timestamp and serial number, regardless of filesystem directory order."""

import os

import pytest

import ratchet
from conftest import dumps, fixture_dirs, fixture_id, scan

REAL_WALK = os.walk


def reversed_walk(top, *args, **kwargs):
    # Same tree, opposite listing order. Pruning still works because os.walk
    # reads the dirnames list back after we yield it.
    for dirpath, dirnames, filenames in REAL_WALK(top, *args, **kwargs):
        dirnames.reverse()
        filenames.reverse()
        yield dirpath, dirnames, filenames


@pytest.mark.parametrize("root", fixture_dirs(), ids=fixture_id)
def test_output_is_independent_of_directory_order(root, monkeypatch):
    forward = scan(root)
    monkeypatch.setattr(ratchet.os, "walk", reversed_walk)
    backward = scan(root)
    assert dumps(forward[0]) == dumps(backward[0])
    assert forward[1] == backward[1]


@pytest.mark.parametrize("root", fixture_dirs(), ids=fixture_id)
def test_every_cbom_array_is_sorted(root):
    cbom, _ = scan(root)
    names = [c["name"] for c in cbom["components"]]
    assert names == sorted(names)
    for c in cbom["components"]:
        locations = [
            (path, int(line))
            for path, line in (o["location"].rsplit("#L", 1) for o in c["evidence"]["occurrences"])
        ]
        assert locations == sorted(locations)
        props = [p["name"] for p in c["properties"]]
        assert props == sorted(props)
        if c["type"] == "cryptographic-asset":
            functions = c["cryptoProperties"]["algorithmProperties"]["cryptoFunctions"]
            assert functions == sorted(functions)
