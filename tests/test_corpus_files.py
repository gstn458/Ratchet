"""Offline consistency checks for the corpus files. The corpus run itself
fetches repositories and lives in tests/corpus/run.py, outside pytest."""

import json
import re

import pytest

from conftest import REPO_ROOT

CORPUS = REPO_ROOT / "tests" / "corpus"
MANIFEST = json.loads((CORPUS / "manifest.json").read_text())
NAMES = [r["name"] for r in MANIFEST["repositories"]]


def test_manifest_pins_every_repository_to_a_commit():
    assert len(NAMES) == len(set(NAMES)) == 20
    for repo in MANIFEST["repositories"]:
        assert re.fullmatch(r"[0-9a-f]{40}", repo["commit"]), repo["name"]
        assert repo["url"].startswith("https://github.com/"), repo["name"]
        assert repo["why"].strip(), repo["name"]


@pytest.mark.parametrize("name", NAMES)
def test_results_are_committed_for_the_pinned_commit(name):
    result = json.loads((CORPUS / "results" / f"{name}.json").read_text())
    pinned = next(r["commit"] for r in MANIFEST["repositories"] if r["name"] == name)
    assert result["commit"] == pinned


@pytest.mark.parametrize("name", NAMES)
def test_labels_refer_to_existing_call_sites(name):
    # A label for a finding that no longer exists is stale and would silently
    # drop out of the measurement.
    path = CORPUS / "labels" / f"{name}.json"
    if not path.exists():
        return
    labels = json.loads(path.read_text())
    result = json.loads((CORPUS / "results" / f"{name}.json").read_text())
    calls = {f"{f['path']}:{f['line']}:{f['label']}" for f in result["findings"] if f["kind"] == "call site"}
    for key, label in labels["findings"].items():
        assert key in calls, f"stale label: {key}"
        assert label["verdict"] in ("tp", "fp"), key
        assert label.get("note", "").strip() or label["verdict"] == "tp", f"an fp needs a note: {key}"
