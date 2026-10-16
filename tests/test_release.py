"""Release plumbing: the changelog, the notes extracted from it, and the
places that name the version, which must agree before a tag is pushed."""

import re
import subprocess
import sys

import ratchet
from conftest import REPO_ROOT

sys.path.insert(0, str(REPO_ROOT / "tools"))
import release_notes  # noqa: E402

NOTES = REPO_ROOT / "tools" / "release_notes.py"


def test_changelog_has_a_section_for_this_version():
    # The release workflow refuses a tag without one; this catches it first.
    text = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    notes = release_notes.section(text, ratchet.VERSION)
    assert notes and notes.strip()
    assert f"Registry {ratchet.REGISTRY['registry_version']}." in notes


def test_section_stops_at_the_next_version():
    text = "# Changelog\n\n## 0.2.0\n\nNew.\n\n### Added\n\n- b\n\n## 0.1.0\n\nOld.\n"
    assert release_notes.section(text, "0.2.0") == "New.\n\n### Added\n\n- b\n"
    assert release_notes.section(text, "0.1.0") == "Old.\n"
    assert release_notes.section(text, "0.1") is None
    assert release_notes.section(text, "0.3.0") is None


def test_cli_accepts_the_tag_name():
    r = subprocess.run([sys.executable, str(NOTES), f"v{ratchet.VERSION}"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert r.stdout.startswith("First release.")
    r = subprocess.run([sys.executable, str(NOTES), "v9.9.9"], capture_output=True, text=True)
    assert r.returncode == 1 and r.stdout == ""
    assert "no section for v9.9.9" in r.stderr


def test_readme_names_this_version_of_the_action():
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    versions = set(re.findall(r"uses: gstn458/Ratchet@v([0-9.]+)", readme))
    assert versions == {ratchet.VERSION}


def test_release_workflow_guards_the_tag():
    workflow = (REPO_ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    assert 'tags: ["v*"]' in workflow
    assert 'test "$GITHUB_REF_NAME" = "v$version"' in workflow
    assert "git merge-base --is-ancestor" in workflow
    assert "--draft" in workflow
    # Write access only where the release is made.
    assert workflow.count("contents: write") == 1
