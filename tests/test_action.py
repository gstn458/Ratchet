"""The GitHub Action's driver, action/run.py, against real git repositories.

Each test builds an origin repository and a shallow clone of it, the way
actions/checkout leaves the workspace, writes a GitHub event file, and runs
the driver with the environment a runner would give it.
"""

import json
import os
import re
import subprocess
import sys

import pytest

from conftest import REPO_ROOT

RUN = REPO_ROOT / "action" / "run.py"
RSA = "from cryptography.hazmat.primitives.asymmetric import rsa\n"
GEN = "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
GIT_ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@example.com", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}


def git(cwd, *args):
    r = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, env={**os.environ, **GIT_ENV})
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


class Origin:
    """A repository standing in for GitHub, which serves any commit by SHA."""

    def __init__(self, path):
        self.path = path
        path.mkdir()
        git(path, "init", "-q", "-b", "main")
        git(path, "config", "uploadpack.allowAnySHA1InWant", "true")

    def commit(self, files, message="change"):
        for name, text in files.items():
            target = self.path / name
            if text is None:
                target.unlink()
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
        git(self.path, "add", "-A")
        git(self.path, "commit", "-q", "--allow-empty", "-m", message)
        return git(self.path, "rev-parse", "HEAD")

    def checkout(self, ref):
        git(self.path, "checkout", "-q", ref)

    def clone(self, dest, sha):
        """A depth-1 checkout of sha, as actions/checkout makes by default."""
        git(self.path, "update-ref", "refs/ci/checkout", sha)
        git(dest.parent, "clone", "-q", "--depth=1", "--no-single-branch", f"file://{self.path}", dest.name)
        git(dest, "fetch", "-q", "--depth=1", "origin", sha)
        git(dest, "checkout", "-q", "--detach", sha)
        return dest


def run(workspace, tmp_path, event_name="pull_request", pr_base=None, env=None, **inputs):
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"pull_request": {"base": {"sha": pr_base}}} if pr_base else {}))
    runner = tmp_path / "runner"
    runner.mkdir(exist_ok=True)
    output, step_summary = runner / "output", runner / "summary"
    extra, env = env or {}, {**os.environ, **GIT_ENV, "GITHUB_WORKSPACE": str(workspace), "GITHUB_EVENT_NAME": event_name,
           "GITHUB_EVENT_PATH": str(event), "GITHUB_OUTPUT": str(output), "GITHUB_STEP_SUMMARY": str(step_summary),
           "RUNNER_TEMP": str(runner)}
    env.update({f"RATCHET_{k.upper()}": v for k, v in inputs.items()}, **extra)
    r = subprocess.run([sys.executable, str(RUN)], cwd=workspace, capture_output=True, encoding="utf-8", env=env)
    outputs = (dict(line.split("=", 1) for line in output.read_text(encoding="utf-8").splitlines())
               if output.exists() else {})
    text = step_summary.read_text(encoding="utf-8") if step_summary.exists() else ""
    return r, outputs, text


@pytest.fixture
def origin(tmp_path):
    return Origin(tmp_path / "origin")


def pull_request(origin, base_files, head_files):
    """Base and head commits and the merge commit GitHub makes for the pull
    request. Returns (base, head, merge) SHAs."""
    base = origin.commit(base_files, "base")
    git(origin.path, "checkout", "-q", "-b", "feature")
    head = origin.commit(head_files, "feature")
    origin.checkout("main")
    git(origin.path, "merge", "-q", "--no-ff", "--no-commit", "feature")
    git(origin.path, "commit", "-q", "-m", "merge")
    merge = git(origin.path, "rev-parse", "HEAD")
    git(origin.path, "reset", "-q", "--hard", base)
    return base, head, merge


def test_new_call_site_fails_the_pull_request(origin, tmp_path):
    base, _, merge = pull_request(origin, {"app/keys.py": RSA + GEN}, {"app/keys.py": RSA + GEN + GEN})
    workspace = origin.clone(tmp_path / "ws", merge)
    r, outputs, text = run(workspace, tmp_path, pr_base=base)
    assert r.returncode == 1, r.stderr
    assert outputs["failed"] == "true"
    assert outputs["new-vulnerable"] == "1"
    assert outputs["vulnerable"] == "2"
    assert "**Failed:** 1 new quantum-vulnerable call site" in text
    assert "| RSA | call site | <code>app/keys.py</code> | 1 | 2 | now 2, 3 |" in text
    assert "::error file=app/keys.py,line=2,title=Ratchet%3A new RSA call site::" in r.stdout
    for name in ("cbom", "sarif", "base-cbom", "diff"):
        assert os.path.exists(outputs[name]), name
    # The base worktree is gone again.
    assert git(workspace, "worktree", "list").count("\n") == 0


def test_existing_call_sites_do_not_fail(origin, tmp_path):
    base, _, merge = pull_request(origin, {"keys.py": RSA + GEN}, {"keys.py": "# moved\n\n" + RSA + GEN,
                                                                      "notes.txt": "x\n"})
    workspace = origin.clone(tmp_path / "ws", merge)
    r, outputs, text = run(workspace, tmp_path, pr_base=base)
    assert r.returncode == 0, r.stdout + r.stderr
    assert outputs["failed"] == "false"
    assert outputs["new-vulnerable"] == "0"
    assert "**Passed:** no new quantum-vulnerable call sites." in text
    assert "No cryptography was added or removed." in text
    assert "::error" not in r.stdout


def test_head_checkout_compares_with_the_merge_base(origin, tmp_path):
    # The base branch dropped RSA after the pull request branched. Compared
    # with the base tip, the untouched file would read as new RSA.
    fork = origin.commit({"keys.py": RSA + GEN, "other.py": "x = 1\n"}, "fork point")
    git(origin.path, "checkout", "-q", "-b", "feature")
    head = origin.commit({"other.py": "x = 2\n"}, "feature")
    origin.checkout("main")
    base = origin.commit({"keys.py": "x = 0\n"}, "migrate off RSA")
    workspace = origin.clone(tmp_path / "ws", head)
    r, outputs, text = run(workspace, tmp_path, pr_base=base)
    assert r.returncode == 0, r.stdout + r.stderr
    assert outputs["new-vulnerable"] == "0"
    assert fork[:12] in text


def test_push_reports_only(origin, tmp_path):
    sha = origin.commit({"keys.py": RSA + GEN})
    workspace = origin.clone(tmp_path / "ws", sha)
    r, outputs, text = run(workspace, tmp_path, event_name="push")
    assert r.returncode == 0, r.stderr
    assert outputs["new-vulnerable"] == "" and outputs["base-cbom"] == ""
    assert outputs["vulnerable"] == "1"
    assert "**Report only:** no base commit to compare with on this event." in text
    r, outputs, text = run(workspace, tmp_path, event_name="push", fail_on="any")
    assert r.returncode == 1
    assert "**Failed:** 1 quantum-vulnerable call site (unsuppressed)." in text


def test_fail_on_none_never_fails(origin, tmp_path):
    base, _, merge = pull_request(origin, {"a.py": "x = 1\n"}, {"a.py": RSA + GEN})
    workspace = origin.clone(tmp_path / "ws", merge)
    r, outputs, text = run(workspace, tmp_path, pr_base=base, fail_on="none")
    assert r.returncode == 0
    assert outputs["new-vulnerable"] == "1" and outputs["failed"] == "false"
    assert "::warning file=a.py,line=2" in r.stdout


def test_path_new_in_the_change_compares_with_nothing(origin, tmp_path):
    base, _, merge = pull_request(origin, {"README": "x\n"}, {"svc/keys.py": RSA + GEN})
    workspace = origin.clone(tmp_path / "ws", merge)
    r, outputs, _ = run(workspace, tmp_path, pr_base=base, path="svc")
    assert r.returncode == 1
    assert outputs["new-vulnerable"] == "1"
    # Annotations name the file from the workspace root, not the scan root.
    assert "::error file=svc/keys.py,line=2," in r.stdout


def test_base_branch_name_is_accepted(origin, tmp_path):
    origin.commit({"keys.py": RSA + GEN})
    git(origin.path, "checkout", "-q", "-b", "feature")
    head = origin.commit({"keys.py": RSA + GEN + GEN})
    workspace = origin.clone(tmp_path / "ws", head)
    r, outputs, _ = run(workspace, tmp_path, event_name="workflow_dispatch", base="main")
    assert r.returncode == 1, r.stdout + r.stderr
    assert outputs["new-vulnerable"] == "1"


@pytest.mark.parametrize("inputs, message", [
    ({"fail_on": "sometimes"}, "fail-on must be one of new, any, none"),
    ({"path": "missing"}, "is not a directory"),
    ({"include_vendored": "yes"}, "include-vendored must be true or false"),
    ({"base": "0" * 40}, "could not fetch 000000000000"),
])
def test_bad_input_exits_2(origin, tmp_path, inputs, message):
    sha = origin.commit({"keys.py": RSA + GEN})
    workspace = origin.clone(tmp_path / "ws", sha)
    r, _, _ = run(workspace, tmp_path, event_name="push", **inputs)
    assert r.returncode == 2
    assert r.stdout.startswith("::error title=Ratchet::")
    assert message in r.stdout


def test_summary_escapes_paths(origin, tmp_path):
    base, _, merge = pull_request(origin, {"a.py": "x = 1\n"}, {"<b>|x.py": RSA + GEN})
    workspace = origin.clone(tmp_path / "ws", merge)
    _, _, text = run(workspace, tmp_path, pr_base=base)
    assert "<code>&lt;b&gt;&#124;x.py</code>" in text
    assert "<b>" not in text


def test_command_escape():
    sys.path.insert(0, str(RUN.parent))
    import run as action
    assert action.command_escape("a%b\nc:d,e") == "a%25b%0Ac:d,e"
    assert action.command_escape("a%b\nc:d,e", property_value=True) == "a%25b%0Ac%3Ad%2Ce"


def test_action_yml_matches_the_driver():
    # Every input the driver reads is passed by action.yml, and every input
    # action.yml refers to is declared.
    spec = (REPO_ROOT / "action.yml").read_text()
    driver = RUN.read_text()
    declared = set(re.findall(r"^  ([a-z][a-z-]*):\n    description:", spec.split("\noutputs:")[0], re.M))
    used = set(re.findall(r"inputs\.([a-z-]+)", spec))
    assert used <= declared
    assert declared == {"path", "fail-on", "base", "tree-sitter", "include-vendored", "upload-sarif",
                        "sarif-category", "python-version"}
    passed = set(re.findall(r"^\s+(RATCHET_[A-Z_]+):", spec, re.M)) - {"RATCHET_PYTHON"}
    read = set(re.findall(r'"(RATCHET_[A-Z_]+)"', driver))
    assert passed == read
    # Third-party actions are pinned to a full commit.
    for ref in re.findall(r"uses: (\S+)", spec):
        assert re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", ref), ref


def test_non_ascii_code_is_reported(origin, tmp_path):
    sha = origin.commit({"clé.py": "# Schlüssel für Zürich\n" + RSA + GEN})
    workspace = origin.clone(tmp_path / "ws", sha)
    r, outputs, text = run(workspace, tmp_path, event_name="push",
                           env={"PYTHONIOENCODING": "ascii", "LC_ALL": "C"})
    assert r.returncode == 0, r.stdout + r.stderr
    assert outputs["vulnerable"] == "1"
    assert "clé.py" in text
