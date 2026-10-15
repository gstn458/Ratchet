#!/usr/bin/env python3
"""The Ratchet GitHub Action: scan, compare with the pull request's base, report.

action.yml runs this with the action's inputs in RATCHET_* environment
variables and the usual GITHUB_* context. It needs Python and git, nothing
else: ratchet.py is run from the action's own checkout.

On a pull request (or merge queue) the base commit is checked out in a git
worktree beside the workspace, scanned the same way, and the two CBOMs are
compared with ratchet diff. The default gate, fail-on: new, fails only when a
file gains unsuppressed quantum-vulnerable call sites, so existing debt does
not block anyone. Without a base, as on a push, the scan is reported and
nothing fails unless fail-on is any.

Exit status: 0 passed or report only, 1 the gate failed, 2 the action could
not do what it was asked (bad input, base commit not fetchable). The step
summary, outputs and SARIF are written before a gate failure, so a later
step can still upload the SARIF.
"""

import html
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ACTION_ROOT = Path(__file__).resolve().parent.parent
RATCHET = ACTION_ROOT / "ratchet.py"
sys.path.insert(0, str(ACTION_ROOT))

import ratchet  # noqa: E402

FAIL_ON = ("new", "any", "none")
MAX_ROWS = 100          # table rows per section in the step summary
MAX_REPORT = 200_000    # characters of the terminal report in the step summary
MAX_ANNOTATIONS = 50    # GitHub shows at most 50 annotations per job


class ActionError(Exception):
    pass


def git(workspace, *args, check=True):
    r = subprocess.run(["git", "-C", str(workspace), *args], capture_output=True, encoding="utf-8",
                       errors="replace")
    if check and r.returncode != 0:
        raise ActionError(f"git {' '.join(args)} failed: {r.stderr.strip()}")
    return r


def flag(name, default="false"):
    value = os.environ.get(name, default).strip().lower()
    if value not in ("true", "false"):
        raise ActionError(f"{name.replace('RATCHET_', '').lower().replace('_', '-')} must be true or false, "
                          f"not {value!r}")
    return value == "true"


def base_commit(event_name, event, override):
    """The commit to compare with, or None to report only."""
    if override:
        return override
    if event_name in ("pull_request", "pull_request_target"):
        return event["pull_request"]["base"]["sha"]
    if event_name == "merge_group":
        return event["merge_group"]["base_sha"]
    return None


def has_commit(workspace, sha):
    return git(workspace, "cat-file", "-e", f"{sha}^{{commit}}", check=False).returncode == 0


def fetch(workspace, *shas, unshallow=False):
    args = ["fetch", "--no-tags", "--quiet"] + (["--unshallow"] if unshallow else ["--depth=1"])
    r = git(workspace, *args, "origin", *shas, check=False)
    if r.returncode != 0:
        raise ActionError(
            f"could not fetch {', '.join(s[:12] for s in shas)} from origin: {r.stderr.strip()}. "
            "Check out with actions/checkout and keep persist-credentials, or use fetch-depth: 0.")


def compare_point(workspace, base):
    """The commit whose scan this checkout is compared with.

    actions/checkout checks out a pull request's merge commit, whose first
    parent is the base, so the base itself is right: the difference is what
    merging adds. When the head is checked out instead, the base branch may
    have moved on since the branch point, so compare with the merge base.
    """
    if has_commit(workspace, base):
        base = git(workspace, "rev-parse", f"{base}^{{commit}}").stdout.strip()
    else:
        fetch(workspace, base)   # a SHA or a branch name on origin
        base = git(workspace, "rev-parse", "FETCH_HEAD^{commit}").stdout.strip()
    head = git(workspace, "rev-parse", "HEAD").stdout.strip()
    raw = git(workspace, "cat-file", "-p", head).stdout
    parents = [line.split()[1] for line in raw.splitlines() if line.startswith("parent ")]
    if head == base or base in parents:
        return base
    r = git(workspace, "merge-base", base, head, check=False)
    if r.returncode != 0 and git(workspace, "rev-parse", "--is-shallow-repository").stdout.strip() == "true":
        fetch(workspace, base, head, unshallow=True)
        r = git(workspace, "merge-base", base, head, check=False)
    if r.returncode != 0:
        raise ActionError(f"no merge base between {base[:12]} and {head[:12]}")
    return r.stdout.strip()


def scan(root, cbom, sarif, include_vendored):
    """Run ratchet.py on root from inside it, so paths are relative to it.
    Returns the terminal report."""
    args = [sys.executable, str(RATCHET), ".", "--cbom", str(cbom)]
    if sarif:
        args += ["--sarif", str(sarif)]
    if include_vendored:
        args.append("--include-vendored")
    # UTF-8 whatever the runner's code page: snippets are the scanned code's own text.
    r = subprocess.run(args, cwd=root, capture_output=True, encoding="utf-8", errors="replace",
                       env={**os.environ, "PYTHONIOENCODING": "utf-8"})
    if r.returncode != 0:
        raise ActionError(f"ratchet failed on {root}: {r.stderr.strip() or r.stdout.strip()}")
    return r.stdout


def vulnerable_count(cbom):
    """What --fail-on-vulnerable counts, read back from a CBOM."""
    _, counts, _, status = ratchet.read_cbom(str(cbom))
    return sum(n for (algorithm, _, kind, suppressed), n in counts.items()
               if kind == ratchet.CALL and not suppressed and status[algorithm][0] == "broken")


def command_escape(text, property_value=False):
    text = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    if property_value:
        text = text.replace(":", "%3A").replace(",", "%2C")
    return text


def annotations(diff, prefix, level):
    """Workflow commands marking each file that gained quantum-vulnerable
    call sites, at every such call site in it: the diff counts per file, so
    it cannot tell which of them is new."""
    out = []
    for c in diff["changes"]:
        if not (c["new"] > c["old"] and c["kind"] == ratchet.CALL and not c["suppressed"]
                and c["quantum_status"] == "broken"):
            continue
        path = (prefix / c["path"]).as_posix()
        message = (f"{c['algorithm']} call sites in this file went from {c['old']} to {c['new']}. "
                   f"{c['algorithm']} is quantum-vulnerable")
        spec = ratchet.ALGORITHMS.get(c["algorithm"])
        message += f"; migrate to: {spec['replacement']}." if spec else "."
        for line in c["new_lines"]:
            out.append(f"::{level} file={command_escape(path, True)},line={line},"
                       f"title={command_escape('Ratchet: new ' + c['algorithm'] + ' call site', True)}::"
                       f"{command_escape(message)}")
    return out[:MAX_ANNOTATIONS]


def cell(text):
    # A | ends a table cell even inside <code>.
    return f"<code>{html.escape(str(text)).replace('|', '&#124;')}</code>"


def table(changes):
    rows = ["| Algorithm | Kind | File | Before | After | Lines |", "| --- | --- | --- | ---: | ---: | --- |"]
    for c in changes[:MAX_ROWS]:
        lines = c["new_lines"] or c["old_lines"]
        where = ("now " if c["new_lines"] else "was ") + ", ".join(map(str, lines[:20]))
        if len(lines) > 20:
            where += f", ... {len(lines) - 20} more"
        rows.append(f"| {html.escape(c['algorithm'])} | {c['kind']} | {cell(c['path'])} | {c['old']} | {c['new']} "
                    f"| {where} |")
    if len(changes) > MAX_ROWS:
        rows.append(f"\n{len(changes) - MAX_ROWS} more rows; the full comparison is the diff output.")
    return "\n".join(rows)


def summary(result):
    """The step summary, in Markdown."""
    out = ["## Ratchet", ""]
    diff = result["diff"]
    if result["failed"]:
        if result["fail_on"] == "new":
            out.append(f"**Failed:** {ratchet.plural(diff['new_quantum_vulnerable_call_sites'], 'new quantum-vulnerable call site')} "
                       "(counted file by file, unsuppressed).")
        else:
            out.append(f"**Failed:** {ratchet.plural(result['vulnerable'], 'quantum-vulnerable call site')} "
                       "(unsuppressed). The gate is fail-on: any.")
    elif diff is not None:
        more = diff["new_quantum_vulnerable_call_sites"]
        out.append(f"**{'Passed' if result['fail_on'] != 'none' else 'Report only'}:** "
                   f"{ratchet.plural(more, 'new quantum-vulnerable call site')}.")
    elif result["fail_on"] == "any":
        out.append("**Passed:** no unsuppressed quantum-vulnerable call sites.")
    else:
        out.append("**Report only:** no base commit to compare with on this event.")
    out.append("")
    scanned = cell(result["path"])
    if diff is not None:
        out.append(f"Compared {scanned} at {cell(result['base'][:12])} (base) with this checkout "
                   f"({cell(result['head'][:12])}).")
        out += ["", "| | Base | This change |", "| --- | ---: | ---: |",
                f"| Quantum-vulnerable call sites | {diff['quantum_vulnerable_call_sites']['old']} "
                f"| {diff['quantum_vulnerable_call_sites']['new']} |", ""]
        for w in diff["warnings"]:
            out.append(f"> **Warning:** {html.escape(w)}")
        if diff["warnings"]:
            out.append("")
        active = [c for c in diff["changes"] if not c["suppressed"]]
        sections = [("More", [c for c in active if c["new"] > c["old"]]),
                    ("Fewer", [c for c in active if c["new"] < c["old"]]),
                    ("Suppressed, changed (not counted by the gate)", [c for c in diff["changes"] if c["suppressed"]])]
        for title, changes in sections:
            if changes:
                out += [f"### {title}", "", table(changes), ""]
        if not diff["changes"]:
            out += ["No cryptography was added or removed.", ""]
    else:
        out += [f"Scanned {scanned} at {cell(result['head'][:12])}: "
                f"{ratchet.plural(result['vulnerable'], 'unsuppressed quantum-vulnerable call site')}.", ""]
    report = result["report"]
    if len(report) > MAX_REPORT:
        report = report[:MAX_REPORT] + "\n... cut short; the CBOM output has everything.\n"
    out += ["<details><summary>Full report</summary>", "", f"<pre>{html.escape(report.strip())}</pre>", "",
            "</details>", ""]
    return "\n".join(out)


def write_outputs(path, values):
    if not path:
        return
    with open(path, "a", encoding="utf-8") as fh:
        for key, value in values.items():
            fh.write(f"{key}={value}\n")


def run(env):
    workspace = Path(env.get("GITHUB_WORKSPACE") or os.getcwd()).resolve()
    rel = env.get("RATCHET_PATH", ".").strip() or "."
    root = (workspace / rel).resolve()
    if not root.is_dir():
        raise ActionError(f"path {rel!r} is not a directory in the workspace")
    fail_on = env.get("RATCHET_FAIL_ON", "new").strip().lower()
    if fail_on not in FAIL_ON:
        raise ActionError(f"fail-on must be one of {', '.join(FAIL_ON)}, not {fail_on!r}")
    include_vendored = flag("RATCHET_INCLUDE_VENDORED")

    out = Path(env.get("RUNNER_TEMP") or tempfile.mkdtemp()) / "ratchet"
    out.mkdir(parents=True, exist_ok=True)
    head_cbom, sarif = out / "cbom.json", out / "ratchet.sarif"
    report = scan(root, head_cbom, sarif, include_vendored)
    head = git(workspace, "rev-parse", "HEAD").stdout.strip()

    event = {}
    if env.get("GITHUB_EVENT_PATH") and os.path.exists(env["GITHUB_EVENT_PATH"]):
        with open(env["GITHUB_EVENT_PATH"], encoding="utf-8") as fh:
            event = json.load(fh)
    base = base_commit(env.get("GITHUB_EVENT_NAME", ""), event, env.get("RATCHET_BASE", "").strip())

    diff, base_cbom, diff_file = None, None, None
    if base:
        base = compare_point(workspace, base)
        tree = out / "base"
        git(workspace, "worktree", "remove", "--force", str(tree), check=False)
        git(workspace, "worktree", "add", "--quiet", "--detach", str(tree), base)
        try:
            base_root = tree / root.relative_to(workspace)
            if not base_root.is_dir():
                base_root = out / "empty"   # the directory is new in this change
                base_root.mkdir(exist_ok=True)
            base_cbom = out / "base.cbom.json"
            scan(base_root, base_cbom, None, include_vendored)
        finally:
            git(workspace, "worktree", "remove", "--force", str(tree), check=False)
        diff = ratchet.diff_cboms(str(base_cbom), str(head_cbom))
        diff_file = out / "diff.json"
        diff_file.write_text(json.dumps(diff, indent=2) + "\n", encoding="utf-8")

    vulnerable = vulnerable_count(head_cbom)
    if fail_on == "new":
        failed = diff is not None and diff["new_quantum_vulnerable_call_sites"] > 0
    elif fail_on == "any":
        failed = vulnerable > 0
    else:
        failed = False

    result = {"path": rel, "fail_on": fail_on, "failed": failed, "diff": diff, "base": base, "head": head,
              "vulnerable": vulnerable, "report": report}
    if diff is not None:
        level = "error" if fail_on == "new" else "warning"
        for line in annotations(diff, root.relative_to(workspace), level):
            print(line)
    write_outputs(env.get("GITHUB_OUTPUT"), {
        "cbom": head_cbom, "sarif": sarif, "base-cbom": base_cbom or "", "diff": diff_file or "",
        "vulnerable": vulnerable,
        "new-vulnerable": "" if diff is None else diff["new_quantum_vulnerable_call_sites"],
        "failed": str(failed).lower(),
    })
    text = summary(result)
    if env.get("GITHUB_STEP_SUMMARY"):
        with open(env["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as fh:
            fh.write(text + "\n")
    print(report)
    return result


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    try:
        result = run(os.environ)
    except (ActionError, ratchet.CbomError) as e:
        print(f"::error title=Ratchet::{command_escape(str(e))}")
        return 2
    return 1 if result["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
