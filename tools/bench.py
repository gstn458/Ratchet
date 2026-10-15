#!/usr/bin/env python3
"""Measure scan speed against the 100,000-file target.

    python3 tools/bench.py [--files 100000] [--backend auto] [--jobs N]

Builds a tree of --files symbolic links to the Python and Go sources in the
corpus checkouts ($RATCHET_CORPUS_DIR, filled by tests/corpus/run.py), 100 to
a directory, cycling through the sources in a fixed order, then times a full
scan of it. The links make a large tree cheap to build; the files they point
to are real code, so parsing and rule matching cost what they would on a
real repository. The operating system caches the files after the first read,
so this measures a warm cache, as on a repeat run.
"""

import argparse
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import ratchet  # noqa: E402


def sources(corpus):
    found = []
    for dirpath, dirnames, filenames in os.walk(corpus):
        dirnames[:] = sorted(d for d in dirnames if not ratchet.skip_reason(d, False))
        found += [os.path.join(dirpath, f) for f in sorted(filenames) if f.endswith((".py", ".go"))]
    return found


def build(tree, corpus, count):
    marker = tree / f".built-{count}"
    if marker.exists():
        return
    files = sources(corpus)
    if not files:
        sys.exit(f"no sources under {corpus}; run tests/corpus/run.py first")
    tree.mkdir(parents=True, exist_ok=True)
    for i in range(count):
        src = files[i % len(files)]
        d = tree / f"d{i // 100:05d}"
        d.mkdir(exist_ok=True)
        link = d / f"f{i % 100:02d}{os.path.splitext(src)[1]}"
        if not link.is_symlink():
            link.symlink_to(src)
    marker.touch()


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--files", type=int, default=100_000)
    p.add_argument("--backend", choices=ratchet.BACKENDS, default="auto")
    p.add_argument("--jobs", type=int, default=None, help="worker processes (default: walk's default)")
    p.add_argument("--tree", type=Path, help="where to build the tree (default: next to the corpus)")
    args = p.parse_args()

    corpus = Path(os.environ.get("RATCHET_CORPUS_DIR", ROOT / "tests" / "corpus" / ".cache"))
    tree = args.tree or corpus.parent / f"bench-tree-{args.files}"
    build(tree, corpus, args.files)

    options = {"backend": args.backend}
    if args.jobs is not None:
        options["jobs"] = args.jobs
    start = time.perf_counter()
    scan = ratchet.walk(str(tree), **options)
    elapsed = time.perf_counter() - start
    print(f"{scan.files} files in {elapsed:.1f}s ({scan.files / elapsed:,.0f} files/s), "
          f"{len(scan.findings)} findings, Go parser: {scan.parsers['Go']}, "
          f"{os.cpu_count()} CPUs")


if __name__ == "__main__":
    main()
