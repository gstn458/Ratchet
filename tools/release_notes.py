#!/usr/bin/env python3
"""Print the CHANGELOG.md section for a version, for a release's notes.

    python3 tools/release_notes.py 0.1.0

Exits 1, printing nothing, when the changelog has no section for the version.
"""

import re
import sys
from pathlib import Path

CHANGELOG = Path(__file__).resolve().parent.parent / "CHANGELOG.md"


def section(text, version):
    """The body under '## <version>', up to the next '## ' heading, or None."""
    match = re.search(rf"^## {re.escape(version)}[ \t]*\n(.*?)(?=^## |\Z)", text, re.M | re.S)
    return match.group(1).strip() + "\n" if match else None


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__.strip().splitlines()[2].strip())
    notes = section(CHANGELOG.read_text(encoding="utf-8"), sys.argv[1].lstrip("v"))
    if notes is None:
        print(f"CHANGELOG.md has no section for {sys.argv[1]}", file=sys.stderr)
        return 1
    sys.stdout.write(notes)
    return 0


if __name__ == "__main__":
    sys.exit(main())
