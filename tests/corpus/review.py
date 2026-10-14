#!/usr/bin/env python3
"""Write REVIEW.md: every false positive, and a random 10% of true positives.

    python3 tests/corpus/review.py

The sample is drawn with a fixed seed from the committed results and labels,
so the same labels always give the same sheet. Run it after run.py.
"""

import json
import random
from pathlib import Path

HERE = Path(__file__).resolve().parent
SEED = 20261014


def rows():
    out = []
    for path in sorted((HERE / "results").glob("*.json")):
        result = json.loads(path.read_text())
        name = result["name"]
        labels = json.loads((HERE / "labels" / f"{name}.json").read_text())["findings"]
        seen = set()
        for f in result["findings"]:
            if f["kind"] != "call site":
                continue
            key = f"{f['path']}:{f['line']}:{f['label']}"
            if key in seen:
                continue
            seen.add(key)
            out.append((name, key, f["snippet"], labels[key]))
    return out


def section(title, items):
    out = [f"## {title}", ""]
    for name, key, snippet, label in items:
        out += [f"- **{name}** `{key}`", f"  `{snippet[:140]}`", f"  {label['verdict']}: {label['note']}"]
    return out + [""]


def main():
    all_rows = rows()
    fps = [r for r in all_rows if r[3]["verdict"] == "fp"]
    tps = [r for r in all_rows if r[3]["verdict"] == "tp"]
    random.seed(SEED)
    sample = sorted(random.sample(tps, round(len(tps) * 0.1)))
    lines = ["# Label review sheet", "",
             f"Every false positive, and a random 10% of true positives (seed {SEED},",
             "regenerated from the committed labels by `review.py`). Change a verdict in",
             "`labels/<name>.json` and say why in the commit message.", ""]
    lines += section(f"False positives ({len(fps)})", fps)
    lines += section(f"True positives, random sample ({len(sample)} of {len(tps)})", sample)
    (HERE / "REVIEW.md").write_text("\n".join(lines))
    print(f"{len(fps)} false positives, {len(sample)} of {len(tps)} true positives sampled")


if __name__ == "__main__":
    main()
