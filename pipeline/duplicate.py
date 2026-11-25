"""Check whether a same-day successful run repeats a release."""

import sys
from pathlib import Path

from .sources import read_json


def state(site):
    root = site / "api/v1"
    pointer = read_json(root / "latest.json")
    release = root / "releases" / pointer["release_id"]
    report = read_json(release / "report.json")
    changes = read_json(release / "changes.json")
    return pointer["window"],pointer["source_commit"],[
        (r["id"],r["state"],r["coverage"],r.get("snapshot"),r.get("count")) for r in report["sources"]
    ], changes["count"], report["quarantined"]


if __name__ == "__main__":
    before = state(Path(sys.argv[1]))
    after = state(Path(sys.argv[2]))
    sys.exit(0 if before[:3] == after[:3] and not after[3] and before[4] == after[4] else 1)
