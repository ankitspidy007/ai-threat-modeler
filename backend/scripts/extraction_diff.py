"""Compare two extraction snapshots and print what moved."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def load(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def names(entry: dict) -> set:
    return {f"{item['name']} <{item['type']}>" for item in entry["components"]}


def main(before_path: str, after_path: str) -> None:
    before, after = load(before_path), load(after_path)
    for label in sorted(set(before) | set(after)):
        old, new = before.get(label, {}), after.get(label, {})
        if not old or not new:
            print(f"\n== {label}: only in one snapshot ==")
            continue

        gone = names(old) - names(new)
        added = names(new) - names(old)
        flows_gone = set(old["flows"]) - set(new["flows"])
        flows_added = set(new["flows"]) - set(old["flows"])
        if not (gone or added or flows_gone or flows_added):
            print(f"\n== {label}: unchanged "
                  f"({len(new['components'])} components, {len(new['flows'])} flows) ==")
            continue

        print(f"\n== {label}: {len(old['components'])} -> {len(new['components'])} components, "
              f"{len(old['flows'])} -> {len(new['flows'])} flows ==")
        for item in sorted(gone):
            print(f"  - component {item}")
        for item in sorted(added):
            print(f"  + component {item}")
        for item in sorted(flows_gone):
            print(f"  - flow {item}")
        for item in sorted(flows_added):
            print(f"  + flow {item}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
