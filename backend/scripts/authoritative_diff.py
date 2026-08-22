"""Report every difference between two authoritative-model snapshots."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def load(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def index(rows: list, key: str) -> dict:
    return {row[key]: row for row in rows if row.get(key) is not None}


def compare(label: str, before: dict, after: dict, fields: list) -> None:
    added = sorted(set(after) - set(before))
    removed = sorted(set(before) - set(after))
    changed = []
    for key in sorted(set(before) & set(after)):
        for field in fields:
            if before[key].get(field) != after[key].get(field):
                changed.append((key, field, before[key].get(field), after[key].get(field)))

    if not (added or removed or changed):
        print(f"{label}: identical ({len(before)})")
        return
    print(f"{label}:")
    for key in removed:
        print(f"  - removed {key}: {before[key]}")
    for key in added:
        print(f"  + added   {key}: {after[key]}")
    for key, field, old, new in changed:
        print(f"  ~ {key}.{field}: {old!r} -> {new!r}")


def main() -> None:
    before, after = load(sys.argv[1]), load(sys.argv[2])

    compare(
        "components",
        index(before["components"], "id"),
        index(after["components"], "id"),
        ["name", "type", "trust_level", "security_properties"],
    )
    compare(
        "flows",
        index(before["flows"], "record"),
        index(after["flows"], "record"),
        ["source", "target", "protocol", "data_type"],
    )
    compare(
        "boundaries",
        {row["name"]: row for row in before["trust_boundaries"]},
        {row["name"]: row for row in after["trust_boundaries"]},
        ["type", "components"],
    )
    compare(
        "assets",
        index(before["assets"], "name"),
        index(after["assets"], "name"),
        ["sensitivity", "component"],
    )
    compare(
        "known_issues",
        index(before["known_issues"], "record"),
        index(after["known_issues"], "record"),
        ["threat_id", "hints"],
    )


if __name__ == "__main__":
    main()
