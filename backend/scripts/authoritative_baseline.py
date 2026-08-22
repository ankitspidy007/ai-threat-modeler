"""Dump the parsed authoritative model as a stable, diffable snapshot.

Used to compare the ID-indexed parser against the content-derived one. Any
difference in this output is a behaviour change that has to be justified.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from app.engine.parser import ArchitectureParser  # noqa: E402

FIXTURE = BACKEND / "tests" / "fixtures" / "reference_architecture.txt"


def snapshot(text: str) -> dict:
    architecture = ArchitectureParser().parse(text)
    return {
        "components": [
            {
                "id": component.id,
                "name": component.name,
                "type": component.type,
                "trust_level": component.trust_level,
                "security_properties": {
                    key: value
                    for key, value in sorted(component.properties.items())
                    if isinstance(value, bool)
                },
            }
            for component in sorted(architecture.components, key=lambda item: item.id)
        ],
        "flows": [
            {
                "record": flow.properties.get("source_record_id"),
                "route": flow.properties.get("route"),
                "source": flow.source_id,
                "target": flow.target_id,
                "protocol": flow.protocol,
                "data_type": flow.data_type,
                "crosses_boundary": flow.properties.get("crosses_trust_boundary"),
            }
            for flow in sorted(
                architecture.flows,
                key=lambda item: int(
                    str(item.properties.get("source_record_id", "F0")).lstrip("F") or 0
                ),
            )
        ],
        "trust_boundaries": [
            {
                "name": boundary.name,
                "type": boundary.boundary_type,
                "components": sorted(boundary.components),
            }
            for boundary in architecture.trust_boundaries
        ],
        "assets": [
            {
                "name": asset.name,
                "sensitivity": asset.sensitivity,
                "location": asset.location,
                "component": asset.related_component_id,
            }
            for asset in architecture.assets
        ],
        "known_issues": [
            {
                "record": issue.get("source_record_id"),
                "threat_id": issue.get("suggested_threat_id"),
                "hints": issue.get("component_hints"),
            }
            for issue in architecture.metadata.get("known_issues", [])
        ],
        "actors": architecture.metadata.get("actors", []),
        "record_counts": architecture.metadata.get("authoritative_record_counts"),
    }


def main() -> None:
    output = Path(sys.argv[1]) if len(sys.argv) > 1 else BACKEND / "baseline.json"
    result = snapshot(FIXTURE.read_text(encoding="utf-8"))
    output.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")

    print(f"components       : {len(result['components'])}")
    print(f"flows            : {len(result['flows'])}")
    print(f"trust boundaries : {len(result['trust_boundaries'])}")
    print(f"assets           : {len(result['assets'])}")
    print(f"known issues     : {len(result['known_issues'])}")
    print(f"actors           : {len(result['actors'])}")
    print(f"written to       : {output}")


if __name__ == "__main__":
    main()
