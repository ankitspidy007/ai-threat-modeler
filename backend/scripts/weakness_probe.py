"""Does a weakness stated in prose reach a finding, and does the control agree?"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.engine.parser import ArchitectureParser
from app.engine.analyzer import ThreatAnalyzer

BASE = "A clinician portal calls a records service backed by a ledger database. "

CASES = (
    "The clinician portal has no MFA.",
    "MFA is not enforced on the clinician portal.",
    "The ledger database is not encrypted at rest.",
    "The records service does not authenticate callers.",
)

WATCH = ("mfa_enabled", "encryption_at_rest", "auth_type")


def main() -> None:
    parser = ArchitectureParser()
    analyzer = ThreatAnalyzer()
    for sentence in CASES:
        architecture = parser.parse(BASE + sentence)
        print(f"\n=== {sentence}")
        for component in architecture.components:
            props = component.properties or {}
            watched = {key: props[key] for key in WATCH if key in props and props[key] not in (None, "unknown")}
            weaknesses = [item["rule_id"] for item in props.get("stated_weaknesses") or []]
            if watched or weaknesses:
                print(f"   {component.name:<22} {watched} weaknesses={weaknesses}")
        result = analyzer.analyze(architecture)
        confirmed = [threat for threat in result.threats if (threat.tier or "") == "Confirmed"]
        print(f"   threats={len(result.threats)} confirmed={len(confirmed)}")
        for threat in confirmed[:4]:
            print(f"      ! {threat.severity:<8} {threat.component} :: {threat.title}")
        for threat in result.threats[:3]:
            print(f"      - {threat.tier:<10} {threat.component} :: {threat.title}")


if __name__ == "__main__":
    main()
