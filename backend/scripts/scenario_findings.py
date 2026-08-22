"""What does each probe scenario actually confirm, and on which component?"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.engine.analyzer import ThreatAnalyzer
from scenario_probe import SCENARIOS, STRUCTURED


def main() -> None:
    cases = dict(SCENARIOS)
    cases["structured_orders"] = STRUCTURED
    only = sys.argv[1] if len(sys.argv) > 1 else None
    analyzer = ThreatAnalyzer()
    for name, description in cases.items():
        if only and only != name:
            continue
        result = analyzer.analyze_from_text(description, project_name=name, use_local_slm=False)
        tiers = {}
        for threat in result.threats:
            tiers[threat.tier] = tiers.get(threat.tier, 0) + 1
        print(f"\n{'=' * 78}")
        print(f"{name}  score={result.score} components={len(result.architecture.components)} "
              f"flows={len(result.architecture.flows)} threats={len(result.threats)} tiers={tiers}")
        for component in result.architecture.components:
            props = component.properties or {}
            denied = sorted(props.get('explicit_negations') or [])
            weaknesses = [item['rule_id'] for item in props.get('stated_weaknesses') or []]
            if denied or weaknesses:
                print(f"   {component.name[:26]:<26} denied={denied} weaknesses={weaknesses}")
        print("   confirmed findings:")
        for threat in result.threats:
            if threat.tier == "Confirmed":
                print(f"      - {threat.severity:<8} {threat.component_id:<24} {threat.title[:64]}")


if __name__ == "__main__":
    main()
