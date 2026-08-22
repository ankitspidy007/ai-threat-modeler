"""Show the risk inputs the graph now supplies, per scenario.

Blast radius, boundary crossing and data classification used to be answered from
a single finding's own fields; this prints what the graph says instead, so a
change to either can be seen rather than assumed.
"""
import sys
from collections import Counter
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.engine.analyzer import ThreatAnalyzer  # noqa: E402
from scripts.flow_probe import SCENARIOS  # noqa: E402


def main() -> None:
    analyzer = ThreatAnalyzer()
    for label, description in SCENARIOS.items():
        result = analyzer.analyze_from_text(description, project_name=label)
        threats = result.threats
        print(f"\n=== {label} ===  {len(threats)} findings")
        classified = {
            c.id: (
                (c.properties or {}).get("data_sensitivity"),
                (c.properties or {}).get("data_sensitivity_basis"),
            )
            for c in result.architecture.components
        }
        for cid, (value, basis) in sorted(classified.items()):
            if value:
                print(f"  data: {cid} = {value} ({basis})")
        print("  severity:", dict(Counter(t.severity for t in threats)))
        factors = [t.risk_factors or {} for t in threats]
        print("  blast radius:", dict(Counter(f.get("blast_radius") for f in factors)))
        print("  on a boundary:", dict(Counter(bool(f.get("crosses_trust_boundary")) for f in factors)))
        print("  sensitivity used:", dict(Counter(f.get("asset_sensitivity") for f in factors)))
        paths = [t.attack_path for t in threats if t.attack_path]
        print(f"  attack paths: {len(paths)}", dict(Counter(p.get("path_status") for p in paths)))
        print("  path hops:", dict(Counter(len(p.get("hops") or []) for p in paths)))


if __name__ == "__main__":
    main()
