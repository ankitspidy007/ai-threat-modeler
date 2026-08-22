"""Severity spread across every probe scenario, with the points behind it.

Severity is the one number a reader acts on, so a change to the risk model has to
be visible as a distribution rather than argued from the code. This prints the
spread per scenario and the likelihood and impact points that produced it, so a
recalibration can be compared against a run taken before the change.
"""
import sys
from collections import Counter
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.engine.analyzer import ThreatAnalyzer  # noqa: E402
from scripts.flow_probe import SCENARIOS  # noqa: E402

ORDER = ["Critical", "High", "Medium", "Low"]


def main() -> None:
    analyzer = ThreatAnalyzer()
    overall: Counter = Counter()
    for label, description in SCENARIOS.items():
        threats = analyzer.analyze_from_text(description, project_name=label).threats
        spread = Counter(t.severity for t in threats)
        overall.update(spread)
        counts = " ".join(f"{name}={spread.get(name, 0):3}" for name in ORDER)
        print(f"\n=== {label} ===  {len(threats):3} findings   {counts}")
        for threat in sorted(threats, key=lambda t: -(t.risk_score or 0))[:8]:
            factors = threat.risk_factors or {}
            print(
                f"  {threat.severity:9} score={threat.risk_score:3} {threat.id:34}"
                f" L={factors.get('likelihood_points')}"
                f" I={factors.get('impact_points')}"
                f" exp={factors.get('exposure'):9}"
                f" cx={factors.get('exploit_complexity'):7}"
                f" priv={factors.get('privilege_required'):7}"
                f" conf={factors.get('evidence_confidence')}"
            )

    total = sum(overall.values())
    print(f"\n=== all scenarios ===  {total} findings")
    for name in ORDER:
        count = overall.get(name, 0)
        share = (count / total * 100) if total else 0
        print(f"  {name:9} {count:4}  {share:5.1f}%")


if __name__ == "__main__":
    main()
