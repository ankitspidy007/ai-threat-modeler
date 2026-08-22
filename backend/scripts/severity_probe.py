"""Severity spread for the healthcare template, to check for inflation."""
import sys
from collections import Counter
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests"))

from app.engine.analyzer import ThreatAnalyzer  # noqa: E402
from test_grounded_threat_modeling import HEALTHCARE_TEMPLATE  # noqa: E402


def main() -> None:
    result = ThreatAnalyzer().analyze_from_text(HEALTHCARE_TEMPLATE, use_local_slm=False)
    print("severity:", dict(Counter(t.severity for t in result.threats)))
    for threat in sorted(result.threats, key=lambda t: -(t.risk_score or 0)):
        factors = threat.risk_factors or {}
        print(
            f"  {threat.severity:9} {threat.risk_score:3} {threat.id:36}"
            f" sens={factors.get('asset_sensitivity'):15} blast={factors.get('blast_radius')}"
            f" boundary={factors.get('crosses_trust_boundary')}"
            f" L={factors.get('likelihood_points')} I={factors.get('impact_points')}"
        )


if __name__ == "__main__":
    main()
