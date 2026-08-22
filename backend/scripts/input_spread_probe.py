"""How much does each risk input actually vary?

A scoring input that takes the same value on almost every finding adds a constant
and separates nothing, however sensible it looks in the formula. This counts the
observed values per input across the probe scenarios so a near-constant input can
be spotted rather than reasoned about.
"""
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.engine.analyzer import ThreatAnalyzer  # noqa: E402
from scripts.flow_probe import SCENARIOS  # noqa: E402

INPUTS = [
    "exposure",
    "privilege_required",
    "exploit_complexity",
    "crosses_trust_boundary",
    "compensating_controls",
    "asset_sensitivity",
    "broad_reach",
    "reachability",
    "likelihood_points",
    "impact_points",
]


def main() -> None:
    analyzer = ThreatAnalyzer()
    spread = defaultdict(Counter)
    tiers: Counter = Counter()
    total = 0
    for label, description in SCENARIOS.items():
        for threat in analyzer.analyze_from_text(description, project_name=label).threats:
            total += 1
            tiers[threat.tier] += 1
            factors = threat.risk_factors or {}
            for name in INPUTS:
                spread[name][factors.get(name)] += 1

    print(f"{total} findings   tiers={dict(tiers)}\n")
    for name in INPUTS:
        counts = spread[name].most_common()
        top_value, top_count = counts[0]
        share = top_count / total * 100 if total else 0
        flag = "  <-- near constant" if share >= 80 else ""
        rendered = ", ".join(f"{value}={count}" for value, count in counts)
        print(f"{name:24} {rendered}")
        print(f"{'':24} most common {top_value!r} on {share:.0f}% of findings{flag}\n")


if __name__ == "__main__":
    main()
