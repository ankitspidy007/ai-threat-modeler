"""Empirical check of the aggregate Security score (result.score).

The dashboard shows score/100 as a headline metric, but it is computed separately
from per-finding technical-v3 risk_score. This probe prints score, finding count,
severity/tier spread, and the implied deduction so sparse or weakly-described
inputs can be compared against richer scenarios.
"""
import sys
from collections import Counter
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.engine.analyzer import ThreatAnalyzer  # noqa: E402
from scripts.flow_probe import SCENARIOS  # noqa: E402

ORDER = ["Critical", "High", "Medium", "Low"]


def implied_deduction(threats) -> float:
    total = 0.0
    for threat in threats:
        weight = 1.0 if threat.tier == "Confirmed" else 0.6
        total += ((threat.risk_score or 0) / 10) * weight
    return total


def run_case(analyzer: ThreatAnalyzer, label: str, description: str) -> None:
    result = analyzer.analyze_from_text(description, project_name=label)
    threats = result.threats
    sev = Counter(t.severity for t in threats)
    tier = Counter(t.tier for t in threats)
    ded = implied_deduction(threats)
    gate = ((result.engine_status or {}).get("quality_gate") or {}).get("publication_status", "?")
    stride = result.stride_coverage or {}
    unresolved = stride.get("unresolved_cells") or stride.get("unresolved") or "?"
    print(f"\n=== {label} ===")
    print(f"  score={result.score}/100  findings={len(threats)}  implied_deduction={ded:.1f}")
    print(f"  severity: {' '.join(f'{s}={sev.get(s, 0)}' for s in ORDER)}")
    print(f"  tier: Confirmed={tier.get('Confirmed', 0)} Potential={tier.get('Potential', 0)}")
    print(f"  publication_status={gate}  stride_unresolved={unresolved}")
    if threats:
        avg_risk = sum(t.risk_score or 0 for t in threats) / len(threats)
        print(f"  avg risk_score={avg_risk:.1f}  min={min(t.risk_score or 0 for t in threats)} max={max(t.risk_score or 0 for t in threats)}")


def main() -> None:
    analyzer = ThreatAnalyzer()

    extra = {
        "sparse_one_liner": "a website with a database",
        "vague_no_controls": (
            "We have a web application that stores user data. "
            "Users log in and upload files. There is a backend service."
        ),
        "explicit_bad": (
            "A public website with no authentication, no encryption, no MFA, "
            "and a publicly accessible database containing customer passwords in plain text."
        ),
        "explicit_good": (
            "A public React portal behind Cloudflare WAF. Users authenticate via "
            "Auth0 with mandatory MFA. All traffic is TLS 1.3. Data at rest is "
            "AES-256 encrypted in PostgreSQL with column-level encryption for PII. "
            "Secrets are in AWS Secrets Manager. Admin access requires hardware keys."
        ),
    }

    for label, description in extra.items():
        run_case(analyzer, label, description)

    for label, description in SCENARIOS.items():
        run_case(analyzer, label, description)


if __name__ == "__main__":
    main()
