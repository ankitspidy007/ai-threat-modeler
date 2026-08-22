"""Show the evidence requests a scenario produces, for manual review."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.engine.analyzer import ThreatAnalyzer  # noqa: E402

DESCRIPTION = (
    "The Aurora payments platform serves retail customers. A React web portal and an iOS "
    "mobile app call a FastAPI orchestration service over HTTPS. The orchestration service "
    "calls a payments service, which writes transactions to a PostgreSQL database. Card data "
    "is tokenized by a vault service. Auth0 issues tokens for customers. An internal admin "
    "console reaches the payments service directly. Events are published to a Kafka topic, "
    "and a settlement worker consumes from Kafka and writes reports to an S3 bucket. "
    "Secrets are held in AWS KMS. "
    "Known issues: the JWT signing secret is committed to the repository, and the admin "
    "console has no multi-factor authentication."
)


def main() -> None:
    result = ThreatAnalyzer().analyze_from_text(DESCRIPTION, "Evidence Request Probe")
    coverage = result.stride_coverage or {}
    evidence = result.evidence_requests or {}

    print(f"components={len(result.architecture.components)} flows={len(result.architecture.flows)} findings={len(result.threats)}")
    print(f"applicable cells={coverage.get('applicable_cells')} unresolved={coverage.get('unknown_cells')}")
    print(f"evidence resolution={coverage.get('evidence_resolution_percent')}%")
    print()
    print(evidence.get("summary"))
    print(f"cells addressed by requests: {evidence.get('cells_addressed')} of {evidence.get('unresolved_cells')}"
          f" (unmapped: {evidence.get('cells_without_request')})")
    print()
    for request in evidence.get("requests", []):
        print(f"[{request['priority']:<8}] {request['rank']}. {request['title']}"
              f"  resolves={request['resolves_cells']} score={request['priority_score']}")
        print(f"           Q: {request['question']}")
        for element in request["elements"][:6]:
            print(f"             - {element['label']} [{element['exposure']}]: {', '.join(element['stride_categories'])}")
        if len(request["elements"]) > 6:
            print(f"             - ... {len(request['elements']) - 6} more")
    print()
    print("--- report section ---")
    report = result.report_markdown or ""
    start = report.find("## 8a.")
    end = report.find("## 9.")
    print(report[start:end][:2500] if start >= 0 else "(no evidence request section)")


if __name__ == "__main__":
    main()
