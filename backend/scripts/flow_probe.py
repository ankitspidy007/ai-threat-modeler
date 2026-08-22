"""Show which flows a description states, and which the tool had to guess.

Run after touching flow extraction or the flow templates: the split between
stated and assumed is the measure of how much of the diagram is the analyst's
and how much is the tool's invention.
"""
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.engine.parser import ArchitectureParser  # noqa: E402

SCENARIOS = {
    "healthcare": (
        "A public React web portal calls a Node.js REST API over HTTPS. "
        "The API authenticates staff against Azure AD, stores patient records in "
        "a PostgreSQL database, and uploads scanned documents to an S3 ingestion "
        "bucket. The API also sends results to a laboratory partner. "
        "The portal has no MFA and the ingestion bucket is not encrypted at rest."
    ),
    "ec2_website": (
        "a website with ec2 on backend and s3 bucket for image store and a aws rds db"
    ),
    "fintech": (
        "A React web app and a mobile app call an AWS API Gateway. The gateway "
        "routes to a payments service and an accounts service. The payments "
        "service calls Stripe, stores transactions in PostgreSQL and publishes "
        "events to Kafka. A settlement worker consumes from Kafka and writes "
        "files to an S3 bucket. Auth0 issues tokens."
    ),
}


def main() -> None:
    parser = ArchitectureParser()
    for label, description in SCENARIOS.items():
        architecture = parser.parse(description)
        names = {c.id: c.name for c in architecture.components}
        print(f"\n=== {label} ===")
        print("components:", ", ".join(f"{c.id}({c.type})" for c in architecture.components))
        for flow in architecture.flows:
            origin = flow.properties.get("origin", "?")
            crosses = " crosses-boundary" if flow.properties.get("crosses_trust_boundary") else ""
            print(
                f"  [{origin:8}] {names.get(flow.source_id, flow.source_id)} -> "
                f"{names.get(flow.target_id, flow.target_id)}"
                f" ({flow.protocol or '?'}, {flow.data_type or '?'}){crosses}"
            )
        if not architecture.flows:
            print("  (no flows)")


if __name__ == "__main__":
    main()
