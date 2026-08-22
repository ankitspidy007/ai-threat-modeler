"""Dump what the parser extracts from a set of descriptions, as a stable snapshot.

Consolidating duplicate components changes the model for every prose input, so
the change has to be judged by what it does across a corpus rather than on the
one example that motivated it. Run this before and after, and diff.

    python scripts/extraction_baseline.py before.json
    python scripts/extraction_baseline.py after.json
    python scripts/extraction_diff.py before.json after.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from app.engine.parser import ArchitectureParser  # noqa: E402

CORPUS: dict[str, str] = {
    "payments_prose": """
A React portal calls an AWS API Gateway which routes to a Spring Boot payments
service backed by an Aurora PostgreSQL database and an S3 receipts bucket.
""",
    "payments_detailed": """
The Aurora payments platform serves retail customers. A React web portal and an
iOS mobile app call an AWS API Gateway over HTTPS. The gateway validates tokens
with AWS Cognito and routes payment requests to a Java Spring Boot payments
service. The payments service writes the transaction ledger to an Aurora
PostgreSQL database and stores receipts in S3. MFA is enforced at the identity
service, a WAF protects the edge, and data is encrypted at rest and in transit.
""",
    "microservice_list": """
Our platform runs on Kubernetes with the following services:
1. User Service (Node.js + Express): Handles authentication and profile data.
2. Payment Service (Java Spring Boot): Processes card payments via Stripe.
3. Notification Service (Python): Sends email through SendGrid.

Data is stored in a PostgreSQL cluster with read replicas and cached in Redis.
An NGINX ingress terminates TLS at the edge.
""",
    "ai_rag": """
A customer support assistant uses an Azure OpenAI model with a RAG pipeline over
a Pinecone vector store. A Python orchestrator retrieves documents from S3,
builds prompts, and calls the model. Responses are logged to Elasticsearch.
Users authenticate with Entra ID before reaching the Flask API.
""",
    "healthcare": """
Clinicians use a web portal to view patient records. The portal calls a FHIR API
gateway which reads from a MongoDB clinical document store. A Kafka event bus
carries admission events to a reporting service that writes to Snowflake.
PHI is encrypted at rest. There is no MFA on the clinician portal.
""",
}

FIXTURE = BACKEND / "tests" / "fixtures" / "reference_architecture.txt"
if FIXTURE.exists():
    CORPUS["structured_reference"] = FIXTURE.read_text(encoding="utf-8")


def snapshot() -> dict:
    parser = ArchitectureParser()
    out: dict = {}
    for label, text in CORPUS.items():
        architecture = parser.parse(text)
        names = {component.id: component.name for component in architecture.components}
        out[label] = {
            "components": sorted(
                (
                    {
                        "id": component.id,
                        "name": component.name,
                        "type": component.type,
                        "trust": component.trust_level,
                        "properties": sorted(
                            f"{key}={value}"
                            for key, value in (component.properties or {}).items()
                            if isinstance(value, bool) or key in {"auth_type", "db_type", "technology"}
                        ),
                    }
                    for component in architecture.components
                ),
                key=lambda item: item["id"],
            ),
            "flows": sorted(
                f"{names.get(flow.source_id, flow.source_id)} -> {names.get(flow.target_id, flow.target_id)}"
                f" [{flow.protocol}/{flow.data_type}{'/assumed' if flow.assumed else ''}]"
                for flow in architecture.flows
            ),
            "boundaries": sorted(
                f"{boundary.name} ({boundary.boundary_type}): "
                + ", ".join(sorted(names.get(member, member) for member in boundary.components))
                for boundary in architecture.trust_boundaries
            ),
            "assets": sorted(
                f"{asset.name} [{asset.sensitivity}] @ {asset.location}" for asset in architecture.assets
            ),
        }
    return out


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else BACKEND / "extraction_snapshot.json"
    target.write_text(json.dumps(snapshot(), indent=2, sort_keys=True), encoding="utf-8")
    data = snapshot()
    print(f"wrote {target}")
    for label, payload in data.items():
        print(f"  {label}: {len(payload['components'])} components, {len(payload['flows'])} flows")
