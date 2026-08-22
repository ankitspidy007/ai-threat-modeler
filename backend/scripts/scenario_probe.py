"""Run a spread of architectures through the running API and record what came back.

Kept as a script rather than a test because the point is to read the output and
judge it, not to assert a fixed answer. The scenarios differ in shape on purpose:
prose against structured input, a system with stated weaknesses against one
without, and an AI system against a conventional one, so that a weakness in one
extraction path is not hidden by another path doing well.
"""

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

API = "http://127.0.0.1:8000/analyze"
OUT = Path(__file__).resolve().parent.parent / "scenario_output"

SCENARIOS = {
    "fintech_payments": """
Our retail payments platform serves consumers in the EU. A React single page
application and an iOS mobile app call an AWS API Gateway over HTTPS. The gateway
validates OAuth2 tokens with AWS Cognito and routes payment requests to a Java
Spring Boot payments service running on ECS Fargate. The payments service writes
the transaction ledger to an Aurora PostgreSQL database and stores signed
receipts in an S3 bucket. It calls Stripe to capture cards and publishes
settlement events to an SQS queue, which a Python settlement worker consumes from
and reconciles nightly against a Snowflake warehouse. Card data is tokenized at
the edge. Admin staff use a separate internal console on the corporate VPN to
issue refunds.
""",
    "healthcare_phi": """
A hospital patient portal lets clinicians view and amend patient records.
Clinicians authenticate with Azure AD and the React portal calls a FHIR API
gateway which routes to a Node.js records service. The records service reads
patient documents from a MongoDB clinical store and writes audit events to an
Elasticsearch cluster. Lab results arrive from an external laboratory partner
over SFTP into an ingestion bucket, and a Python ETL job loads them into the
clinical store. PHI is encrypted at rest. There is no MFA on the clinician
portal, the audit log is writable by the records service account, and the
laboratory partner uses a shared static credential that has never been rotated.
""",
    "ai_agent_rag": """
A customer support assistant answers billing questions. A Next.js chat widget
calls a FastAPI orchestration service which retrieves context documents from a
Pinecone vector store and from an S3 knowledge bucket, builds a prompt, and calls
an Azure OpenAI GPT-4 model. The orchestrator exposes MCP tools that let the
agent query a PostgreSQL billing database and call an internal refunds API
directly. Conversation transcripts are logged to Elasticsearch. End users
authenticate with Entra ID. The agent runs with a single service account that has
read and write access to the billing database.
""",
    "k8s_multitenant_saas": """
Our multi-tenant SaaS runs on an AWS EKS cluster. An NGINX ingress terminates TLS
and forwards to a Go API gateway. The gateway calls an account service, a project
service and a billing service, all deployed as pods in the same namespace. The
services share a PostgreSQL cluster with a tenant_id column for isolation and
cache sessions in Redis. Container images are built by a GitHub Actions pipeline
and pushed to ECR. Secrets are mounted from AWS Secrets Manager. Tenants can
upload files which are stored in a shared S3 bucket keyed by tenant prefix.
Prometheus and Grafana provide observability.
""",
}

STRUCTURED = """
[Table 1]
Row 1: ID | Component | Type | Technology | Trust level | Controls | Responsibility / Data
Row 2: C1 | Customer web app | WebClient | React SPA | public |  | Customer facing ordering UI
Row 3: C2 | Public API edge | API Gateway | AWS API Gateway | public | waf_enabled, rate_limiting | Terminates TLS and authenticates callers
Row 4: C3 | Identity service | Identity Provider | AWS Cognito | internal | mfa_enabled=no | Issues OAuth2 tokens
Row 5: C4 | Orders service | Service | Java Spring Boot | internal |  | Order lifecycle and pricing
Row 6: C5 | Orders database | Database | Aurora PostgreSQL | restricted | encryption_at_rest | Order and customer records
Row 7: C6 | Invoice store | Object Storage | Amazon S3 | restricted | encryption_at_rest=no | Generated invoice PDFs

[Table 2]
Row 1: ID | Source and Destination | Protocol | Data | Evidence
Row 2: F1 | C1 -> C2 | HTTPS | application_data | stated
Row 3: F2 | C2 -> C3 | HTTPS | credentials | stated
Row 4: F3 | C2 -> C4 | HTTPS | application_data | stated
Row 5: F4 | C4 -> C5 | TLS | financial | stated
Row 6: F5 | C4 -> C6 | HTTPS | financial | stated

[Table 3]
Row 1: ID | Boundary | Trust level | Contents
Row 2: TB1 | Internet edge | public | C1, C2
Row 3: TB2 | Application tier | internal | C3, C4
Row 4: TB3 | Data tier | restricted | C5, C6
"""


def analyze(name: str, description: str, project: str | None = None) -> dict:
    body = json.dumps({
        "description": description,
        "project_name": project or name,
        "analysis_mode": "standard",
    }).encode()
    request = urllib.request.Request(API, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=600) as response:
        return json.loads(response.read())


def summarize(name: str, result: dict) -> None:
    architecture = result.get("architecture", {})
    components = architecture.get("components", [])
    flows = architecture.get("flows", [])
    threats = result.get("threats", [])
    names = {component["id"]: component["name"] for component in components}

    print(f"\n{'=' * 78}\n{name}  score={result.get('score')}\n{'=' * 78}")
    print(f"components={len(components)} flows={len(flows)} threats={len(threats)}")

    print("\n-- components --")
    for component in components:
        properties = component.get("properties") or {}
        print(f"  {component['id']:<34} {component['type']:<18} {component.get('trust_level'):<10} {properties.get('technology','')}")

    print("\n-- flows --")
    for flow in flows:
        mark = "assumed" if flow.get("assumed") else "stated"
        print(f"  {names.get(flow['source_id'], flow['source_id']):<28} -> {names.get(flow['target_id'], flow['target_id']):<28} {flow.get('protocol',''):<7} {flow.get('data_type',''):<18} {mark}")

    print("\n-- trust boundaries --")
    for boundary in architecture.get("trust_boundaries", []):
        member_names = [names.get(member, member) for member in boundary.get("components", [])]
        print(f"  {boundary.get('name')} [{boundary.get('trust_level','')}]: {', '.join(member_names)}")

    by_severity: dict = {}
    by_tier: dict = {}
    for threat in threats:
        by_severity[threat["severity"]] = by_severity.get(threat["severity"], 0) + 1
        by_tier[threat.get("tier")] = by_tier.get(threat.get("tier"), 0) + 1
    print(f"\n-- threats by severity -- {by_severity}")
    print(f"-- threats by tier -- {by_tier}")

    print("\n-- top threats --")
    for threat in threats[:12]:
        print(f"  [{threat['severity']:<8}][{threat.get('tier',''):<9}] {threat['id']:<28} {threat['title'][:64]}")
        print(f"      on: {names.get(threat.get('component_id'), threat.get('component_id'))}")

    coverage = result.get("coverage") or {}
    print("\n-- coverage gaps --")
    for gap in coverage.get("missing_information", []):
        print(f"  ({gap.get('type')}) {gap.get('message')}")
    print("\n-- assumptions --")
    for assumption in (coverage.get("assumptions") or [])[:10]:
        print(f"  ({assumption.get('scope')}) {assumption.get('message')}")

    stride = result.get("stride_coverage") or {}
    print(f"\n-- stride -- applicable={stride.get('applicable_cells')} unknown={stride.get('unknown_cells')}")

    print("\n-- diagram --")
    print(result.get("mermaid_diagram", ""))


def main() -> None:
    OUT.mkdir(exist_ok=True)
    only = sys.argv[1] if len(sys.argv) > 1 else None
    cases = dict(SCENARIOS)
    cases["structured_orders"] = STRUCTURED
    for name, description in cases.items():
        if only and only != name:
            continue
        result = analyze(name, description)
        (OUT / f"{name}.json").write_text(json.dumps(result, indent=1), encoding="utf-8")
        summarize(name, result)


if __name__ == "__main__":
    main()
