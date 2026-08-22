"""Show what the Data flows panel will now render for each finding.

Reads the same fields the dashboard reads, so an empty panel here means an
empty panel there.
"""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.stdout.reconfigure(encoding="utf-8")

from app.engine.analyzer import ThreatAnalyzer  # noqa: E402

DESCRIPTION = (
    "A public React web portal calls a Node.js REST API over HTTPS. The API "
    "authenticates staff against Azure AD, stores patient records in a "
    "PostgreSQL database, and uploads scanned documents to an S3 ingestion "
    "bucket. The API also sends results to a laboratory partner. The portal "
    "has no MFA and the ingestion bucket is not encrypted at rest."
)


def main() -> None:
    result = ThreatAnalyzer().analyze_from_text(
        DESCRIPTION, project_name="Flow Context Probe", use_local_slm=False,
    )
    architecture = result.architecture
    print(f"components={len(architecture.components)} flows={len(architecture.flows)}")
    for flow in architecture.flows:
        properties = flow.properties or {}
        print(
            f"   {flow.source_id} -> {flow.target_id} [{flow.protocol}] "
            f"boundary={properties.get('trust_boundary')} "
            f"crosses={properties.get('crosses_trust_boundary', False)} "
            f"assumed={flow.assumed}"
        )

    print(f"\nthreats={len(result.threats)}")
    contexts = Counter((threat.explanation or {}).get("flow_context") for threat in result.threats)
    print(f"flow_context counts: {dict(contexts)}")

    for threat in result.threats[:8]:
        explanation = threat.explanation or {}
        scoped = threat.affected_data_flows or []
        related = explanation.get("component_flows") or []
        print(f"\n   {threat.severity:<8} {threat.component} :: {threat.title}")
        if scoped:
            print(f"      Data flows: {', '.join(scoped)}")
        elif related:
            print("      Flows touching this component:")
            for flow in related:
                print(
                    f"         {flow['label']} ({flow['direction']}, {flow['protocol']}"
                    f"{', crosses a trust boundary' if flow['crosses_trust_boundary'] else ''}"
                    f"{', assumed' if flow['assumed'] else ''})"
                )
        else:
            print(f"      (blank) reason={explanation.get('flow_context')}")


if __name__ == "__main__":
    main()
