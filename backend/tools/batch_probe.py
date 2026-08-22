"""Report what the engine produced for a scenario, for manual review."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.engine.analyzer import ThreatAnalyzer

SCENARIOS = {
    'payments': """
The Aurora payments platform serves retail customers.
A React web portal and an iOS mobile app call an API gateway over HTTPS.
The API gateway routes to a payments service and an accounts service.
The payments service calls Stripe for card capture and stores transactions in a PostgreSQL database.
The payments service publishes events to a Kafka queue, and a settlement worker consumes from Kafka
and writes reconciliation files to an S3 bucket.
Auth0 issues tokens for staff and customers.
An admin portal lets support staff issue refunds; the admin portal has no multi-factor authentication.
The PostgreSQL database is not encrypted at rest and admin actions are not logged.
Known issues:
- The JWT signing secret is committed to the repository.
- The S3 bucket policy allows public read.
""",
    'internal_ai': """
An internal knowledge assistant answers staff questions.
A Vue web console calls a FastAPI orchestration service over HTTPS.
The orchestration service retrieves context from a Pinecone vector store and calls Azure OpenAI for generation.
Documents are ingested from a SharePoint connector into an S3 landing bucket.
The orchestration service has no rate limiting and prompts are not validated.
Known issues:
- Uploaded documents are not scanned before indexing.
""",
}


def report(name: str, description: str) -> None:
    result = ThreatAnalyzer().analyze_from_text(description, name, use_local_slm=False)
    architecture = result.architecture
    gate = result.engine_status['quality_gate']
    coverage = result.engine_status['diagram_coverage']

    print(f'\n{"=" * 78}\n{name}\n{"=" * 78}')
    print(f'components {len(architecture.components)}  flows {len(architecture.flows)}  '
          f'findings {len(result.threats)}')
    print(f'\ncomponents:')
    for component in architecture.components:
        aliases = component.properties.get('merged_aliases')
        print(f'  {component.id:24s} {component.name:34s} {component.type:18s}'
              f'{" merged=" + ",".join(aliases) if aliases else ""}')
    print(f'\nflows:')
    for flow in architecture.flows:
        origin = flow.properties.get('origin', '?')
        detail = flow.properties.get('stated_relationship') or 'assumed from component types'
        print(f'  {origin:8s} {flow.source_id:22s} -> {flow.target_id:22s} {flow.protocol:6s} {detail}')

    confirmed = [threat for threat in result.threats if threat.tier == 'Confirmed']
    print(f'\nconfirmed findings ({len(confirmed)}):')
    for threat in confirmed[:14]:
        scope = ', '.join(threat.affected_components or threat.affected_data_flows or ['-'])
        print(f'  {threat.severity:8s} {threat.id:38s} {scope:28s} '
              f'{",".join(threat.owasp_top_10 or []) [:34]}')
    print(f'  ... {max(0, len(confirmed) - 14)} more' if len(confirmed) > 14 else '')

    print(f'\nquality gate: {gate["status"]}  integrity={gate["model_integrity"]}')
    for violation in gate['integrity_violations']:
        print(f'  BLOCK  {violation["check"]} x{violation["count"]}: {violation["detail"]}')
    for warning in gate['completeness_warnings']:
        print(f'  REVIEW {warning["check"]} x{warning["count"]}: {warning["detail"]}')
    print(f'  known issues declared {gate["declared_known_issues"]} reported {gate["reported_known_issues"]}')
    print(f'  stride cells {gate["applicable_stride_cells"]} determined ratio {gate["determined_control_ratio"]}')
    print(f'diagram: {coverage["components_drawn"]}/{coverage["components_in_model"]} components, '
          f'{coverage["flows_drawn"]}/{coverage["flows_in_model"]} flows, complete={coverage["complete"]}, '
          f'flagged={coverage["components_with_confirmed_findings"]}')


if __name__ == '__main__':
    for name, description in SCENARIOS.items():
        report(name, description)
