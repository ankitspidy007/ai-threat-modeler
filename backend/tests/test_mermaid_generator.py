import networkx as nx

from app.engine.mermaid_generator import generate_mermaid
from app.engine.analyzer import ThreatAnalyzer


def test_diagram_uses_standard_dfd_shapes_and_trust_boundaries():
    graph = nx.DiGraph()
    graph.add_node('browser', label='Browser', type='WebClient', external=True)
    graph.add_node('api', label='Public API', type='API Gateway')
    graph.add_edge(
        'browser',
        'api',
        protocol='https',
        crosses_trust_boundary=True,
    )

    diagram = generate_mermaid(graph, enhanced=True)

    assert 'External Entity' in diagram
    assert 'Internet / Client Boundary' in diagram
    assert 'direction LR' in diagram
    assert 'E1 Browser' in diagram
    assert '1.0 Public API' in diagram
    assert 'stroke-dasharray: 7 4' in diagram
    assert '==>|HTTPS|' in diagram


def test_dense_diagram_limits_nodes_and_flows_for_a_readable_dfd():
    graph = nx.DiGraph()
    graph.add_node('web', label='React SPA', type='WebClient')
    graph.add_node('gateway', label='API Gateway', type='API Gateway')

    for index in range(8):
        service = f'service_{index}'
        database = f'database_{index}'
        graph.add_node(service, label=f'Platform Service {index}', type='Service')
        graph.add_node(database, label=f'Data Store {index}', type='Database')
        graph.add_edge('web', 'gateway', protocol='https')
        graph.add_edge('gateway', service, protocol='https')
        graph.add_edge(service, database, protocol='tcp')

    diagram = generate_mermaid(graph, enhanced=True)

    assert 'Application Trust Boundary' in diagram
    assert 'Data Trust Boundary' in diagram
    assert 'Platform Service 0' in diagram
    assert 'Platform Service 7' not in diagram
    assert diagram.count('-->|') + diagram.count('==>|') <= 12


def test_dense_diagram_selects_one_representative_workflow():
    graph = nx.DiGraph()
    graph.add_node('client', label='Client', type='WebClient', public_access=True)
    graph.add_node('api', label='API', type='API')
    graph.add_node('primary', label='Primary DB', type='Database')
    graph.add_node('cache', label='Cache', type='Database')
    graph.add_node('guardduty', label='GuardDuty', type='Threat Detection')
    graph.add_edge('client', 'api', protocol='https')
    graph.add_edge('api', 'primary', protocol='tcp')
    graph.add_edge('api', 'cache', protocol='tcp')

    diagram = generate_mermaid(graph, enhanced=True)

    assert diagram.count('-->|') + diagram.count('==>|') == 2
    assert 'GuardDuty' not in diagram
    assert ('Primary DB' in diagram) != ('Cache' in diagram)


def test_healthcare_template_keeps_security_relevant_topology():
    description = """Healthcare records management system with:
- React frontend with role-based access (Doctor, Nurse, Admin)
- .NET Core REST API with OAuth2 + MFA authentication
- PostgreSQL for patient records (PHI/PII data)
- Redis for session management
- Azure Blob Storage for medical imaging (DICOM files)
- HL7 FHIR API for interoperability
- Azure AD for identity management
- Encryption at rest (AES-256) and in transit (TLS 1.3)
- Audit logging for all data access
- HIPAA-compliant infrastructure on Azure

KNOWN ISSUES:
- Break-the-glass access procedure not audited separately
- No data loss prevention (DLP) on file downloads
- Session timeout set to 8 hours (too long for PHI access)"""

    result = ThreatAnalyzer().analyze_from_text(
        description, "Healthcare System", use_local_slm=False, domain_profile="healthcare"
    )
    edges = {(flow.source_id, flow.target_id) for flow in result.architecture.flows}

    assert {
        ("react", "rest_api"),
        ("rest_api", "hl7_fhir_api"),
        ("rest_api", "postgresql"),
        ("rest_api", "redis"),
        ("rest_api", "azure_blob"),
        ("rest_api", "azure_ad"),
    }.issubset(edges)
    assert ("hl7_fhir_api", "postgresql") not in edges
    assert ("hl7_fhir_api", "redis") not in edges

    for label in ("React", "Rest Api", "HL7 FHIR API", "Postgresql", "REDIS", "Azure Blob", "Azure Ad"):
        assert label in result.mermaid_diagram
    assert 'Third-Party Trust Boundary' in result.mermaid_diagram
