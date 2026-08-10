import networkx as nx

from app.engine.mermaid_generator import generate_mermaid


def test_enhanced_diagram_visibly_marks_trust_boundaries_and_crossings():
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

    assert 'Trust Boundary: External / Untrusted' in diagram
    assert 'Trust Boundary: API / DMZ' in diagram
    assert 'direction TB' in diagram
    assert 'TB crossing: HTTPS' in diagram
    assert 'linkStyle 0 stroke:#c2410c' in diagram


def test_dense_diagram_uses_compact_layered_overview():
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

    assert 'Compact overview: 18 components and 17 inferred flows' in diagram
    assert '+ 3 additional components' in diagram
    assert diagram.count('TB crossing:') <= 3
    assert 'Service / Internal' in diagram
