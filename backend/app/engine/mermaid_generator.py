import re
import networkx as nx
from typing import List, Dict, Set
import json
import os


COMPACT_GRAPH_NODE_THRESHOLD = 16
COMPACT_GRAPH_EDGE_THRESHOLD = 24
COMPACT_LAYER_LIMITS = {
    'external': 3,
    'frontend': 2,
    'api_layer': 3,
    'services': 5,
    'data_layer': 4,
}
COMPACT_LAYER_ANCHORS = {
    'external': 'External interfaces',
    'frontend': 'Web application',
    'api_layer': 'API ingress',
    'services': 'Internal services',
    'data_layer': 'Trusted data stores',
}
LOW_SIGNAL_COMPONENT_LABELS = {
    'api', 'cdn', 'database', 'frontend', 'identity provider', 'ml service',
    'monitoring', 'queue', 'service', 'spa', 'webclient',
}

def generate_mermaid(graph: nx.DiGraph, threats: List = None, enhanced: bool = True) -> str:
    """
    Converts a NetworkX graph to an enhanced Mermaid flowchart with:
    - STRIDE color coding
    - Trust boundary visualization
    - DFD element standards (processes, data stores, external entities)
    - Threat annotations
    - Component numbering
    - Legend
    
    Args:
        graph: NetworkX directed graph
        threats: Optional list of threats to annotate on diagram
        enhanced: If True, include STRIDE colors and annotations
    """
    # The report diagram is a DFD, not an infrastructure inventory. A single
    # focused view is more useful for threat modeling than every discovered
    # component and inferred connection. Keep the legacy renderers below for
    # compatibility with stored reports, but generate the professional DFD for
    # all new analyses.
    return _generate_professional_dfd_mermaid(graph)


DFD_ZONE_ORDER = ('external', 'public', 'application', 'data', 'third_party')
DFD_ZONE_TITLES = {
    'external': 'External Entity',
    'public': 'Internet / Client Boundary',
    'application': 'Application Trust Boundary',
    'data': 'Data Trust Boundary',
    'third_party': 'Third-Party Trust Boundary',
}
DFD_ZONE_LIMITS = {'external': 3, 'public': 3, 'application': 5, 'data': 4, 'third_party': 3}
DFD_NON_FLOW_COMPONENTS = {'Threat Detection', 'Monitoring', 'Backup'}


def _dfd_zone(data: Dict) -> str:
    node_type = data.get('type', 'Service')
    if node_type == 'Identity Provider':
        return 'third_party'
    if data.get('external', False):
        return 'external' if node_type in {'WebClient', 'Mobile App'} else 'third_party'
    if node_type in {'Database', 'Object Storage', 'Queue', 'Data Warehouse', 'Secrets Manager'}:
        return 'data'
    if node_type in {'WebClient', 'Mobile App', 'CDN', 'API Gateway', 'Load Balancer'} or data.get('public_access'):
        return 'public'
    return 'application'


def _dfd_node_priority(graph: nx.DiGraph, node: str, data: Dict) -> tuple:
    label = _sanitize_label(data.get('label', node))
    score = graph.in_degree(node) + graph.out_degree(node)
    if label.lower() in LOW_SIGNAL_COMPONENT_LABELS:
        score -= 100
    if len(label) > 50:
        score -= 20
    if data.get('external'):
        score += 15
    return (-score, label.lower())


def _dfd_node_label(data: Dict, number: str) -> str:
    label = _sanitize_label(data.get('label', 'Component'))
    if len(label) > 32:
        label = f'{label[:29].rstrip()}...'
    return f'{number} {label}'


def _dfd_shape(data: Dict) -> tuple:
    node_type = data.get('type', 'Service')
    if data.get('external', False) or node_type == 'Identity Provider':
        return ('[', ']')                 # DFD external entity
    if node_type in {'Database', 'Object Storage', 'Queue', 'Data Warehouse', 'Secrets Manager'}:
        return ('[(', ')]')                # DFD data store
    return ('((', '))')                    # DFD process


def _workflow_score(graph: nx.DiGraph, path: List[str]) -> tuple:
    zones = {_dfd_zone(graph.nodes[node]) for node in path}
    edge_data = [graph.get_edge_data(a, b) or {} for a, b in zip(path, path[1:])]
    score = len(zones) * 20 + len(path)
    if _dfd_zone(graph.nodes[path[0]]) in {'external', 'public'}:
        score += 20
    if _dfd_zone(graph.nodes[path[-1]]) in {'data', 'third_party'}:
        score += 25
    if any(graph.nodes[node].get('type') == 'ML Service' for node in path):
        score += 5
    if any(graph.nodes[node].get('type') == 'API Gateway' for node in path):
        score += 10
    if graph.nodes[path[-1]].get('type') in {'Database', 'Object Storage', 'Data Warehouse'}:
        score += 5
    score += sum(3 for data in edge_data if not data.get('assumed'))
    return score, -len(path)


def _representative_workflow(graph: nx.DiGraph) -> tuple:
    """Select one coherent entry-to-asset flow for a readable final DFD."""
    eligible = [
        node for node, data in graph.nodes(data=True)
        if data.get('type') not in DFD_NON_FLOW_COMPONENTS
    ]
    workflow_graph = graph.subgraph(eligible).copy()
    contextual_types = {'Identity Provider', 'Object Storage', 'Secrets Manager'}
    if (
        workflow_graph.number_of_nodes() <= 10
        and workflow_graph.number_of_edges() <= 14
        and any(data.get('type') in contextual_types for _, data in workflow_graph.nodes(data=True))
    ):
        return set(workflow_graph.nodes), list(workflow_graph.edges(data=True))
    sources = [
        node for node in workflow_graph
        if _dfd_zone(workflow_graph.nodes[node]) in {'external', 'public'} and workflow_graph.out_degree(node)
    ]
    if not sources:
        sources = [node for node in workflow_graph if workflow_graph.in_degree(node) == 0 and workflow_graph.out_degree(node)]
    sinks = [
        node for node in workflow_graph
        if _dfd_zone(workflow_graph.nodes[node]) in {'data', 'third_party'} and workflow_graph.in_degree(node)
    ]

    candidates = []
    for source in sources:
        for sink in sinks:
            for path in nx.all_simple_paths(workflow_graph, source, sink, cutoff=5):
                if len(path) >= 2:
                    candidates.append(path)

    if candidates:
        path = max(candidates, key=lambda item: _workflow_score(workflow_graph, item))
        edges = [(a, b, workflow_graph.get_edge_data(a, b) or {}) for a, b in zip(path, path[1:])]
        return set(path), edges

    fallback_edges = list(workflow_graph.edges(data=True))[:4]
    fallback_nodes = {node for edge in fallback_edges for node in edge[:2]}
    if not fallback_nodes:
        fallback_nodes = set(eligible[:4])
    return fallback_nodes, fallback_edges


def _generate_professional_dfd_mermaid(graph: nx.DiGraph) -> str:
    """Generate a compact, presentation-ready DFD with explicit boundaries."""
    workflow_nodes, workflow_edges = _representative_workflow(graph)
    zones = {zone: [] for zone in DFD_ZONE_ORDER}
    for node, data in graph.nodes(data=True):
        if node in workflow_nodes:
            zones[_dfd_zone(data)].append((node, data))

    visible_by_zone = {
        zone: sorted(nodes, key=lambda item: _dfd_node_priority(graph, item[0], item[1]))[:DFD_ZONE_LIMITS[zone]]
        for zone, nodes in zones.items()
    }
    visible_nodes = {node for nodes in visible_by_zone.values() for node, _ in nodes}

    entity_number = process_number = datastore_number = 1
    number_by_node = {}
    for zone in DFD_ZONE_ORDER:
        for node, data in visible_by_zone[zone]:
            if data.get('external', False) or data.get('type') == 'Identity Provider':
                number_by_node[node] = f'E{entity_number}'
                entity_number += 1
            elif _dfd_zone(data) == 'data':
                number_by_node[node] = f'D{datastore_number}'
                datastore_number += 1
            else:
                number_by_node[node] = f'{process_number}.0'
                process_number += 1

    lines = [
        "%%{init: {'flowchart': {'htmlLabels': true, 'nodeSpacing': 32, 'rankSpacing': 64, 'curve': 'linear'}} }%%",
        'flowchart TB',
        '    %% DFD notation: E# external entity, #.0 process, D# data store',
    ]
    for zone in DFD_ZONE_ORDER:
        nodes = visible_by_zone[zone]
        if not nodes:
            continue
        zone_id = f'dfd_{zone}'
        lines.append(f'    subgraph {zone_id}["{DFD_ZONE_TITLES[zone]}"]')
        lines.append('        direction LR')
        for node, data in nodes:
            node_id = _sanitize_id(node)
            lines.append(f'        {_format_node(node_id, _dfd_node_label(data, number_by_node[node]), _dfd_shape(data))}')
        lines.append('    end')
        lines.append(f'    style {zone_id} fill:#ffffff,stroke:#404040,stroke-width:2px,stroke-dasharray: 7 4')

    for source, target, data in workflow_edges:
        if source not in visible_nodes or target not in visible_nodes:
            continue
        protocol = str(data.get('protocol') or '').upper()
        data_type = str(data.get('data_type') or '')
        label = protocol or 'data flow'
        if data_type in {'credentials', 'pii', 'financial', 'phi', 'secrets'}:
            label = f'{protocol} / {data_type}' if protocol else data_type
        arrow = '==>' if _dfd_zone(graph.nodes[source]) != _dfd_zone(graph.nodes[target]) else '-->'
        lines.append(f'    {_sanitize_id(source)} {arrow}|{_sanitize_edge_label(label)}| {_sanitize_id(target)}')

    lines.extend([
        '    classDef dfdEntity fill:#ffffff,stroke:#202020,stroke-width:2px,color:#111111',
        '    classDef dfdProcess fill:#ffffff,stroke:#202020,stroke-width:2px,color:#111111',
        '    classDef dfdStore fill:#ffffff,stroke:#202020,stroke-width:2px,color:#111111',
    ])
    for node in visible_nodes:
        data = graph.nodes[node]
        class_name = 'dfdEntity' if data.get('external', False) or data.get('type') == 'Identity Provider' else 'dfdStore' if _dfd_zone(data) == 'data' else 'dfdProcess'
        lines.append(f'    class {_sanitize_id(node)} {class_name}')
    return '\n'.join(lines)
    
    mermaid_lines = ["graph TB"]  # Top to Bottom for better layering
    
    # Load STRIDE colors
    stride_colors = _load_stride_colors()

    # Natural-language extraction can infer a dense, many-to-many graph from a
    # concise description. Render a readable threat-model overview in that case.
    if _should_use_compact_layout(graph):
        return _generate_compact_mermaid(graph, threats, stride_colors)
    
    # Categorize nodes by layer and assign DFD numbering
    layers = {
        'external': [],      # External entities (E1, E2, E3...)
        'frontend': [],      # Processes (1.0, 2.0, 3.0...)
        'api_layer': [],     # Processes (API layer)
        'services': [],      # Processes (Service layer)
        'data_layer': [],    # Data stores (D1, D2, D3...)
    }
    
    # Numbering counters
    entity_num = 1
    process_num = 1
    datastore_num = 1
    
    for node, data in graph.nodes(data=True):
        node_type = data.get('type', 'Service')
        is_external = data.get('external', False)
        
        if is_external:
            data['dfd_id'] = f"E{entity_num}"
            entity_num += 1
            layers['external'].append((node, data))
        elif node_type in ['Database', 'Object Storage', 'Queue', 'Data Warehouse']:
            data['dfd_id'] = f"D{datastore_num}"
            datastore_num += 1
            layers['data_layer'].append((node, data))
        elif node_type in ['WebClient', 'Mobile App']:
            data['dfd_id'] = f"{process_num}.0"
            process_num += 1
            layers['frontend'].append((node, data))
        elif node_type in ['API Gateway', 'Load Balancer', 'CDN', 'API']:
            data['dfd_id'] = f"{process_num}.0"
            process_num += 1
            layers['api_layer'].append((node, data))
        else:
            data['dfd_id'] = f"{process_num}.0"
            process_num += 1
            layers['services'].append((node, data))
    
    # Generate subgraphs for each layer with trust boundary styling
    layer_configs = [
        ('external', 'Trust Boundary: External / Untrusted', 'fill:#ffebee,stroke:#b71c1c,stroke-width:3px,stroke-dasharray: 8 4'),
        ('frontend', 'Trust Boundary: Frontend / DMZ', 'fill:#e1f5ff,stroke:#01579b,stroke-width:3px,stroke-dasharray: 8 4'),
        ('api_layer', 'Trust Boundary: API / DMZ', 'fill:#fff9c4,stroke:#f57f17,stroke-width:3px,stroke-dasharray: 8 4'),
        ('services', 'Trust Boundary: Service / Internal', 'fill:#f3e5f5,stroke:#4a148c,stroke-width:3px,stroke-dasharray: 8 4'),
        ('data_layer', 'Trust Boundary: Data / Trusted', 'fill:#e8f5e9,stroke:#1b5e20,stroke-width:3px,stroke-dasharray: 8 4'),
    ]
    
    for layer_key, layer_name, style in layer_configs:
        nodes = layers[layer_key]
        if not nodes:
            continue
        
        # Create subgraph with trust boundary annotation
        mermaid_lines.append(f"    subgraph zone_{layer_key}[\"{layer_name}\"]")
        mermaid_lines.append("        direction TB")

        for node, data in nodes:
            node_id = _sanitize_id(node)
            label = data.get('label', node)
            node_type = data.get('type', 'Service')
            dfd_id = data.get('dfd_id', '')
            
            # Add DFD ID to label - use colon separator to avoid nested parentheses
            # Format: "1.0: WebClient" instead of "(1.0) WebClient"
            full_label = f"{dfd_id}: {label}" if dfd_id else label
            
            # Choose shape based on DFD standards
            shape = _get_dfd_shape(node_type, data)
            mermaid_lines.append(f"        {_format_node(node_id, full_label, shape)}")
        
        mermaid_lines.append(f"    end")
        mermaid_lines.append(f"    style zone_{layer_key} {style}")
    
    
    # Add edges with enhanced labels including protocol, auth, and data type.
    # Boundary-crossing flows are explicitly labeled and styled after the graph.
    boundary_edge_indexes = []
    for edge_index, (u, v, data) in enumerate(graph.edges(data=True)):
        u_id = _sanitize_id(u)
        v_id = _sanitize_id(v)
        
        protocol = data.get('protocol', 'https').upper()
        crosses_boundary = data.get('crosses_trust_boundary', False)
        auth_method = data.get('auth_method', '')
        data_type = data.get('data_type', '')
        
        # Determine if edge crosses trust boundaries
        u_layer = _get_node_layer(u, layers)
        v_layer = _get_node_layer(v, layers)
        crosses_boundary = crosses_boundary or (u_layer != v_layer)
        
        # Build rich label with protocol and optional auth/data info
        label_parts = [protocol]
        if auth_method:
            label_parts.append(f"Auth: {auth_method}")
        if data_type:
            label_parts.append(data_type)
        
        flow_label = " / ".join(label_parts) if len(label_parts) > 1 else protocol
        if crosses_boundary:
            flow_label = f"TB crossing: {flow_label}"
            boundary_edge_indexes.append(edge_index)
        flow_label = _sanitize_edge_label(flow_label)
        
        # Style edges differently for trust boundary crossings
        if crosses_boundary:
            arrow = f"==>|{flow_label}|" if flow_label else "==>"
        else:
            arrow = f"-->|{flow_label}|" if flow_label else "-->"

        mermaid_lines.append(f"    {u_id} {arrow} {v_id}")

    for edge_index in boundary_edge_indexes:
        mermaid_lines.append(
            f"    linkStyle {edge_index} stroke:#c2410c,stroke-width:3px,stroke-dasharray: 8 4"
        )
    
    
    # Add classDef styling for component types
    mermaid_lines.extend(_generate_class_definitions())
    
    # Apply class styles to nodes based on type
    for node, data in graph.nodes(data=True):
        node_id = _sanitize_id(node)
        node_type = data.get('type', 'Service')
        is_external = data.get('external', False)
        
        if is_external:
            mermaid_lines.append(f"    class {node_id} externalClass")
        elif node_type in ['Database', 'Object Storage', 'Queue', 'Data Warehouse']:
            mermaid_lines.append(f"    class {node_id} datastoreClass")
        elif node_type in ['WebClient', 'Mobile App']:
            mermaid_lines.append(f"    class {node_id} clientClass")
        elif node_type in ['API Gateway', 'Load Balancer']:
            mermaid_lines.append(f"    class {node_id} gatewayClass")
        else:
            mermaid_lines.append(f"    class {node_id} processClass")
    
    # Add STRIDE color coding to nodes (if threats provided) - this overrides class styling
    if threats:
        threat_colors = _apply_stride_colors(graph, threats, stride_colors)
        for node_id, color in threat_colors.items():
            sanitized_id = _sanitize_id(node_id)
            mermaid_lines.append(f"    style {sanitized_id} fill:{color},stroke:#333,stroke-width:4px")
    
    # Add legend
    mermaid_lines.extend(_generate_legend(stride_colors))
    
    return "\n".join(mermaid_lines)


def _should_use_compact_layout(graph: nx.DiGraph) -> bool:
    """Use an overview diagram when the full graph cannot stay legible."""
    return (
        graph.number_of_nodes() > COMPACT_GRAPH_NODE_THRESHOLD
        or graph.number_of_edges() > COMPACT_GRAPH_EDGE_THRESHOLD
    )


def _categorize_nodes(graph: nx.DiGraph) -> Dict[str, List[tuple]]:
    """Group graph nodes into the trust zones used by the diagram."""
    layers = {
        'external': [],
        'frontend': [],
        'api_layer': [],
        'services': [],
        'data_layer': [],
    }

    for node, data in graph.nodes(data=True):
        node_type = data.get('type', 'Service')
        if data.get('external', False):
            layers['external'].append((node, data))
        elif node_type in ['Database', 'Object Storage', 'Queue', 'Data Warehouse']:
            layers['data_layer'].append((node, data))
        elif node_type in ['WebClient', 'Mobile App']:
            layers['frontend'].append((node, data))
        elif node_type in ['API Gateway', 'Load Balancer', 'CDN', 'API']:
            layers['api_layer'].append((node, data))
        else:
            layers['services'].append((node, data))

    return layers


def _compact_node_priority(graph: nx.DiGraph, node: str, data: Dict) -> tuple:
    """Prefer explicit, short component names over parser-generated aliases."""
    label = _sanitize_label(data.get('label', node))
    normalized_label = label.lower()
    score = graph.in_degree(node) + graph.out_degree(node)

    if normalized_label in LOW_SIGNAL_COMPONENT_LABELS:
        score -= 100
    if len(label) > 48:
        score -= 40
    if any(token in normalized_label for token in ('service', 'gateway', 'postgres', 'redis', 'elastic', 'rabbit', 'auth0', 'stripe', 'sendgrid', 'cloudfront')):
        score += 20

    return (-score, normalized_label)


def _compact_visible_nodes(graph: nx.DiGraph, nodes: List[tuple], layer_key: str) -> List[tuple]:
    limit = COMPACT_LAYER_LIMITS[layer_key]
    return sorted(nodes, key=lambda item: _compact_node_priority(graph, item[0], item[1]))[:limit]


def _node_class_name(data: Dict) -> str:
    node_type = data.get('type', 'Service')
    if data.get('external', False):
        return 'externalClass'
    if node_type in ['Database', 'Object Storage', 'Queue', 'Data Warehouse']:
        return 'datastoreClass'
    if node_type in ['WebClient', 'Mobile App']:
        return 'clientClass'
    if node_type in ['API Gateway', 'Load Balancer']:
        return 'gatewayClass'
    return 'processClass'


def _boundary_flow_summary(graph: nx.DiGraph, layers: Dict, source_layer: str, target_layer: str) -> tuple:
    """Summarize all direct flows between two adjacent trust zones."""
    source_nodes = {node for node, _ in layers[source_layer]}
    target_nodes = {node for node, _ in layers[target_layer]}
    protocols = []
    flow_count = 0

    for source, target, data in graph.edges(data=True):
        if (
            (source in source_nodes and target in target_nodes)
            or (source in target_nodes and target in source_nodes)
        ):
            flow_count += 1
            protocol = str(data.get('protocol', '')).upper()
            if protocol and protocol not in protocols:
                protocols.append(protocol)

    if not flow_count:
        return 'Trust boundary', False

    protocol_label = ', '.join(protocols[:2]) or 'modeled data flow'
    return f'TB crossing: {protocol_label} / {flow_count} flows', True


def _generate_compact_mermaid(graph: nx.DiGraph, threats: List, stride_colors: Dict) -> str:
    """Render a compact, vertically layered overview for dense architecture graphs."""
    layers = _categorize_nodes(graph)
    layer_configs = [
        ('external', 'Trust Boundary: External / Untrusted', 'fill:#ffebee,stroke:#b71c1c,stroke-width:3px,stroke-dasharray: 8 4'),
        ('frontend', 'Trust Boundary: Frontend / DMZ', 'fill:#e1f5ff,stroke:#01579b,stroke-width:3px,stroke-dasharray: 8 4'),
        ('api_layer', 'Trust Boundary: API / DMZ', 'fill:#fff9c4,stroke:#f57f17,stroke-width:3px,stroke-dasharray: 8 4'),
        ('services', 'Trust Boundary: Service / Internal', 'fill:#f3e5f5,stroke:#4a148c,stroke-width:3px,stroke-dasharray: 8 4'),
        ('data_layer', 'Trust Boundary: Data / Trusted', 'fill:#e8f5e9,stroke:#1b5e20,stroke-width:3px,stroke-dasharray: 8 4'),
    ]
    mermaid_lines = [
        "%%{init: {'flowchart': {'nodeSpacing': 36, 'rankSpacing': 60, 'curve': 'basis'}} }%%",
        'flowchart LR',
        f'    %% Compact overview: {graph.number_of_nodes()} components and {graph.number_of_edges()} inferred flows',
    ]
    active_layers = []
    rendered_nodes = set()
    anchors = {}
    invisible_link_count = 0

    for layer_key, layer_name, style in layer_configs:
        nodes = layers[layer_key]
        if not nodes:
            continue

        active_layers.append(layer_key)
        anchor_id = f'{layer_key}_anchor'
        anchors[layer_key] = anchor_id
        visible_nodes = _compact_visible_nodes(graph, nodes, layer_key)
        hidden_count = len(nodes) - len(visible_nodes)
        layout_nodes = [anchor_id]

        mermaid_lines.append(f'    subgraph zone_{layer_key}["{layer_name}"]')
        mermaid_lines.append('        direction TB')
        mermaid_lines.append(f'        {anchor_id}("{COMPACT_LAYER_ANCHORS[layer_key]}")')

        for node, data in visible_nodes:
            node_id = _sanitize_id(node)
            label = _sanitize_label(data.get('label', node))
            mermaid_lines.append(f'        {_format_node(node_id, label, _get_dfd_shape(data.get("type", "Service"), data))}')
            layout_nodes.append(node_id)
            rendered_nodes.add(node_id)

        if hidden_count:
            summary_id = f'{layer_key}_summary'
            plural = 'component' if hidden_count == 1 else 'components'
            mermaid_lines.append(f'        {summary_id}["+ {hidden_count} additional {plural}"]')
            mermaid_lines.append(f'        class {summary_id} summaryClass')
            layout_nodes.append(summary_id)

        # Invisible links keep components in an intentional vertical stack inside
        # their trust zone without adding misleading implementation flows.
        for current, next_node in zip(layout_nodes, layout_nodes[1:]):
            mermaid_lines.append(f'        {current} ~~~ {next_node}')
            invisible_link_count += 1

        mermaid_lines.append('    end')
        mermaid_lines.append(f'    style zone_{layer_key} {style}')

    boundary_edge_indexes = []
    for boundary_number, (source_layer, target_layer) in enumerate(zip(active_layers, active_layers[1:])):
        label, observed = _boundary_flow_summary(graph, layers, source_layer, target_layer)
        arrow = '==>' if observed else '-.->'
        mermaid_lines.append(
            f'    {anchors[source_layer]} {arrow}|{_sanitize_edge_label(label)}| {anchors[target_layer]}'
        )
        boundary_edge_indexes.append(invisible_link_count + boundary_number)

    mermaid_lines.extend(_generate_class_definitions())
    mermaid_lines.append('    classDef boundaryAnchor fill:#ffffff,stroke:#475569,stroke-width:2px,color:#0f172a')
    mermaid_lines.append('    classDef summaryClass fill:#f8fafc,stroke:#94a3b8,stroke-width:1px,color:#334155,stroke-dasharray: 4 3')
    for anchor_id in anchors.values():
        mermaid_lines.append(f'    class {anchor_id} boundaryAnchor')

    for layer_key in active_layers:
        for node, data in _compact_visible_nodes(graph, layers[layer_key], layer_key):
            mermaid_lines.append(f'    class {_sanitize_id(node)} {_node_class_name(data)}')

    if threats:
        for node_id, color in _apply_stride_colors(graph, threats, stride_colors).items():
            sanitized_id = _sanitize_id(node_id)
            if sanitized_id in rendered_nodes:
                mermaid_lines.append(f'    style {sanitized_id} fill:{color},stroke:#333,stroke-width:4px')

    for edge_index in boundary_edge_indexes:
        mermaid_lines.append(
            f'    linkStyle {edge_index} stroke:#c2410c,stroke-width:3px,stroke-dasharray: 8 4'
        )

    mermaid_lines.extend(_generate_legend(stride_colors))
    return '\n'.join(mermaid_lines)

def _generate_basic_mermaid(graph: nx.DiGraph) -> str:
    """
    Basic Mermaid generation for backward compatibility.
    This is the original implementation.
    """
    mermaid_lines = ["graph TB"]
    
    layers = {
        'frontend': [],
        'api_layer': [],
        'services': [],
        'data_layer': [],
        'external': []
    }
    
    for node, data in graph.nodes(data=True):
        node_type = data.get('type', 'Service')
        is_external = data.get('external', False)
        
        if is_external:
            layers['external'].append((node, data))
        elif node_type in ['WebClient', 'Mobile App']:
            layers['frontend'].append((node, data))
        elif node_type in ['API Gateway', 'Load Balancer', 'CDN']:
            layers['api_layer'].append((node, data))
        elif node_type == 'Service':
            layers['services'].append((node, data))
        elif node_type in ['Database', 'Object Storage', 'Queue']:
            layers['data_layer'].append((node, data))
        else:
            layers['services'].append((node, data))
    
    layer_configs = [
        ('frontend', 'Frontend Layer', 'fill:#e1f5ff,stroke:#01579b'),
        ('api_layer', 'API Layer', 'fill:#fff9c4,stroke:#f57f17'),
        ('services', 'Service Layer', 'fill:#f3e5f5,stroke:#4a148c'),
        ('data_layer', 'Data Layer', 'fill:#e8f5e9,stroke:#1b5e20'),
        ('external', 'External Services', 'fill:#ffebee,stroke:#b71c1c')
    ]
    
    for layer_key, layer_name, style in layer_configs:
        nodes = layers[layer_key]
        if not nodes:
            continue
        
        mermaid_lines.append(f"    subgraph zone_{layer_key}[\"{layer_name}\"]")
        
        for node, data in nodes:
            node_id = _sanitize_id(node)
            label = data.get('label', node)
            node_type = data.get('type', 'Service')
            
            shape = _get_node_shape(node_type, data)
            mermaid_lines.append(f"        {_format_node(node_id, label, shape)}")
        
        mermaid_lines.append(f"    end")
        mermaid_lines.append(f"    style zone_{layer_key} {style}")
    
    for u, v, data in graph.edges(data=True):
        u_id = _sanitize_id(u)
        v_id = _sanitize_id(v)
        
        protocol = data.get('protocol', '')
        crosses_boundary = data.get('crosses_trust_boundary', False)
        
        safe_protocol = _sanitize_edge_label(protocol)

        if crosses_boundary:
            arrow = f"-.->|{safe_protocol}|" if safe_protocol else "-..->"
        elif safe_protocol:
            arrow = f"-->|{safe_protocol}|"
        else:
            arrow = "-->"
            
        mermaid_lines.append(f"    {u_id} {arrow} {v_id}")

    return "\n".join(mermaid_lines)

def _load_stride_colors() -> Dict:
    """Load STRIDE color configuration."""
    try:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        file_path = os.path.join(base_dir, 'data', 'stride_colors.json')
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Warning: Could not load STRIDE colors: {e}")
        return {}

def _sanitize_id(node_id: str) -> str:
    """Sanitize node ID for Mermaid syntax."""
    sanitized = re.sub(r"[^0-9A-Za-z_]", "_", str(node_id))
    sanitized = re.sub(r"_+", "_", sanitized).strip("_")
    if not sanitized:
        sanitized = "node"
    if sanitized[0].isdigit():
        sanitized = f"node_{sanitized}"
    return sanitized


def _sanitize_label(label: str) -> str:
    """Normalize labels so Mermaid treats them as plain text."""
    sanitized = str(label or "")
    sanitized = sanitized.replace("\\", "/")
    sanitized = sanitized.replace('"', "'")
    sanitized = sanitized.replace("\r", " ").replace("\n", " ")
    sanitized = re.sub(r"\s+", " ", sanitized).strip()
    return sanitized


def _sanitize_edge_label(label: str) -> str:
    """Normalize edge labels while removing Mermaid delimiter characters."""
    sanitized = _sanitize_label(label)
    sanitized = sanitized.replace("|", "/")
    return sanitized


def _format_node(node_id: str, label: str, shape: tuple) -> str:
    """Render a Mermaid node with a quoted label."""
    safe_label = _sanitize_label(label)
    shape_open, shape_close = shape

    if shape == ('[', ']'):
        return f'{node_id}["{safe_label}"]'
    if shape == ('(', ')'):
        return f'{node_id}("{safe_label}")'
    if shape == ('((', '))'):
        return f'{node_id}(("{safe_label}"))'
    if shape == ('[(', ')]'):
        return f'{node_id}[("{safe_label}")]'
    if shape == ('([', '])'):
        return f'{node_id}(["{safe_label}"])'
    if shape == ('[[', ']]'):
        return f'{node_id}[["{safe_label}"]]'
    if shape == ('>', ']'):
        return f'{node_id}>["{safe_label}"]'
    if shape == ('[/', '\\]'):
        return f'{node_id}[/"{safe_label}"\\]'

    return f'{node_id}{shape_open}"{safe_label}"{shape_close}'

def _get_dfd_shape(node_type: str, data: Dict) -> tuple:
    """
    Get Mermaid shape using ONLY the most basic shapes guaranteed to work in all Mermaid versions.
    
    Basic Mermaid Shapes (v8+ compatible):
    - Rectangle: [ ]
    - Rounded Rectangle: ( )
    
    NOTE: We avoid hexagon {{ }} because it conflicts with labels containing square brackets
    like {{[2.0] WebClient}} which causes parse errors.
    """
    # External entities - use rectangle
    if data.get('external', False):
        return ('[', ']')
    
    # Data stores - use rectangle with special marker
    if node_type in ['Database', 'Object Storage', 'Queue', 'Data Warehouse', 'Secrets Manager']:
        return ('[', ']')
    
    # Processes - use rounded rectangles
    if node_type in ['API', 'Service', 'Microservice', 'Lambda', 'Function', 'Serverless']:
        return ('(', ')')
    
    # API Gateways and Load Balancers - use rounded rectangles
    if node_type in ['API Gateway', 'Load Balancer', 'CDN']:
        return ('(', ')')
    
    # Web clients - use rounded rectangle (changed from hexagon to avoid syntax conflicts)
    if node_type in ['WebClient', 'Mobile App']:
        return ('(', ')')
    
    # Identity providers - use rounded rectangle
    if node_type == 'Identity Provider':
        return ('(', ')')
    
    # Default to rectangle
    return ('[', ']')




def _get_node_shape(node_type: str, data: Dict) -> tuple:
    """
    Legacy shape function for backward compatibility.
    Updated to avoid hexagon syntax conflicts.
    """
    shapes = {
        'Database': ('[(', ')]'),
        'WebClient': ('(', ')'),  # Changed from hexagon to rounded rectangle
        'Mobile App': ('(', ')'),  # Changed from hexagon to rounded rectangle
        'API Gateway': ('([', '])'),
        'Load Balancer': ('([', '])'),
        'CDN': ('([', '])'),
        'Service': ('[', ']'),
        'Payment Processor': ('[[', ']]'),
        'Email Service': ('[[', ']]'),
        'SMS Service': ('[[', ']]'),
        'Shipping API': ('[[', ']]'),
        'Object Storage': ('[(', ')]'),
        'Queue': ('>', ']'),
        'Identity Provider': ('([', '])'),
        'Monitoring': ('[/', '\\]'),
        'Backup': ('[/', '\\]'),
        'VPN': ('([', '])'),
        'Bastion': ('[', ']'),
        'Data Warehouse': ('[(', ')]'),
    }
    
    if data.get('external', False):
        return ('[[', ']]')
    
    return shapes.get(node_type, ('[', ']'))

def _get_node_layer(node_id: str, layers: Dict) -> str:
    """Determine which layer a node belongs to."""
    for layer_name, nodes in layers.items():
        if any(n[0] == node_id for n in nodes):
            return layer_name
    return 'services'  # Default

def _apply_stride_colors(graph: nx.DiGraph, threats: List, stride_colors: Dict) -> Dict[str, str]:
    """
    Apply STRIDE color coding to nodes based on threats.
    Returns dict of node_id -> color.
    """
    node_colors = {}
    stride_color_map = stride_colors.get('STRIDE_COLORS', {})
    
    # Count threats per component by STRIDE category
    component_threats = {}
    for threat in threats:
        for comp in threat.affected_components:
            if comp not in component_threats:
                component_threats[comp] = []
            stride_cat = threat.stride_category or threat.category
            component_threats[comp].append(stride_cat)
    
    # Assign color based on most severe STRIDE category
    severity_order = ['Elevation of Privilege', 'Information Disclosure', 'Denial of Service', 
                     'Tampering', 'Repudiation', 'Spoofing']
    
    for comp, threat_cats in component_threats.items():
        # Find highest severity category
        for sev_cat in severity_order:
            if sev_cat in threat_cats:
                color_data = stride_color_map.get(sev_cat, {})
                node_colors[comp] = color_data.get('color', '#FF6B6B')
                break
    
    return node_colors

def _generate_legend(stride_colors: Dict) -> List[str]:
    """Generate diagram legend explaining symbols and colors."""
    legend = []
    
    legend.append("\n    %% Legend")
    legend.append("    %% DFD Elements:")
    legend.append("    %% E#: = External Entity")
    legend.append("    %% #.0: = Process")
    legend.append("    %% D#: = Data Store")
    legend.append("    %% --> = Data Flow")
    legend.append("    %% ==> = Trust Boundary Crossing")
    
    legend.append("\n    %% STRIDE Color Coding:")
    stride_color_map = stride_colors.get('STRIDE_COLORS', {})
    for category, data in stride_color_map.items():
        icon = data.get('icon', '')
        color = data.get('color', '')
        desc = data.get('description', '')
        legend.append(f"    %% {icon} {category}: {desc} ({color})")
    
    legend.append("\n    %% Trust Boundaries:")
    legend.append("    %% Red (External/Untrusted)")
    legend.append("    %% Yellow (DMZ/Semi-trusted)")
    legend.append("    %% Green (Internal/Trusted)")
    
    return legend

def _generate_class_definitions() -> List[str]:
    """Generate classDef styling for different component types."""
    class_defs = []
    
    class_defs.append("\n    %% Component Type Styling")
    
    # External entities - red/orange for untrusted
    class_defs.append("    classDef externalClass fill:#ffccbc,stroke:#d84315,stroke-width:3px,color:#000")
    
    # Client applications - light blue
    class_defs.append("    classDef clientClass fill:#bbdefb,stroke:#1976d2,stroke-width:2px,color:#000")
    
    # API Gateway/Load Balancer - yellow/gold for DMZ
    class_defs.append("    classDef gatewayClass fill:#fff9c4,stroke:#f57f17,stroke-width:2px,color:#000")
    
    # Processes/Services - purple for internal services
    class_defs.append("    classDef processClass fill:#e1bee7,stroke:#7b1fa2,stroke-width:2px,color:#000")
    
    # Data stores - green for trusted data layer
    class_defs.append("    classDef datastoreClass fill:#c8e6c9,stroke:#388e3c,stroke-width:3px,color:#000")
    
    return class_defs
