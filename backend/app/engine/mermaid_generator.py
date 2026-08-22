"""
Renders the architecture graph as a data flow diagram in Mermaid syntax.

A threat model cannot be reviewed against a diagram that quietly leaves parts
of the system out, so every component and flow in the model is drawn. Where a
graph is too large to stay legible the diagram keeps the highest-signal
elements, draws a marker for the remainder in each zone, and states the counts
in a comment, so a reader can always tell whether they are looking at the whole
system. Components carrying a confirmed finding are outlined so the diagram and
the finding list agree.
"""

import re
from typing import Any, Dict, List, Set, Tuple

import networkx as nx


LOW_SIGNAL_COMPONENT_LABELS = {
    'api', 'cdn', 'database', 'frontend', 'identity provider', 'ml service',
    'monitoring', 'queue', 'service', 'spa', 'webclient',
}

DFD_ZONE_ORDER = ('external', 'public', 'application', 'data', 'third_party')
DFD_ZONE_TITLES = {
    'external': 'External Entity',
    'public': 'Internet / Client Boundary',
    'application': 'Application Trust Boundary',
    'data': 'Data Trust Boundary',
    'third_party': 'Third-Party Trust Boundary',
}
# A data flow diagram describes how data moves. Observability and backup
# components do not participate in the modelled flows, so they are left out of
# the drawing and counted as excluded rather than dropped without trace.
DFD_NON_FLOW_COMPONENTS = {'Threat Detection', 'Monitoring', 'Backup'}

# Beyond these the rendered diagram stops being readable. They are deliberately
# far above the size of an ordinary architecture description so that trimming is
# the exception rather than the normal path.
DIAGRAM_NODE_BUDGET = 40
DIAGRAM_EDGE_BUDGET = 60


def _threat_field(threat: Any, name: str, default: Any = None) -> Any:
    if isinstance(threat, dict):
        return threat.get(name, default)
    return getattr(threat, name, default)


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
    """Order nodes so that trimming removes the least informative ones first."""
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
        return ('[', ']')                  # DFD external entity
    if node_type in {'Database', 'Object Storage', 'Queue', 'Data Warehouse', 'Secrets Manager'}:
        return ('[(', ')]')                # DFD data store
    return ('((', '))')                    # DFD process


def _partition_by_zone(graph: nx.DiGraph) -> Tuple[Dict[str, List[tuple]], List[str]]:
    zones: Dict[str, List[tuple]] = {zone: [] for zone in DFD_ZONE_ORDER}
    excluded: List[str] = []
    for node, data in graph.nodes(data=True):
        if data.get('type') in DFD_NON_FLOW_COMPONENTS:
            excluded.append(node)
            continue
        zones[_dfd_zone(data)].append((node, data))
    for zone, nodes in zones.items():
        nodes.sort(key=lambda item: _dfd_node_priority(graph, item[0], item[1]))
    return zones, excluded


def _select_visible(graph: nx.DiGraph) -> Tuple[Dict[str, List[tuple]], Dict[str, int], List[str]]:
    """Choose what to draw, keeping the whole model unless it cannot fit."""
    zones, excluded = _partition_by_zone(graph)
    total = sum(len(nodes) for nodes in zones.values())
    if total <= DIAGRAM_NODE_BUDGET:
        return zones, {zone: 0 for zone in zones}, excluded

    # Take turns across zones so that trimming a large graph does not empty a
    # whole trust boundary and hide a boundary crossing.
    visible: Dict[str, List[tuple]] = {zone: [] for zone in DFD_ZONE_ORDER}
    remaining = DIAGRAM_NODE_BUDGET
    while remaining > 0 and any(len(visible[zone]) < len(zones[zone]) for zone in DFD_ZONE_ORDER):
        for zone in DFD_ZONE_ORDER:
            if remaining <= 0:
                break
            if len(visible[zone]) < len(zones[zone]):
                visible[zone].append(zones[zone][len(visible[zone])])
                remaining -= 1
    hidden = {zone: len(zones[zone]) - len(visible[zone]) for zone in DFD_ZONE_ORDER}
    return visible, hidden, excluded


def _select_edges(graph: nx.DiGraph, visible_nodes: Set[str]) -> Tuple[List[tuple], int]:
    """Keep boundary crossings and stated flows ahead of inferred internal ones."""
    edges = [
        (source, target, data) for source, target, data in graph.edges(data=True)
        if source in visible_nodes and target in visible_nodes
    ]
    if len(edges) <= DIAGRAM_EDGE_BUDGET:
        return edges, 0

    def edge_priority(edge: tuple) -> tuple:
        source, target, data = edge
        crossing = _dfd_zone(graph.nodes[source]) != _dfd_zone(graph.nodes[target])
        return (not crossing, bool(data.get('assumed')), str(source), str(target))

    ordered = sorted(edges, key=edge_priority)
    return ordered[:DIAGRAM_EDGE_BUDGET], len(edges) - DIAGRAM_EDGE_BUDGET


def _components_with_confirmed_findings(threats: List[Any]) -> Set[str]:
    flagged: Set[str] = set()
    for threat in threats or []:
        if str(_threat_field(threat, 'tier') or '') != 'Confirmed':
            continue
        for component in (_threat_field(threat, 'affected_components') or []):
            flagged.add(str(component))
        primary = _threat_field(threat, 'affected_component')
        if primary:
            flagged.add(str(primary))
    return flagged


def diagram_coverage(graph: nx.DiGraph, threats: List[Any] = None) -> Dict[str, Any]:
    """Report what the diagram shows against what the model holds."""
    visible_by_zone, hidden, excluded = _select_visible(graph)
    visible_nodes = {node for nodes in visible_by_zone.values() for node, _ in nodes}
    _, omitted_edges = _select_edges(graph, visible_nodes)
    drawn_edges = sum(
        1 for source, target in graph.edges()
        if source in visible_nodes and target in visible_nodes
    ) - omitted_edges
    hidden_total = sum(hidden.values())
    return {
        'components_in_model': graph.number_of_nodes(),
        'components_drawn': len(visible_nodes),
        'components_hidden_for_readability': hidden_total,
        'components_excluded_as_non_flow': len(excluded),
        'excluded_component_ids': sorted(excluded),
        'flows_in_model': graph.number_of_edges(),
        'flows_drawn': max(0, drawn_edges),
        'flows_hidden_for_readability': omitted_edges,
        'complete': hidden_total == 0 and omitted_edges == 0,
        'components_with_confirmed_findings': len(
            _components_with_confirmed_findings(threats) & visible_nodes
        ),
    }


def generate_mermaid(graph: nx.DiGraph, threats: List = None, enhanced: bool = True) -> str:
    """Render the model as a DFD with trust boundaries and finding overlay.

    `enhanced` is retained for callers; the diagram always uses DFD notation.
    """
    visible_by_zone, hidden, excluded = _select_visible(graph)
    visible_nodes = {node for nodes in visible_by_zone.values() for node, _ in nodes}
    edges, omitted_edges = _select_edges(graph, visible_nodes)
    flagged = _components_with_confirmed_findings(threats) & visible_nodes

    entity_number = process_number = datastore_number = 1
    number_by_node: Dict[str, str] = {}
    for zone in DFD_ZONE_ORDER:
        for node, data in visible_by_zone[zone]:
            if data.get('external', False) or data.get('type') == 'Identity Provider':
                number_by_node[node] = f'E{entity_number}'
                entity_number += 1
            elif zone == 'data':
                number_by_node[node] = f'D{datastore_number}'
                datastore_number += 1
            else:
                number_by_node[node] = f'{process_number}.0'
                process_number += 1

    lines = [
        "%%{init: {'flowchart': {'htmlLabels': true, 'nodeSpacing': 32, 'rankSpacing': 64, 'curve': 'linear'}} }%%",
        'flowchart TB',
        '    %% DFD notation: E# external entity, #.0 process, D# data store',
        f'    %% Coverage: {len(visible_nodes)} of {graph.number_of_nodes()} components '
        f'and {len(edges)} of {graph.number_of_edges()} flows drawn',
    ]
    if excluded:
        lines.append(
            f'    %% Excluded as not part of a data flow: {", ".join(sorted(excluded))}'
        )
    if omitted_edges:
        lines.append(f'    %% {omitted_edges} further flows are not drawn for readability')
    if flagged:
        lines.append('    %% Bold red outline marks a component with a confirmed finding')

    for zone in DFD_ZONE_ORDER:
        nodes = visible_by_zone[zone]
        if not nodes:
            continue
        zone_id = f'dfd_{zone}'
        lines.append(f'    subgraph {zone_id}["{DFD_ZONE_TITLES[zone]}"]')
        lines.append('        direction LR')
        for node, data in nodes:
            node_id = _sanitize_id(node)
            label = _dfd_node_label(data, number_by_node[node])
            lines.append(f'        {_format_node(node_id, label, _dfd_shape(data))}')
        if hidden.get(zone):
            count = hidden[zone]
            plural = 'component' if count == 1 else 'components'
            lines.append(f'        {zone_id}_more["+ {count} further {plural} in this zone"]')
        lines.append('    end')
        lines.append(f'    style {zone_id} fill:#ffffff,stroke:#404040,stroke-width:2px,stroke-dasharray: 7 4')

    assumed_drawn = False
    for source, target, data in edges:
        protocol = str(data.get('protocol') or '').upper()
        data_type = str(data.get('data_type') or '')
        label = protocol or 'data flow'
        if data_type in {'credentials', 'pii', 'financial', 'phi', 'secrets'}:
            label = f'{protocol} / {data_type}' if protocol else data_type
        # A flow nobody described is drawn dotted and labelled as an assumption,
        # so a reviewer can tell the model's guesses from the design's statements.
        if data.get('origin') == 'assumed':
            assumed_drawn = True
            label = f'{label} (assumed)'
            arrow = '-.->'
        elif _dfd_zone(graph.nodes[source]) != _dfd_zone(graph.nodes[target]):
            arrow = '==>'
        else:
            arrow = '-->'
        lines.append(f'    {_sanitize_id(source)} {arrow}|{_sanitize_edge_label(label)}| {_sanitize_id(target)}')
    if assumed_drawn:
        lines.insert(4, '    %% A dotted flow was assumed from component types, not described')

    lines.extend([
        '    classDef dfdEntity fill:#ffffff,stroke:#202020,stroke-width:2px,color:#111111',
        '    classDef dfdProcess fill:#ffffff,stroke:#202020,stroke-width:2px,color:#111111',
        '    classDef dfdStore fill:#ffffff,stroke:#202020,stroke-width:2px,color:#111111',
        '    classDef dfdFinding fill:#ffffff,stroke:#b91c1c,stroke-width:4px,color:#111111',
        '    classDef dfdMore fill:#f8fafc,stroke:#94a3b8,stroke-width:1px,color:#334155,stroke-dasharray: 4 3',
    ])
    for zone in DFD_ZONE_ORDER:
        if hidden.get(zone):
            lines.append(f'    class dfd_{zone}_more dfdMore')
    for node in visible_nodes:
        data = graph.nodes[node]
        if node in flagged:
            class_name = 'dfdFinding'
        elif data.get('external', False) or data.get('type') == 'Identity Provider':
            class_name = 'dfdEntity'
        elif _dfd_zone(data) == 'data':
            class_name = 'dfdStore'
        else:
            class_name = 'dfdProcess'
        lines.append(f'    class {_sanitize_id(node)} {class_name}')
    return '\n'.join(lines)


def _sanitize_id(node_id: str) -> str:
    """Sanitize a node identifier for Mermaid syntax."""
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
    return re.sub(r"\s+", " ", sanitized).strip()


def _sanitize_edge_label(label: str) -> str:
    """Render an edge label Mermaid will parse whatever text it carries.

    The label is quoted because an unquoted one is read as diagram syntax: a
    bracket in "HTTPS (assumed)" opens a node shape and the whole diagram fails
    to render.
    """
    text = _sanitize_label(label).replace('|', '/')
    return f'"{text}"'


def _format_node(node_id: str, label: str, shape: tuple) -> str:
    """Render a Mermaid node with a quoted label."""
    safe_label = _sanitize_label(label)
    shape_open, shape_close = shape
    return f'{node_id}{shape_open}"{safe_label}"{shape_close}'
