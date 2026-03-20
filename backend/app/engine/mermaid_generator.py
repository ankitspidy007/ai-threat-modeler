import re
import networkx as nx
from typing import List, Dict, Set
import json
import os

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
    if not enhanced:
        # Fallback to basic generation for backward compatibility
        return _generate_basic_mermaid(graph)
    
    mermaid_lines = ["graph TB"]  # Top to Bottom for better layering
    
    # Load STRIDE colors
    stride_colors = _load_stride_colors()
    
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
        ('external', 'External / Untrusted Zone', 'fill:#ffebee,stroke:#b71c1c,stroke-width:3px,stroke-dasharray: 5 5'),
        ('frontend', 'Frontend Layer / DMZ', 'fill:#e1f5ff,stroke:#01579b,stroke-width:2px'),
        ('api_layer', 'API Layer / DMZ', 'fill:#fff9c4,stroke:#f57f17,stroke-width:2px'),
        ('services', 'Service Layer / Internal', 'fill:#f3e5f5,stroke:#4a148c,stroke-width:2px'),
        ('data_layer', 'Data Layer / Trusted', 'fill:#e8f5e9,stroke:#1b5e20,stroke-width:3px'),
    ]
    
    for layer_key, layer_name, style in layer_configs:
        nodes = layers[layer_key]
        if not nodes:
            continue
        
        # Create subgraph with trust boundary annotation
        mermaid_lines.append(f"    subgraph zone_{layer_key}[\"{layer_name}\"]")
        
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
    
    
    # Add edges with enhanced labels including protocol, auth, and data type
    for u, v, data in graph.edges(data=True):
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
        flow_label = _sanitize_edge_label(flow_label)
        
        # Style edges differently for trust boundary crossings
        if crosses_boundary:
            arrow = f"==>|{flow_label}|" if flow_label else "==>"
        else:
            arrow = f"-->|{flow_label}|" if flow_label else "-->"

        mermaid_lines.append(f"    {u_id} {arrow} {v_id}")
    
    
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
        with open(file_path, 'r') as f:
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
