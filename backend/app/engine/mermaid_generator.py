import networkx as nx
from typing import Dict, List, Set

def generate_mermaid(graph: nx.DiGraph) -> str:
    """
    Converts a NetworkX graph to an enhanced Mermaid flowchart with layered grouping.
    Groups components by layer: Frontend, API Layer, Services, Data Layer, External.
    """
    mermaid_lines = ["graph TB"]  # Top to Bottom for better layering
    
    # Categorize nodes by layer
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
            # Default to services
            layers['services'].append((node, data))
    
    # Generate subgraphs for each layer
    layer_configs = [
        ('frontend', 'Frontend Layer', 'fill:#e1f5ff,stroke:#01579b'),
        ('api_layer', 'API Layer', 'fill:#fff9c4,stroke:#f57f17'),
        ('services', 'Service Layer', 'fill:#f3e5f5,stroke:#4a148c'),
        ('data_layer', 'Data Layer', 'fill:#e8f5e9,stroke:#1b5e20'),
        ('external', 'External Services', 'fill:#ffebee,stroke:#b71c1c')
    ]
    
    subgraph_counter = 0
    for layer_key, layer_name, style in layer_configs:
        nodes = layers[layer_key]
        if not nodes:
            continue
        
        # Create subgraph
        mermaid_lines.append(f"    subgraph {layer_key}[\"{layer_name}\"]")
        
        for node, data in nodes:
            node_id = _sanitize_id(node)
            label = data.get('label', node)
            node_type = data.get('type', 'Service')
            
            # Choose shape based on type
            shape = _get_node_shape(node_type, data)
            mermaid_lines.append(f"        {node_id}{shape[0]}{label}{shape[1]}")
        
        mermaid_lines.append(f"    end")
        mermaid_lines.append(f"    style {layer_key} {style}")
        subgraph_counter += 1
    
    # Add edges with better styling
    for u, v, data in graph.edges(data=True):
        u_id = _sanitize_id(u)
        v_id = _sanitize_id(v)
        
        protocol = data.get('protocol', '')
        crosses_boundary = data.get('crosses_trust_boundary', False)
        
        # Style edges differently for trust boundary crossings
        if crosses_boundary:
            arrow = f"-.{protocol}.->"
        elif protocol:
            arrow = f"--{protocol}-->"
        else:
            arrow = "-->"
            
        mermaid_lines.append(f"    {u_id} {arrow} {v_id}")

    return "\n".join(mermaid_lines)

def _sanitize_id(node_id: str) -> str:
    """Sanitize node ID for Mermaid syntax."""
    return node_id.replace("-", "_").replace(" ", "_").replace(".", "_")

def _get_node_shape(node_type: str, data: Dict) -> tuple:
    """
    Get Mermaid shape syntax for a node based on its type.
    Returns (start, end) tuple for the shape.
    """
    # Shape mappings
    shapes = {
        'Database': ('[(', ')]'),           # Cylindrical database shape
        'WebClient': ('{{', '}}'),          # Hexagon for clients
        'Mobile App': ('{{', '}}'),         # Hexagon for mobile
        'API Gateway': ('([', '])'),        # Stadium shape
        'Load Balancer': ('([', '])'),      # Stadium shape
        'CDN': ('([', '])'),                # Stadium shape
        'Service': ('[', ']'),              # Rectangle for services
        'Payment Processor': ('[[', ']]'),  # Subroutine for external
        'Email Service': ('[[', ']]'),      # Subroutine for external
        'SMS Service': ('[[', ']]'),        # Subroutine for external
        'Shipping API': ('[[', ']]'),       # Subroutine for external
        'Object Storage': ('[(', ')]'),     # Database-like
        'Queue': ('>', ']'),                # Asymmetric for queues
        'Identity Provider': ('([', '])'),  # Stadium
        'Monitoring': ('[/', '\\]'),        # Parallelogram
        'Backup': ('[/', '\\]'),            # Parallelogram
        'VPN': ('([', '])'),                # Stadium
        'Bastion': ('[', ']'),              # Rectangle
        'Data Warehouse': ('[(', ')]'),     # Database-like
    }
    
    # Check if external
    if data.get('external', False):
        return ('[[', ']]')  # Subroutine shape for all external services
    
    return shapes.get(node_type, ('[', ']'))  # Default to rectangle

