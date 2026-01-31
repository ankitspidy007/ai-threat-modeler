import networkx as nx

def generate_mermaid(graph: nx.DiGraph) -> str:
    """
    Converts a NetworkX graph to a Mermaid flowchart syntax string.
    """
    mermaid_lines = ["graph LR"]
    
    # Add nodes with specific shapes based on type
    for node, data in graph.nodes(data=True):
        node_id = node.replace("-", "_").replace(" ", "_") # Sanitize ID
        label = data.get('label', node)
        node_type = data.get('type', 'Service')
        
        # Mermaid shapes: [rect], ((circle)), [(database)], {{hexagon}}
        if node_type == 'Database':
            shape_start, shape_end = "[(", ")]"
        elif node_type == 'WebClient':
            shape_start, shape_end = "{{", "}}"
        elif node_type == 'API':
            shape_start, shape_end = "([", "])"
        else:
            shape_start, shape_end = "[", "]"
            
        mermaid_lines.append(f"    {node_id}{shape_start}{label}{shape_end}")

    # Add edges
    for u, v, data in graph.edges(data=True):
        u_id = u.replace("-", "_").replace(" ", "_")
        v_id = v.replace("-", "_").replace(" ", "_")
        
        protocol = data.get('protocol', '')
        if protocol:
            arrow = f"-- {protocol} -->"
        else:
            arrow = "-->"
            
        mermaid_lines.append(f"    {u_id} {arrow} {v_id}")

    return "\n".join(mermaid_lines)
