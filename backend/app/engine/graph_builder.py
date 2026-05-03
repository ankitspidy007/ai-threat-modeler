import networkx as nx
from ..models import SystemArchitecture, Component, DataFlow

class GraphBuilder:
    def __init__(self, architecture: SystemArchitecture):
        self.architecture = architecture
        self.graph = nx.DiGraph()
        self._build_graph()

    def _build_graph(self):
        # Add nodes
        for component in self.architecture.components:
            component_props = dict(component.properties or {})
            component_props.pop("trust_level", None)
            self.graph.add_node(
                component.id, 
                label=component.name,
                type=component.type,
                trust_level=component.trust_level,
                **component_props
            )

        # Add edges
        for flow in self.architecture.flows:
            flow_props = dict(flow.properties or {})
            flow_props.pop("assumed", None)
            self.graph.add_edge(
                flow.source_id,
                flow.target_id,
                protocol=flow.protocol,
                data_type=flow.data_type,
                assumed=flow.assumed,
                **flow_props
            )

    def get_graph(self) -> nx.DiGraph:
        return self.graph
    
    def get_components(self):
        return self.graph.nodes(data=True)
    
    def get_flows(self):
        return self.graph.edges(data=True)
