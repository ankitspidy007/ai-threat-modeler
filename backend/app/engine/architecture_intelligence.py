"""
Architecture Intelligence — Infers missing components and detects
anti-patterns from parsed architecture graphs.

Uses NetworkX graph algorithms to:
1. Detect structural security gaps (missing LB, WAF, logging, etc.)
2. Identify anti-patterns (direct DB exposure, SPOFs, missing boundaries)
3. Generate actionable insights with severity and recommendations
"""

import logging
from typing import List, Dict, Optional, Set, Tuple
from collections import defaultdict

try:
    import networkx as nx
    NX_AVAILABLE = True
except ImportError:
    NX_AVAILABLE = False

logger = logging.getLogger(__name__)


class ArchitectureInsight:
    """A single architecture insight/recommendation."""
    
    def __init__(self, insight_type: str, severity: str, title: str,
                 description: str, recommendation: str,
                 affected_components: List[str] = None,
                 category: str = "Architecture"):
        self.type = insight_type  # "missing_component", "anti_pattern", "recommendation"
        self.severity = severity  # Critical, High, Medium, Low
        self.title = title
        self.description = description
        self.recommendation = recommendation
        self.affected_components = affected_components or []
        self.category = category
    
    def to_dict(self) -> Dict:
        return {
            "type": self.type,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "recommendation": self.recommendation,
            "affected_components": self.affected_components,
            "category": self.category,
        }


# ============================================================
# INFERENCE RULES — What components SHOULD exist given the graph
# ============================================================

COMPONENT_INFERENCE_RULES = [
    {
        "id": "missing_load_balancer",
        "title": "Missing Load Balancer",
        "condition": lambda g, nodes: (
            _has_type(nodes, {"Web Server", "API", "Service", "Microservice"}, min_count=2) and
            not _has_type(nodes, {"Load Balancer", "LB", "ALB", "NLB", "ELB"})
        ),
        "severity": "High",
        "description": "Multiple service instances detected but no load balancer. "
                       "This creates a single point of failure and limits scalability.",
        "recommendation": "Add a load balancer (e.g., AWS ALB, Nginx, HAProxy) in front of service instances.",
        "category": "Availability",
    },
    {
        "id": "missing_waf",
        "title": "Missing Web Application Firewall",
        "condition": lambda g, nodes: (
            _has_internet_facing(nodes) and
            not _has_type(nodes, {"WAF", "Web Application Firewall", "CloudFront", "CDN"})
        ),
        "severity": "High",
        "description": "Internet-facing components detected without a WAF. "
                       "This exposes the application to common web attacks (XSS, SQLi, etc.).",
        "recommendation": "Deploy a WAF (e.g., AWS WAF, Cloudflare, ModSecurity) in front of public endpoints.",
        "category": "Security",
    },
    {
        "id": "missing_api_gateway",
        "title": "Missing API Gateway",
        "condition": lambda g, nodes: (
            _has_type(nodes, {"Microservice", "Service"}, min_count=2) and
            not _has_type(nodes, {"API Gateway", "Gateway", "Kong", "Zuul", "Ambassador"})
        ),
        "severity": "Medium",
        "description": "Multiple microservices detected without an API gateway. "
                       "This complicates rate limiting, auth, and routing.",
        "recommendation": "Add an API gateway (e.g., Kong, AWS API Gateway, Zuul) for centralized traffic management.",
        "category": "Architecture",
    },
    {
        "id": "missing_logging",
        "title": "Missing Centralized Logging",
        "condition": lambda g, nodes: (
            len([n for n in nodes if nodes[n].get('type', '') not in ('Logger', 'Logging', 'ELK', 'CloudWatch')]) > 3 and
            not _has_type(nodes, {"Logger", "Logging", "ELK", "CloudWatch", "Datadog", "Splunk", "Log Aggregator"})
        ),
        "severity": "Medium",
        "description": "No centralized logging component detected. Without logging, "
                       "security incidents and operational issues are harder to detect and investigate.",
        "recommendation": "Add centralized logging (e.g., ELK Stack, AWS CloudWatch, Datadog) for monitoring and incident response.",
        "category": "Observability",
    },
    {
        "id": "missing_cache",
        "title": "Missing Cache Layer",
        "condition": lambda g, nodes: (
            _has_type(nodes, {"Database", "DB", "Data Store", "PostgreSQL", "MySQL", "MongoDB"}) and
            _has_type(nodes, {"API", "Service", "Web Server"}, min_count=2) and
            not _has_type(nodes, {"Cache", "Redis", "Memcached", "ElastiCache", "CDN"})
        ),
        "severity": "Low",
        "description": "Database access without a cache layer. This can lead to "
                       "performance bottlenecks and increased database load.",
        "recommendation": "Consider adding a cache layer (e.g., Redis, Memcached) to reduce database load.",
        "category": "Performance",
    },
    {
        "id": "missing_monitoring",
        "title": "Missing Monitoring/Alerting",
        "condition": lambda g, nodes: (
            len(nodes) > 4 and
            not _has_type(nodes, {"Monitor", "Monitoring", "Prometheus", "Grafana", "Datadog", "CloudWatch", "APM"})
        ),
        "severity": "Medium",
        "description": "No monitoring or alerting system detected. Security breaches "
                       "and service degradation may go unnoticed.",
        "recommendation": "Add monitoring (e.g., Prometheus + Grafana, Datadog) with security alerting.",
        "category": "Observability",
    },
    {
        "id": "missing_secrets_management",
        "title": "Missing Secrets Management",
        "condition": lambda g, nodes: (
            _has_type(nodes, {"Database", "DB", "API", "Service"}, min_count=2) and
            not _has_type(nodes, {"Vault", "Secrets Manager", "KMS", "Key Management", "HSM"})
        ),
        "severity": "Medium",
        "description": "No dedicated secrets management system detected. API keys, "
                       "database credentials, and tokens may be hardcoded or stored insecurely.",
        "recommendation": "Use a secrets manager (e.g., HashiCorp Vault, AWS Secrets Manager) for credential management.",
        "category": "Security",
    },
]


# ============================================================
# ANTI-PATTERN DETECTION — Graph-based structural analysis
# ============================================================

class ArchitectureIntelligence:
    """
    Analyzes architecture graph for missing components and anti-patterns.
    """
    
    def __init__(self):
        self._insights: List[ArchitectureInsight] = []
    
    def analyze(self, graph, architecture=None) -> List[ArchitectureInsight]:
        """
        Run all analysis on the architecture graph.
        
        Args:
            graph: NetworkX DiGraph from GraphBuilder
            architecture: Optional SystemArchitecture for metadata
            
        Returns:
            List of ArchitectureInsight objects
        """
        if not NX_AVAILABLE or graph is None:
            return []
        
        self._insights = []
        nodes = dict(graph.nodes(data=True))
        
        # 1. Infer missing components
        self._check_missing_components(graph, nodes)
        
        # 2. Detect anti-patterns
        self._detect_direct_db_exposure(graph, nodes)
        self._detect_single_point_of_failure(graph, nodes)
        self._detect_missing_trust_boundaries(graph, nodes)
        self._detect_unprotected_external_access(graph, nodes)
        self._detect_circular_dependencies(graph, nodes)
        
        logger.info(f"Architecture intelligence: {len(self._insights)} insights found")
        return self._insights
    
    def get_insights_dict(self) -> List[Dict]:
        """Return insights as serializable dicts."""
        return [i.to_dict() for i in self._insights]
    
    def get_summary(self) -> Dict:
        """Get summary grouped by severity."""
        summary = {"total": len(self._insights), "by_severity": {}, "by_category": {}}
        for insight in self._insights:
            summary["by_severity"][insight.severity] = summary["by_severity"].get(insight.severity, 0) + 1
            summary["by_category"][insight.category] = summary["by_category"].get(insight.category, 0) + 1
        return summary
    
    # ---- Missing Component Inference ----
    
    def _check_missing_components(self, graph, nodes: Dict):
        """Check all inference rules."""
        for rule in COMPONENT_INFERENCE_RULES:
            try:
                if rule["condition"](graph, nodes):
                    self._insights.append(ArchitectureInsight(
                        insight_type="missing_component",
                        severity=rule["severity"],
                        title=rule["title"],
                        description=rule["description"],
                        recommendation=rule["recommendation"],
                        category=rule.get("category", "Architecture"),
                    ))
            except Exception as e:
                logger.debug(f"Rule {rule['id']} failed: {e}")
    
    # ---- Anti-Pattern: Direct Database Exposure ----
    
    def _detect_direct_db_exposure(self, graph, nodes: Dict):
        """Detect if internet-facing components connect directly to databases."""
        db_types = {"Database", "DB", "Data Store", "PostgreSQL", "MySQL", 
                    "MongoDB", "DynamoDB", "RDS", "Aurora"}
        
        for node_id, data in nodes.items():
            if not _is_internet_facing(data):
                continue
            
            # Check if this internet-facing node has direct edges to databases
            for successor in graph.successors(node_id):
                succ_type = nodes.get(successor, {}).get('type', '')
                if succ_type in db_types or any(db.lower() in succ_type.lower() for db in db_types):
                    self._insights.append(ArchitectureInsight(
                        insight_type="anti_pattern",
                        severity="Critical",
                        title="Direct Database Access from Internet",
                        description=f"Internet-facing component '{data.get('label', node_id)}' "
                                    f"has direct access to database '{nodes.get(successor, {}).get('label', successor)}'. "
                                    f"This bypasses application-level security controls.",
                        recommendation="Add an API/service layer between internet-facing components and databases. "
                                       "Never expose databases directly to the internet.",
                        affected_components=[node_id, successor],
                        category="Security",
                    ))
    
    # ---- Anti-Pattern: Single Point of Failure ----
    
    def _detect_single_point_of_failure(self, graph, nodes: Dict):
        """Detect nodes with high betweenness centrality (critical chokepoints)."""
        if graph.number_of_nodes() < 3:
            return
        
        try:
            centrality = nx.betweenness_centrality(graph)
            threshold = 0.5  # Nodes carrying >50% of shortest paths
            
            for node_id, score in centrality.items():
                if score >= threshold:
                    data = nodes.get(node_id, {})
                    node_type = data.get('type', 'Unknown')
                    
                    # Skip if it's an expected bottleneck (like API Gateway)
                    if node_type in ('API Gateway', 'Gateway', 'Load Balancer', 'LB'):
                        continue
                    
                    self._insights.append(ArchitectureInsight(
                        insight_type="anti_pattern",
                        severity="High",
                        title=f"Single Point of Failure: {data.get('label', node_id)}",
                        description=f"Component '{data.get('label', node_id)}' ({node_type}) has very high "
                                    f"betweenness centrality ({score:.0%}), meaning most data flows "
                                    f"pass through it. If this component fails, the entire system is affected.",
                        recommendation="Consider adding redundancy (load balancing, replication) or "
                                       "re-architecting to reduce dependency on this single component.",
                        affected_components=[node_id],
                        category="Availability",
                    ))
        except Exception as e:
            logger.debug(f"Centrality analysis failed: {e}")
    
    # ---- Anti-Pattern: Missing Trust Boundaries ----
    
    def _detect_missing_trust_boundaries(self, graph, nodes: Dict):
        """Detect when internet-facing and internal components are in the same trust zone."""
        internet_facing = set()
        has_db = False
        
        for node_id, data in nodes.items():
            if _is_internet_facing(data):
                internet_facing.add(node_id)
            if data.get('type', '') in ('Database', 'DB', 'Data Store'):
                has_db = True
        
        if internet_facing and has_db:
            # Check if any component has trust_boundary metadata
            has_boundary = any(
                data.get('trust_boundary') or data.get('zone') or data.get('trust_level')
                for data in nodes.values()
            )
            
            if not has_boundary:
                self._insights.append(ArchitectureInsight(
                    insight_type="anti_pattern",
                    severity="Medium",
                    title="No Trust Boundaries Defined",
                    description="Architecture has internet-facing and database components "
                                "but no explicit trust boundaries. This makes it unclear "
                                "which network segments are isolated.",
                    recommendation="Define trust boundaries (DMZ, private subnet, data layer) "
                                   "and ensure proper network segmentation.",
                    affected_components=list(internet_facing),
                    category="Security",
                ))
    
    # ---- Anti-Pattern: External Services Without Gateway ----
    
    def _detect_unprotected_external_access(self, graph, nodes: Dict):
        """Detect internal services making direct external calls without a gateway."""
        external_types = {"External Service", "External API", "Third Party", "SaaS"}
        has_gateway = _has_type(nodes, {"API Gateway", "Gateway"})
        
        if has_gateway:
            return  # Gateway exists, so external calls are likely routed through it
        
        external_nodes = []
        for node_id, data in nodes.items():
            node_type = data.get('type', '')
            if node_type in external_types or data.get('external', False):
                external_nodes.append(node_id)
        
        if len(external_nodes) >= 2:
            self._insights.append(ArchitectureInsight(
                insight_type="recommendation",
                severity="Medium",
                title="External Services Without Centralized Gateway",
                description=f"{len(external_nodes)} external service integrations detected "
                            f"without a centralized gateway. Each integration point is a "
                            f"potential attack surface.",
                recommendation="Route external API calls through a gateway or service mesh "
                               "for centralized authentication, rate limiting, and monitoring.",
                affected_components=external_nodes,
                category="Architecture",
            ))
    
    # ---- Anti-Pattern: Circular Dependencies ----
    
    def _detect_circular_dependencies(self, graph, nodes: Dict):
        """Detect circular dependencies in the architecture."""
        try:
            cycles = list(nx.simple_cycles(graph))
            if cycles:
                # Only report the longest cycle
                longest = max(cycles, key=len)
                if len(longest) >= 3:
                    cycle_names = [nodes.get(n, {}).get('label', n) for n in longest]
                    self._insights.append(ArchitectureInsight(
                        insight_type="anti_pattern",
                        severity="Medium",
                        title="Circular Dependency Detected",
                        description=f"Circular dependency found: {' → '.join(cycle_names)} → {cycle_names[0]}. "
                                    f"This can cause cascading failures and makes the system harder to maintain.",
                        recommendation="Break the circular dependency by introducing an event bus, "
                                       "message queue, or restructuring the service boundaries.",
                        affected_components=list(longest),
                        category="Architecture",
                    ))
        except Exception as e:
            logger.debug(f"Cycle detection failed: {e}")


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def _has_type(nodes: Dict, type_set: Set[str], min_count: int = 1) -> bool:
    """Check if any node matches the given type set."""
    count = 0
    for data in nodes.values():
        node_type = data.get('type', '')
        name = data.get('label', data.get('name', ''))
        if (node_type in type_set or 
            any(t.lower() in node_type.lower() for t in type_set) or
            any(t.lower() in name.lower() for t in type_set)):
            count += 1
            if count >= min_count:
                return True
    return False


def _has_internet_facing(nodes: Dict) -> bool:
    """Check if any node is internet-facing."""
    return any(_is_internet_facing(data) for data in nodes.values())


def _is_internet_facing(data: Dict) -> bool:
    """Check if a single node is internet-facing."""
    indicators = [
        data.get('public_access', False),
        data.get('internet_facing', False),
        data.get('trust_boundary') in ('internet', 'public', 'dmz'),
        data.get('trust_level') in ('public', 'external'),
        data.get('type', '') in ('Web Server', 'CDN', 'Load Balancer', 'WAF',
                                  'Web Application', 'Frontend', 'SPA', 'Client'),
    ]
    return any(indicators)
