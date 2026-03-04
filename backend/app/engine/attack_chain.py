"""
Attack Chain Analyzer — Models threat relationships and computes attack paths.

Uses NetworkX (already a dependency) to:
1. Build a threat dependency graph from prerequisite_threats/related_threats
2. Score attack paths by cumulative risk
3. Identify critical chokepoints where a single mitigation blocks multiple chains
"""

import logging
from typing import List, Dict, Tuple, Optional, Set
from collections import defaultdict

try:
    import networkx as nx
    NX_AVAILABLE = True
except ImportError:
    NX_AVAILABLE = False

logger = logging.getLogger(__name__)


class AttackChainAnalyzer:
    """
    Analyzes relationships between threats to identify attack chains
    and critical mitigation points.
    """
    
    def __init__(self):
        self.threat_graph = nx.DiGraph() if NX_AVAILABLE else None
        self._threats_by_id: Dict[str, Dict] = {}
    
    def build_threat_graph(self, threats: List[Dict]):
        """
        Build a directed graph of threat relationships.
        
        Edges represent:
        - prerequisite_threats: threat A must exist for threat B
        - amplifies: threat A increases the impact of threat B
        - related_threats: general relationship
        """
        if not NX_AVAILABLE or not threats:
            return
        
        self.threat_graph.clear()
        self._threats_by_id.clear()
        
        # Index threats
        for threat in threats:
            tid = threat.get('threat_id', threat.get('id', ''))
            if tid:
                self._threats_by_id[tid] = threat
                self.threat_graph.add_node(tid, **{
                    'name': threat.get('threat_name', threat.get('threat', {}).get('title', tid)),
                    'severity': threat.get('impact', threat.get('risk', {}).get('severity', 'Medium')),
                    'category': threat.get('stride_category', threat.get('category', '')),
                    'component': threat.get('component', ''),
                })
        
        # Build edges from relationships
        for threat in threats:
            tid = threat.get('threat_id', threat.get('id', ''))
            if not tid:
                continue
            
            # Prerequisite threats (A → B means A enables B)
            prereqs = threat.get('prerequisite_threats', [])
            for prereq_id in prereqs:
                if prereq_id in self._threats_by_id:
                    self.threat_graph.add_edge(prereq_id, tid, 
                                              relationship='prerequisite',
                                              weight=3)
            
            # Amplification relationships
            related = threat.get('related_threats', {})
            amplifies = related.get('amplifies', [])
            for amp_id in amplifies:
                if amp_id in self._threats_by_id:
                    self.threat_graph.add_edge(tid, amp_id,
                                              relationship='amplifies',
                                              weight=2)
            
            # Mitigation relationships (reverse — B mitigates A)
            mitigates = related.get('mitigates', [])
            for mit_id in mitigates:
                if mit_id in self._threats_by_id:
                    self.threat_graph.add_edge(tid, mit_id,
                                              relationship='mitigates',
                                              weight=-1)
        
        # Auto-infer relationships based on component and category
        self._infer_relationships()
        
        logger.info(f"Threat graph built: {self.threat_graph.number_of_nodes()} nodes, "
                    f"{self.threat_graph.number_of_edges()} edges")
    
    def _infer_relationships(self):
        """Infer relationships between threats based on categories and components."""
        if not NX_AVAILABLE:
            return
        
        # Group by component
        by_component = defaultdict(list)
        for tid, data in self.threat_graph.nodes(data=True):
            component = data.get('component', '')
            if component:
                by_component[component].append(tid)
        
        # Common attack patterns:
        # Spoofing → Information Disclosure (identity theft leads to data access)
        # Spoofing → Elevation of Privilege (fake identity → admin access)
        # Tampering → Information Disclosure (modify data → extract info)
        # Elevation of Privilege → Tampering (admin → modify anything)
        
        chain_patterns = [
            ('Spoofing', 'Information Disclosure', 'prerequisite', 1),
            ('Spoofing', 'Elevation of Privilege', 'prerequisite', 2),
            ('Tampering', 'Information Disclosure', 'amplifies', 1),
            ('Elevation of Privilege', 'Tampering', 'amplifies', 2),
            ('Information Disclosure', 'Spoofing', 'amplifies', 1),  # Leaked creds → spoofing
        ]
        
        for component, tids in by_component.items():
            for from_cat, to_cat, rel, weight in chain_patterns:
                from_threats = [t for t in tids if self.threat_graph.nodes[t].get('category') == from_cat]
                to_threats = [t for t in tids if self.threat_graph.nodes[t].get('category') == to_cat]
                
                for ft in from_threats[:2]:  # Limit to prevent explosion
                    for tt in to_threats[:2]:
                        if ft != tt and not self.threat_graph.has_edge(ft, tt):
                            self.threat_graph.add_edge(ft, tt,
                                                      relationship=rel,
                                                      weight=weight,
                                                      inferred=True)
    
    def find_attack_chains(self, max_length: int = 5) -> List[List[str]]:
        """
        Find all attack chains (paths) in the threat graph.
        
        Returns:
            List of chains, where each chain is a list of threat IDs
        """
        if not NX_AVAILABLE or not self.threat_graph:
            return []
        
        chains = []
        
        # Find source nodes (threats with no prerequisites)
        source_nodes = [n for n in self.threat_graph.nodes()
                       if self.threat_graph.in_degree(n) == 0]
        
        # Find sink nodes (threats that don't enable anything else)
        sink_nodes = [n for n in self.threat_graph.nodes()
                     if self.threat_graph.out_degree(n) == 0]
        
        # If no clear sources/sinks, use all nodes
        if not source_nodes:
            source_nodes = list(self.threat_graph.nodes())[:10]
        if not sink_nodes:
            sink_nodes = list(self.threat_graph.nodes())
        
        # Find paths from sources to sinks
        for source in source_nodes:
            for sink in sink_nodes:
                if source == sink:
                    continue
                try:
                    for path in nx.all_simple_paths(self.threat_graph, source, sink, cutoff=max_length):
                        if len(path) >= 2:
                            chains.append(path)
                except nx.NetworkXError:
                    continue
        
        # Sort by chain length and risk score
        chains.sort(key=lambda c: self._score_chain(c), reverse=True)
        
        return chains[:20]  # Top 20 chains
    
    def _score_chain(self, chain: List[str]) -> float:
        """Score an attack chain by cumulative severity."""
        severity_scores = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}
        total = 0
        for tid in chain:
            if tid in self.threat_graph.nodes:
                sev = self.threat_graph.nodes[tid].get('severity', 'Medium')
                total += severity_scores.get(sev, 2)
        # Longer chains with high severity score higher
        return total * (1 + 0.1 * len(chain))
    
    def find_critical_chokepoints(self) -> List[Dict]:
        """
        Find threats that, if mitigated, would block the most attack chains.
        These are the high-value mitigation targets.
        
        Returns:
            List of {threat_id, name, chains_blocked, severity} sorted by impact
        """
        if not NX_AVAILABLE or not self.threat_graph:
            return []
        
        chains = self.find_attack_chains()
        if not chains:
            return []
        
        # Count how many chains each threat appears in
        threat_chain_count = defaultdict(set)
        for i, chain in enumerate(chains):
            for tid in chain:
                threat_chain_count[tid].add(i)
        
        chokepoints = []
        for tid, chain_indices in threat_chain_count.items():
            if tid in self.threat_graph.nodes:
                node_data = self.threat_graph.nodes[tid]
                chokepoints.append({
                    'threat_id': tid,
                    'name': node_data.get('name', tid),
                    'chains_blocked': len(chain_indices),
                    'severity': node_data.get('severity', 'Medium'),
                    'category': node_data.get('category', ''),
                    'component': node_data.get('component', ''),
                })
        
        # Sort by chains blocked (descending)
        chokepoints.sort(key=lambda x: x['chains_blocked'], reverse=True)
        
        return chokepoints[:10]
    
    def get_chain_details(self, chain: List[str]) -> List[Dict]:
        """
        Get detailed information about each step in an attack chain.
        """
        details = []
        for i, tid in enumerate(chain):
            info = {
                'step': i + 1,
                'threat_id': tid,
                'name': 'Unknown',
                'severity': 'Unknown',
                'category': 'Unknown',
            }
            
            if tid in self.threat_graph.nodes:
                node_data = self.threat_graph.nodes[tid]
                info.update({
                    'name': node_data.get('name', tid),
                    'severity': node_data.get('severity', 'Unknown'),
                    'category': node_data.get('category', 'Unknown'),
                    'component': node_data.get('component', ''),
                })
            
            if i > 0:
                prev_tid = chain[i - 1]
                edge_data = self.threat_graph.get_edge_data(prev_tid, tid, default={})
                info['relationship'] = edge_data.get('relationship', 'leads_to')
                info['inferred'] = edge_data.get('inferred', False)
            
            details.append(info)
        
        return details
    
    def get_summary(self) -> Dict:
        """Get summary statistics about the threat graph."""
        if not NX_AVAILABLE or not self.threat_graph:
            return {'nodes': 0, 'edges': 0, 'chains': 0, 'chokepoints': []}
        
        chains = self.find_attack_chains()
        chokepoints = self.find_critical_chokepoints()
        
        return {
            'nodes': self.threat_graph.number_of_nodes(),
            'edges': self.threat_graph.number_of_edges(),
            'chains': len(chains),
            'max_chain_length': max((len(c) for c in chains), default=0),
            'top_chokepoints': chokepoints[:5],
            'critical_chains': [
                {
                    'chain': chain,
                    'score': self._score_chain(chain),
                    'details': self.get_chain_details(chain)
                }
                for chain in chains[:5]
            ]
        }


class SeverityClassifier:
    """
    ML-enhanced severity classification.
    Uses embeddings to compare threat context against known severity patterns.
    Falls back to heuristic scoring when embeddings unavailable.
    """
    
    # Training examples for severity calibration
    SEVERITY_ANCHORS = {
        'Critical': [
            'Remote code execution vulnerability allowing full system compromise',
            'SQL injection in authentication endpoint leaking all user credentials',
            'Unencrypted storage of credit card numbers and PII data',
            'Missing authentication on admin API endpoints',
            'JWT signature bypass allowing token forgery',
        ],
        'High': [
            'Cross-site scripting allowing session hijacking',
            'Missing rate limiting on login endpoint enabling brute force',
            'Insecure direct object references exposing other users data',
            'Missing encryption at rest for sensitive database',
            'Third party API integration without certificate validation',
        ],
        'Medium': [
            'Missing audit logging for sensitive operations',
            'CORS misconfiguration allowing broader access than needed',
            'Session tokens with excessive validity period',
            'Missing content security policy headers',
            'Verbose error messages potentially revealing system internals',
        ],
        'Low': [
            'Missing HTTP security headers like X-Frame-Options',
            'Cookie without secure flag on HTTPS site',
            'Missing HSTS header on secure endpoints',
            'Information disclosure through server version headers',
            'Missing referrer policy configuration',
        ]
    }
    
    def __init__(self):
        self._embedding_service = None
        self._anchor_embeddings = {}
        self._initialized = False
    
    def _ensure_initialized(self):
        """Lazy initialization of embeddings."""
        if self._initialized:
            return
        
        try:
            from .embedding_service import get_embedding_service
            self._embedding_service = get_embedding_service()
            
            if self._embedding_service.is_available:
                # Pre-compute anchor embeddings
                for severity, examples in self.SEVERITY_ANCHORS.items():
                    embeddings = self._embedding_service.embed_batch(examples)
                    # Average embedding per severity level
                    import numpy as np
                    self._anchor_embeddings[severity] = np.mean(embeddings, axis=0)
                logger.info("Severity classifier initialized with embeddings")
            
        except Exception as e:
            logger.warning(f"Severity classifier falling back to heuristics: {e}")
        
        self._initialized = True
    
    def classify(self, threat_text: str, context: Dict = None) -> str:
        """
        Classify threat severity using ML when available, heuristics otherwise.
        
        Args:
            threat_text: Description of the threat
            context: Additional context (component type, data sensitivity, etc.)
            
        Returns:
            Severity string: 'Critical', 'High', 'Medium', or 'Low'
        """
        self._ensure_initialized()
        
        if self._embedding_service and self._embedding_service.is_available and self._anchor_embeddings:
            return self._classify_with_embeddings(threat_text, context)
        
        return self._classify_with_heuristics(threat_text, context)
    
    def _classify_with_embeddings(self, threat_text: str, context: Dict = None) -> str:
        """Classify using embedding similarity to severity anchors."""
        import numpy as np
        
        try:
            text_emb = self._embedding_service.embed(threat_text)
            
            best_severity = 'Medium'
            best_score = -1
            
            for severity, anchor_emb in self._anchor_embeddings.items():
                score = float(np.dot(text_emb, anchor_emb))
                if score > best_score:
                    best_score = score
                    best_severity = severity
            
            # Adjust based on context
            if context:
                best_severity = self._adjust_for_context(best_severity, context)
            
            return best_severity
            
        except Exception as e:
            logger.error(f"Embedding classification failed: {e}")
            return self._classify_with_heuristics(threat_text, context)
    
    def _classify_with_heuristics(self, threat_text: str, context: Dict = None) -> str:
        """Heuristic severity classification."""
        text_lower = threat_text.lower()
        
        critical_keywords = ['remote code execution', 'rce', 'sql injection', 'authentication bypass',
                           'credentials exposed', 'full compromise', 'root access', 'admin bypass',
                           'token forgery', 'all users', 'credit card', 'ssn']
        high_keywords = ['xss', 'cross-site', 'injection', 'brute force', 'missing encryption',
                        'privilege escalation', 'idor', 'data breach', 'session hijack']
        medium_keywords = ['audit', 'cors', 'session', 'error message', 'verbose', 'csrf',
                          'rate limit', 'certificate', 'logging']
        
        if any(kw in text_lower for kw in critical_keywords):
            severity = 'Critical'
        elif any(kw in text_lower for kw in high_keywords):
            severity = 'High'
        elif any(kw in text_lower for kw in medium_keywords):
            severity = 'Medium'
        else:
            severity = 'Low'
        
        if context:
            severity = self._adjust_for_context(severity, context)
        
        return severity
    
    def _adjust_for_context(self, severity: str, context: Dict) -> str:
        """Adjust severity based on architectural context."""
        severity_order = ['Low', 'Medium', 'High', 'Critical']
        idx = severity_order.index(severity)
        
        # Increase severity for internet-facing components
        if context.get('public_access') or context.get('trust_boundary') == 'internet':
            idx = min(idx + 1, 3)
        
        # Increase for sensitive data
        if context.get('data_sensitivity') in ('pii', 'financial', 'credentials', 'phi'):
            idx = min(idx + 1, 3)
        
        # Decrease for internal-only components with good controls
        if (context.get('trust_boundary') == 'internal' and 
            context.get('encryption_at_rest') and 
            context.get('auth_type') not in ('none', 'basic')):
            idx = max(idx - 1, 0)
        
        return severity_order[idx]
