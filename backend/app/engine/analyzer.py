import hashlib
import json
import logging
from collections import OrderedDict
from typing import List, Dict, Tuple, Any
from .graph_builder import GraphBuilder
from .rules import RuleEngine
from .parser import ArchitectureParser
from .mermaid_generator import generate_mermaid
from .reporter import ReportGenerator
from ..models import AnalysisResult, Threat, SystemArchitecture

logger = logging.getLogger(__name__)

# Import NLP/DL modules (graceful fallback)
try:
    from .semantic_matcher import get_semantic_matcher
    SEMANTIC_AVAILABLE = True
except ImportError:
    SEMANTIC_AVAILABLE = False
    logger.warning("Semantic matcher not available")

try:
    from .stride_classifier import get_stride_classifier
    STRIDE_CLASSIFIER_AVAILABLE = True
except ImportError:
    STRIDE_CLASSIFIER_AVAILABLE = False

try:
    from .attack_chain import AttackChainAnalyzer, SeverityClassifier
    ATTACK_CHAIN_AVAILABLE = True
except ImportError:
    ATTACK_CHAIN_AVAILABLE = False
    logger.warning("Attack chain analyzer not available")

try:
    from .architecture_intelligence import ArchitectureIntelligence
    ARCH_INTELLIGENCE_AVAILABLE = True
except ImportError:
    ARCH_INTELLIGENCE_AVAILABLE = False


# STRIDE Category Mapping
STRIDE_MAPPING = {
    "Spoofing": "Spoofing",
    "Tampering": "Tampering", 
    "Repudiation": "Repudiation",
    "Information Disclosure": "Information Disclosure",
    "Denial of Service": "Denial of Service",
    "Elevation of Privilege": "Elevation of Privilege",
    # Internal category mappings
    "Lateral Movement": "Elevation of Privilege",
    "Eavesdropping": "Information Disclosure",
    "Data Breach": "Information Disclosure",
    "Injection": "Tampering",
    "Authentication": "Spoofing",
    "Authorization": "Elevation of Privilege",
}

DOMAIN_PLAYBOOK = {
    "general": {
        "label": "General software system",
        "headline": "Balance identity, data protection, and external exposure first.",
        "priority_controls": ["authentication", "authorization", "logging", "encryption"],
        "high_risk_areas": ["internet-facing entry points", "admin workflows", "sensitive data paths"],
    },
    "saas": {
        "label": "Multi-tenant SaaS",
        "headline": "Tenant isolation, admin abuse paths, and auth federation deserve the strongest scrutiny.",
        "priority_controls": ["tenant isolation", "RBAC", "audit logging", "API rate limiting"],
        "high_risk_areas": ["cross-tenant access", "support/admin tooling", "identity federation"],
    },
    "fintech": {
        "label": "Fintech or payments",
        "headline": "Payment integrity, fraud abuse, and secrets handling should drive the review order.",
        "priority_controls": ["transaction integrity", "strong auth", "fraud monitoring", "key management"],
        "high_risk_areas": ["payment flows", "ledger updates", "third-party payment integrations"],
    },
    "healthcare": {
        "label": "Healthcare or PHI system",
        "headline": "PHI access paths, session handling, and auditability are usually the highest-value review areas.",
        "priority_controls": ["least privilege", "audit trails", "session controls", "data loss prevention"],
        "high_risk_areas": ["record access", "file downloads", "break-glass workflows"],
    },
    "ai": {
        "label": "AI or LLM application",
        "headline": "Prompt injection, tool authorization, and data leakage through retrieval need explicit safeguards.",
        "priority_controls": ["tool-call authorization", "prompt filtering", "retrieval access control", "artifact integrity"],
        "high_risk_areas": ["prompt inputs", "agent tools", "vector stores", "model outputs"],
    },
    "platform": {
        "label": "Cloud platform or Kubernetes stack",
        "headline": "Control plane access, workload identity, and network segmentation matter more than surface polish.",
        "priority_controls": ["workload identity", "network policy", "secret isolation", "cluster governance"],
        "high_risk_areas": ["control plane", "service mesh", "cluster admin paths", "shared infrastructure"],
    },
}

class ThreatAnalyzer:
    def __init__(self):
        self.rule_engine = RuleEngine()
        self._semantic_matcher = None
        self._attack_chain_analyzer = None
        self._severity_classifier = None
        self._stride_classifier = None
        self._parsed_arch_cache: OrderedDict[str, SystemArchitecture] = OrderedDict()
        self._graph_cache: OrderedDict[str, object] = OrderedDict()
        self._report_cache: OrderedDict[str, str] = OrderedDict()
        self._semantic_query_cache: OrderedDict[str, List[Tuple[Dict, float]]] = OrderedDict()
        self._attack_chain_summary_cache = None
        self._init_ml_components()

    @staticmethod
    def _cache_get(cache: OrderedDict, key: str):
        if key in cache:
            cache.move_to_end(key)
            return cache[key]
        return None

    @staticmethod
    def _cache_set(cache: OrderedDict, key: str, value, max_size: int):
        cache[key] = value
        cache.move_to_end(key)
        while len(cache) > max_size:
            cache.popitem(last=False)

    @staticmethod
    def _stable_hash(payload) -> str:
        encoded = json.dumps(payload, sort_keys=True, default=str).encode('utf-8')
        return hashlib.sha256(encoded).hexdigest()

    def _architecture_signature(self, architecture: SystemArchitecture) -> str:
        payload = architecture.model_dump() if hasattr(architecture, 'model_dump') else architecture.dict()
        return self._stable_hash(payload)

    def _get_cached_graph(self, architecture: SystemArchitecture):
        signature = self._architecture_signature(architecture)
        cached_graph = self._cache_get(self._graph_cache, signature)
        if cached_graph is not None:
            return cached_graph

        graph = GraphBuilder(architecture).get_graph()
        self._cache_set(self._graph_cache, signature, graph, max_size=32)
        return graph

    def _get_attack_chain_summary(self):
        if not self._attack_chain_analyzer:
            return None
        if self._attack_chain_summary_cache is not None:
            return self._attack_chain_summary_cache

        kb_threats = self.rule_engine.get_all_threats()
        self._attack_chain_analyzer.build_threat_graph(kb_threats)
        self._attack_chain_summary_cache = self._attack_chain_analyzer.get_summary()
        return self._attack_chain_summary_cache

    def _generate_report_markdown(self, result: AnalysisResult) -> str:
        cache_key = self._stable_hash({
            'project_name': result.project_name,
            'architecture': self._architecture_signature(result.architecture),
            'score': result.score,
            'threats': [
                {
                    'id': threat.id,
                    'severity': threat.severity,
                    'confidence': threat.confidence,
                    'tier': threat.tier,
                    'risk_score': threat.risk_score,
                }
                for threat in result.threats
            ],
        })
        cached_report = self._cache_get(self._report_cache, cache_key)
        if cached_report is not None:
            return cached_report

        report = ReportGenerator.generate_markdown(result)
        self._cache_set(self._report_cache, cache_key, report, max_size=32)
        return report

    def _build_coverage(self, architecture: SystemArchitecture, threats: List[Threat], analysis_flags: Dict[str, bool]) -> Dict[str, object]:
        """Summarize how complete the current analysis is and what assumptions remain."""
        assumptions = architecture.metadata.get('assumptions', [])
        threat_boundaries = architecture.metadata.get('trust_boundaries', [])
        component_total = len(architecture.components)
        flow_total = len(architecture.flows)
        components_with_auth = sum(1 for comp in architecture.components if comp.properties.get('auth_type') not in (None, 'none', False))
        components_with_logging = sum(1 for comp in architecture.components if comp.properties.get('logging_enabled'))
        components_with_encryption = sum(1 for comp in architecture.components if comp.properties.get('encryption_at_rest'))

        return {
            'analysis_mode': analysis_flags["mode"],
            'components_analyzed': component_total,
            'flows_analyzed': flow_total,
            'threats_identified': len(threats),
            'assumption_count': len(assumptions),
            'trust_boundary_count': len(threat_boundaries),
            'component_control_coverage': {
                'authentication': components_with_auth,
                'logging': components_with_logging,
                'encryption_at_rest': components_with_encryption,
            },
            'optional_stages': {
                'semantic_matching': analysis_flags["semantic_matching"],
                'severity_refinement': analysis_flags["severity_refinement"],
                'attack_chains': analysis_flags["attack_chains"],
                'architecture_intelligence': analysis_flags["architecture_intelligence"],
            },
            'assumptions': assumptions,
        }

    def _build_follow_up_questions(self, architecture: SystemArchitecture, threats: List[Threat]) -> List[Dict[str, Any]]:
        """Turn assumptions into concrete follow-up prompts for the user."""
        assumptions = architecture.metadata.get('assumptions', [])
        component_map = {component.id: component for component in architecture.components}
        threat_map: Dict[str, int] = {}

        for threat in threats:
            related_scopes = set(threat.affected_components or [])
            if threat.component_id:
                related_scopes.add(threat.component_id)
            if threat.flow_source and threat.flow_target:
                related_scopes.add(f"{threat.flow_source}->{threat.flow_target}")
            for flow_ref in threat.affected_data_flows or []:
                normalized_flow = flow_ref.replace(" → ", "->").replace("â†’", "->")
                related_scopes.add(normalized_flow)
            for scope in related_scopes:
                threat_map[scope] = threat_map.get(scope, 0) + 1

        question_map = {
            'authentication': "What authentication and authorization controls protect this component?",
            'encryption': "Is encryption at rest enabled here, and who manages the keys?",
            'logging': "What audit and application logging exists for this component or flow?",
            'trust_boundary': "Does this flow cross a real trust boundary, and what validation or filtering exists at that boundary?",
        }
        priority_map = {
            'authentication': 'high',
            'trust_boundary': 'high',
            'encryption': 'medium',
            'logging': 'medium',
        }

        follow_ups: List[Dict[str, Any]] = []
        for index, assumption in enumerate(assumptions[:8], start=1):
            scope = assumption.get('scope', 'system')
            assumption_type = assumption.get('type', 'general')
            component = component_map.get(scope)
            related_components = [component.name] if component else []
            related_threats = threat_map.get(scope, 0)
            if "->" in scope:
                source_id, target_id = scope.split("->", 1)
                related_components = [
                    component_map.get(source_id).name if component_map.get(source_id) else source_id,
                    component_map.get(target_id).name if component_map.get(target_id) else target_id,
                ]

            priority = priority_map.get(assumption_type, 'low')
            if related_threats >= 2 and priority != 'high':
                priority = 'high'

            follow_ups.append({
                'id': f"question-{index}",
                'scope': scope,
                'type': assumption_type,
                'priority': priority,
                'question': question_map.get(assumption_type, "What additional implementation detail can confirm or reject this assumption?"),
                'rationale': assumption.get('message', ''),
                'related_components': [name for name in related_components if name],
                'related_threat_count': related_threats,
            })

        return follow_ups

    def _enrich_threat_explanations(self, threats: List[Threat], architecture: SystemArchitecture) -> List[Threat]:
        """Attach lightweight explainability metadata that the UI can render directly."""
        component_map = {component.id: component for component in architecture.components}

        for threat in threats:
            component_ids = []
            if threat.component_id:
                component_ids.append(threat.component_id)
            component_ids.extend(threat.affected_components or [])
            component_names = []
            for component_id in component_ids:
                component = component_map.get(component_id)
                component_names.append(component.name if component else component_id)

            evidence_summary = threat.evidence[:3]
            why_flagged = (
                f"This finding was raised because the analyzer matched {threat.category.lower()} risk patterns "
                f"against the architecture context and supporting evidence."
            )
            if threat.confidence == "High":
                why_flagged = f"{why_flagged} Multiple strong signals or explicit controls gaps increased confidence."
            elif threat.confidence == "Low":
                why_flagged = f"{why_flagged} Evidence is weaker, so this remains a potential risk."

            remediation_priority = "Planned"
            if threat.severity in {"Critical", "High"} and threat.tier == "Confirmed":
                remediation_priority = "Immediate"
            elif threat.severity == "Medium":
                remediation_priority = "Near-term"

            threat.explanation = {
                'why_flagged': why_flagged,
                'evidence_summary': evidence_summary,
                'impacted_components': component_names[:5],
                'impacted_flows': (threat.affected_data_flows or [])[:4],
                'remediation_priority': remediation_priority,
            }

        return threats

    def _build_review_summary(self, threats: List[Threat]) -> Dict[str, Any]:
        """Build a compact review workflow summary for the dashboard."""
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        confirmed = 0
        potential = 0

        for threat in threats:
            severity_counts[threat.severity] = severity_counts.get(threat.severity, 0) + 1
            if threat.tier == "Confirmed":
                confirmed += 1
            else:
                potential += 1

        top_queue = [
            {
                'id': threat.id,
                'title': threat.title,
                'severity': threat.severity,
                'tier': threat.tier,
            }
            for threat in sorted(
                threats,
                key=lambda item: (
                    {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}.get(item.severity, 0),
                    1 if item.tier == "Confirmed" else 0,
                    item.risk_score or 0,
                ),
                reverse=True
            )[:5]
        ]

        return {
            'open_findings': len(threats),
            'confirmed_findings': confirmed,
            'potential_findings': potential,
            'severity_counts': severity_counts,
            'priority_queue': top_queue,
        }

    def _build_domain_context(self, domain_profile: str, architecture: SystemArchitecture, threats: List[Threat]) -> Dict[str, Any]:
        """Return domain-specific guidance to help the UI feel more specialized."""
        profile = DOMAIN_PLAYBOOK.get(domain_profile or "general", DOMAIN_PLAYBOOK["general"])
        threat_titles = [threat.title for threat in threats[:5]]
        component_types = sorted({component.type for component in architecture.components})
        return {
            'profile': domain_profile or 'general',
            'label': profile['label'],
            'headline': profile['headline'],
            'priority_controls': profile['priority_controls'],
            'high_risk_areas': profile['high_risk_areas'],
            'observed_component_types': component_types[:8],
            'top_findings': threat_titles,
        }
    
    def _init_ml_components(self):
        """Initialize ML/NLP components (graceful fallback)."""
        all_threats = self.rule_engine.get_all_threats()
        
        if SEMANTIC_AVAILABLE:
            try:
                self._semantic_matcher = get_semantic_matcher()
                # Vectorize the knowledge base for semantic search
                if all_threats:
                    self._semantic_matcher.vectorize_knowledge_base(all_threats)
                    logger.info(f"Vectorized {len(all_threats)} threats for semantic search")
            except Exception as e:
                logger.warning(f"Semantic matcher init failed: {e}")
        
        if STRIDE_CLASSIFIER_AVAILABLE:
            try:
                self._stride_classifier = get_stride_classifier()
                if all_threats:
                    self._stride_classifier.load_or_train(all_threats)
                    if self._stride_classifier.is_trained:
                        logger.info(f"STRIDE classifier ready (accuracy: {self._stride_classifier.accuracy:.1%})")
            except Exception as e:
                logger.warning(f"STRIDE classifier init failed: {e}")
        
        if ATTACK_CHAIN_AVAILABLE:
            try:
                self._attack_chain_analyzer = AttackChainAnalyzer()
                self._severity_classifier = SeverityClassifier()
                logger.info("Attack chain analyzer and severity classifier initialized")
            except Exception as e:
                logger.warning(f"Attack chain init failed: {e}")

    def reload_local_intelligence(self) -> Dict[str, object]:
        """Reload the KB and rebuild local semantic/classifier artifacts."""
        from ..knowledge_base.loader import reload_knowledge_base
        from .embedding_service import reset_vector_store
        from .semantic_matcher import reset_semantic_matcher
        from .stride_classifier import reset_stride_classifier

        reload_knowledge_base()
        reset_vector_store()
        reset_semantic_matcher()
        reset_stride_classifier()

        self.rule_engine = RuleEngine()
        self._semantic_matcher = None
        self._attack_chain_analyzer = None
        self._severity_classifier = None
        self._stride_classifier = None
        self._parsed_arch_cache.clear()
        self._graph_cache.clear()
        self._report_cache.clear()
        self._semantic_query_cache.clear()
        self._attack_chain_summary_cache = None
        self._init_ml_components()

        kb_stats = {
            'total_threats': len(self.rule_engine.get_all_threats()),
            'semantic_ready': self._semantic_matcher is not None,
            'stride_classifier_ready': self._stride_classifier is not None and self._stride_classifier.is_trained,
            'stride_classifier_accuracy': (
                self._stride_classifier.accuracy
                if self._stride_classifier and self._stride_classifier.is_trained
                else 0.0
            ),
            'attack_chain_ready': self._attack_chain_analyzer is not None,
        }
        logger.info(f"Reloaded local intelligence: {kb_stats}")
        return kb_stats

    def _normalize_analysis_mode(self, analysis_mode: str = "standard", use_local_slm: bool = True) -> str:
        """Normalize analysis mode while preserving legacy use_local_slm behavior."""
        mode = (analysis_mode or "standard").lower()
        if mode not in {"fast", "standard", "deep"}:
            mode = "standard"
        if not use_local_slm and mode != "deep":
            return "fast"
        return mode

    def _analysis_flags(self, analysis_mode: str = "standard", use_local_slm: bool = True) -> Dict[str, bool]:
        """Resolve which optional analysis stages should run."""
        mode = self._normalize_analysis_mode(analysis_mode, use_local_slm)
        is_fast = mode == "fast"
        is_deep = mode == "deep"
        return {
            "mode": mode,
            "architecture_intelligence": is_deep,
            "semantic_matching": not is_fast and use_local_slm,
            "severity_refinement": not is_fast,
            "attack_chains": is_deep,
            "semantic_top_k": 8 if is_deep else 5,
        }

    def analyze_from_text(
        self,
        description: str,
        project_name: str = "Untitled Project",
        use_local_slm: bool = True,
        analysis_mode: str = "standard",
        domain_profile: str = "general"
    ) -> AnalysisResult:
        """Parse text and analyze the resulting architecture."""
        cache_key = self._stable_hash({'description': description})
        system_architecture = self._cache_get(self._parsed_arch_cache, cache_key)
        if system_architecture is None:
            parser = ArchitectureParser()
            system_architecture = parser.parse(description)
            self._cache_set(self._parsed_arch_cache, cache_key, system_architecture, max_size=32)
        return self.analyze(
            system_architecture,
            project_name,
            use_local_slm=use_local_slm,
            analysis_mode=analysis_mode,
            domain_profile=domain_profile
        )

    def analyze(
        self,
        architecture: SystemArchitecture,
        project_name: str = "Untitled Project",
        use_local_slm: bool = True,
        analysis_mode: str = "standard",
        domain_profile: str = "general"
    ) -> AnalysisResult:
        analysis_flags = self._analysis_flags(analysis_mode, use_local_slm)
        graph = self._get_cached_graph(architecture)
        
        raw_threats = []

        # ========================================
        # PHASE 0.5 (NEW): Architecture Intelligence
        # ========================================
        arch_insights = []
        if ARCH_INTELLIGENCE_AVAILABLE and analysis_flags["architecture_intelligence"]:
            try:
                intel = ArchitectureIntelligence()
                insights = intel.analyze(graph, architecture)
                arch_insights = intel.get_insights_dict()
                logger.info(f"Architecture intelligence found {len(arch_insights)} insights")
            except Exception as e:
                logger.warning(f"Architecture intelligence failed: {e}")

        # Analyze Components (Nodes) — Rule-based
        prioritized_nodes = self._prioritize_component_nodes(graph)
        prioritized_edges = self._prioritize_flow_edges(graph)

        for node_id, data in prioritized_nodes:
            threats = self.rule_engine.evaluate_component(node_id, data)
            raw_threats.extend(threats)

        # Analyze Flows (Edges) — Rule-based
        for u, v, data in prioritized_edges:
            threats = self.rule_engine.evaluate_flow(u, v, data)
            raw_threats.extend(threats)

        # ========================================
        # PHASE 1: Process Known Issues
        # ========================================
        known_issues_threats = self._process_known_issues(architecture)
        raw_threats.extend(known_issues_threats)
        
        # ========================================
        # PHASE 1.5 (NEW): Semantic Threat Discovery
        # ========================================
        if self._semantic_matcher and analysis_flags["semantic_matching"]:
            semantic_threats = self._discover_semantic_threats(
                architecture,
                graph,
                top_k=analysis_flags["semantic_top_k"]
            )
            raw_threats.extend(semantic_threats)
        
        # ========================================
        # PHASE 2: Aggregate by threat_id
        # ========================================
        aggregated_threats = self._aggregate_threats_by_id(raw_threats)
        
        # ========================================
        # PHASE 2.5 (NEW): ML Severity Refinement  
        # ========================================
        if self._severity_classifier and analysis_flags["severity_refinement"]:
            aggregated_threats = self._refine_severity(aggregated_threats, architecture)
        
        # ========================================
        # PHASE 3: Apply Confidence-Gated Severity
        # ========================================
        gated_threats = self._apply_confidence_gating(aggregated_threats)
        
        # ========================================
        # PHASE 4: Classify into Confirmed vs Potential
        # ========================================
        classified_threats = self._classify_tiers(gated_threats)
        
        # ========================================
        # PHASE 5: Normalize STRIDE Categories
        # ========================================
        normalized_threats = self._normalize_stride(classified_threats)
        
        # ========================================
        # PHASE 5.5 (NEW): Attack Chain Analysis
        # ========================================
        attack_chain_summary = None
        if self._attack_chain_analyzer and analysis_flags["attack_chains"]:
            try:
                attack_chain_summary = self._get_attack_chain_summary()
                logger.info(f"Attack chain analysis: {attack_chain_summary.get('chains', 0)} chains found")
            except Exception as e:
                logger.warning(f"Attack chain analysis failed: {e}")
        
        normalized_threats = self._enrich_threat_explanations(normalized_threats, architecture)

        # ========================================
        # PHASE 6: Calculate Risk Score (post-aggregation)
        # ========================================
        score = self._calculate_score(normalized_threats)
        
        # Generate Enhanced Mermaid Diagram with STRIDE colors and threat annotations
        diagram = generate_mermaid(graph, threats=normalized_threats, enhanced=True)

        # Build Result
        confirmed = [t for t in normalized_threats if t.tier == "Confirmed"]
        potential = [t for t in normalized_threats if t.tier == "Potential"]
        
        from datetime import datetime
        
        result = AnalysisResult(
            project_name=project_name,
            summary=f"Analysis complete. {len(confirmed)} confirmed risks, {len(potential)} potential risks.",
            threats=normalized_threats,
            architecture=architecture,
            score=score,
            mermaid_diagram=diagram,
            diagram=diagram,  # Set both for compatibility
            timestamp=datetime.now().isoformat()
        )
        
        # Add attack chain data to metadata if available
        if attack_chain_summary:
            result.attack_chains = attack_chain_summary
        
        # Add architecture insights
        if arch_insights:
            result.architecture_insights = arch_insights
        
        # Indicate NLP/ML enhancement status
        result.ml_enhanced = {
            'semantic_matching': self._semantic_matcher is not None and analysis_flags["semantic_matching"],
            'stride_classifier': self._stride_classifier is not None and self._stride_classifier.is_trained,
            'stride_classifier_accuracy': self._stride_classifier.accuracy if self._stride_classifier and self._stride_classifier.is_trained else 0.0,
            'severity_classifier': self._severity_classifier is not None and analysis_flags["severity_refinement"],
            'attack_chains': self._attack_chain_analyzer is not None and analysis_flags["attack_chains"],
            'analysis_mode': analysis_flags["mode"],
            'nlp_parser': architecture.metadata.get('nlp_enhanced', False),
        }
        result.coverage = self._build_coverage(architecture, normalized_threats, analysis_flags)
        result.follow_up_questions = self._build_follow_up_questions(architecture, normalized_threats)
        result.review_summary = self._build_review_summary(normalized_threats)
        result.domain_context = self._build_domain_context(domain_profile, architecture, normalized_threats)
        
        # Generate comprehensive markdown report
        result.report_markdown = self._generate_report_markdown(result)
        
        return result
    
    def _priority_score_for_component(self, data: Dict) -> int:
        score = 0
        if data.get('public_access') or data.get('internet_facing'):
            score += 6
        if data.get('trust_boundary') in ('internet', 'public', 'external', 'dmz'):
            score += 5
        if data.get('data_sensitivity') in ('credentials', 'financial', 'pii', 'phi'):
            score += 4
        if data.get('auth_type') not in (None, 'none', False):
            score += 2
        if data.get('type') in ('API', 'API Gateway', 'Database', 'Identity Provider', 'Secrets Manager', 'Object Storage'):
            score += 2
        if data.get('waf_enabled') is False or data.get('encryption_at_rest') is False:
            score += 1
        return score

    def _priority_score_for_flow(self, source_data: Dict, flow_data: Dict, target_data: Dict) -> int:
        score = 0
        if flow_data.get('crosses_trust_boundary'):
            score += 5
        if flow_data.get('trust_boundary') in ('internet', 'public', 'external'):
            score += 4
        if source_data.get('public_access') or target_data.get('public_access'):
            score += 3
        if source_data.get('data_sensitivity') or target_data.get('data_sensitivity'):
            score += 2
        if flow_data.get('protocol') in ('http', 'https', 'websocket'):
            score += 1
        return score

    def _prioritize_component_nodes(self, graph) -> List[Tuple[str, Dict]]:
        prioritized = list(graph.nodes(data=True))
        prioritized.sort(key=lambda item: self._priority_score_for_component(item[1]), reverse=True)
        return prioritized

    def _prioritize_flow_edges(self, graph) -> List[Tuple[str, str, Dict]]:
        prioritized = list(graph.edges(data=True))
        prioritized.sort(
            key=lambda item: self._priority_score_for_flow(
                graph.nodes[item[0]],
                item[2],
                graph.nodes[item[1]]
            ),
            reverse=True
        )
        return prioritized

    def _discover_semantic_threats(self, architecture: SystemArchitecture, graph, top_k: int = 5) -> List[Threat]:
        """
        Use semantic similarity to discover threats that keyword-based rules might miss.
        Only adds threats with high confidence semantic match (score > 0.6).
        """
        semantic_threats = []
        existing_ids = set()
        
        for node_id, data in self._prioritize_component_nodes(graph):
            comp_type = data.get('type', 'Service')
            comp_name = data.get('name', node_id)
            
            # Build a description from all component properties
            desc_parts = [f"{comp_name} ({comp_type})"]
            props = data.get('properties', {})
            for k, v in props.items():
                if v and v is not True:
                    desc_parts.append(f"{k}: {v}")
                elif v is True:
                    desc_parts.append(k)
            description = ' '.join(desc_parts)
            
            # Semantic search for relevant threats
            semantic_cache_key = self._stable_hash({
                'description': description,
                'component_type': comp_type,
                'top_k': top_k,
            })
            results = self._cache_get(self._semantic_query_cache, semantic_cache_key)
            if results is None:
                results = self._semantic_matcher.find_relevant_threats(
                    description, comp_type, top_k=top_k
                )
                self._cache_set(self._semantic_query_cache, semantic_cache_key, results, max_size=128)
            
            for meta, score in results:
                if score < 0.6:  # Only high-confidence matches
                    continue
                
                threat_id = meta.get('threat_id', '')
                if threat_id in existing_ids:
                    continue
                existing_ids.add(threat_id)
                
                # Get original threat data
                original = meta.get('original', {})
                threat_detail = original.get('threat', {})
                risk_info = original.get('risk', {})
                
                confidence = 'Medium' if score > 0.7 else 'Low'
                
                threat = Threat(
                    id=f"SEM-{threat_id}" if not threat_id.startswith('SEM-') else threat_id,
                    category=meta.get('category', 'Unknown'),
                    title=f"[Semantic] {meta.get('threat_name', threat_detail.get('title', 'Unknown'))}",
                    description=threat_detail.get('description', meta.get('threat_name', '')),
                    severity=meta.get('severity', 'Medium'),
                    likelihood=risk_info.get('likelihood', 'Medium'),
                    impact=risk_info.get('impact', 'Medium'),
                    risk_score=int(score * 100),
                    mitigation='See threat knowledge base for details',
                    confidence=confidence,
                    evidence=[f"Semantic match (score: {score:.2f}) for component: {comp_name}"],
                    status='Identified',
                    component_id=node_id,
                )
                semantic_threats.append(threat)
        
        logger.info(f"Semantic matching found {len(semantic_threats)} additional threats")
        return semantic_threats
    
    def _refine_severity(self, threats: List[Threat], architecture: SystemArchitecture) -> List[Threat]:
        """
        Refine threat severity using the ML severity classifier.
        Only adjusts severity when the classifier has high confidence.
        """
        component_map = {comp.id: comp for comp in architecture.components}
        for threat in threats:
            context = {}
            candidate_ids = []
            if threat.component_id:
                candidate_ids.append(threat.component_id)
            candidate_ids.extend(threat.affected_components or [])
            for component_id in candidate_ids:
                comp = component_map.get(component_id)
                if comp:
                    context = comp.properties
                    break
            
            threat_text = f"{threat.title} {threat.description}"
            ml_severity = self._severity_classifier.classify(threat_text, context)
            
            # Only adjust if ML and rule-based disagree by more than 1 level
            severity_levels = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}
            rule_level = severity_levels.get(threat.severity, 2)
            ml_level = severity_levels.get(ml_severity, 2)
            
            if abs(rule_level - ml_level) >= 2:
                # Split the difference (don't fully override rules)
                avg_level = (rule_level + ml_level) // 2
                level_to_severity = {v: k for k, v in severity_levels.items()}
                threat.severity = level_to_severity.get(avg_level, threat.severity)
                threat.evidence.append(f"ML severity refinement: {ml_severity} (rule-based: {threat.severity})")
        
        return threats

    def _process_known_issues(self, architecture: SystemArchitecture) -> List[Threat]:
        """
        Process known issues from architecture metadata and convert them to threat findings.
        Known issues are explicitly stated vulnerabilities that should be high-confidence threats.
        """
        threats = []
        known_issues = architecture.metadata.get('known_issues', [])
        
        if not known_issues:
            return threats
        
        # Map issue types to threat properties
        for issue in known_issues:
            issue_type = issue.get('type')
            control = issue.get('control')
            severity = issue.get('severity', 'medium').title()
            description = issue.get('description', '')
            suggested_id = issue.get('suggested_threat_id')
            
            # Create a threat object from the known issue
            if issue_type == 'missing_control':
                title = f"Known Issue: {description[:80]}..."
                if len(description) <= 80:
                    title = f"Known Issue: {description}"
                
                # Map severity to risk score
                risk_scores = {
                    'critical': 90,
                    'high': 75,
                    'medium': 50,
                    'low': 25
                }
                risk_score = risk_scores.get(severity.lower(), 50)
                
                # Determine STRIDE category from suggested threat ID
                category = "Spoofing"  # Default
                if suggested_id:
                    if suggested_id.startswith('S-'):
                        category = "Spoofing"
                    elif suggested_id.startswith('T-'):
                        category = "Tampering"
                    elif suggested_id.startswith('R-'):
                        category = "Repudiation"
                    elif suggested_id.startswith('ID-'):
                        category = "Information Disclosure"
                    elif suggested_id.startswith('DOS-'):
                        category = "Denial of Service"
                    elif suggested_id.startswith('EOP-'):
                        category = "Elevation of Privilege"
                    elif suggested_id.startswith('CORS-'):
                        category = "Information Disclosure"
                
                threat = Threat(
                    id=suggested_id or f"KNOWN-{len(threats)+1}",
                    category=category,
                    title=title,
                    description=description,
                    severity=severity,
                    likelihood="High",  # Known issues are high likelihood
                    impact="High" if severity.lower() in ['critical', 'high'] else "Medium",
                    risk_score=risk_score,
                    mitigation=f"Address the known issue: {control}",
                    confidence="High",  # Known issues are high confidence
                    evidence=[f"Explicitly stated in architecture description: {description}"],
                    status="Identified",
                    tier="Confirmed"  # Known issues are always confirmed
                )
                threats.append(threat)
        
        return threats

    def _aggregate_threats_by_id(self, threats: List[Threat]) -> List[Threat]:
        """
        Aggregates threats by threat_id. Multiple matches become one finding
        with aggregated affected_components and affected_data_flows.
        """
        grouped: Dict[str, Threat] = {}
        
        for t in threats:
            key = t.id  # Group by threat_id ONLY
            
            if key not in grouped:
                # Create new aggregated threat
                grouped[key] = Threat(
                    id=t.id,
                    category=t.category,
                    title=t.title,
                    description=t.description,
                    severity=t.severity,
                    likelihood=t.likelihood,
                    impact=t.impact,
                    risk_score=t.risk_score,
                    confidence=t.confidence,
                    status=t.status,
                    evidence=list(t.evidence),
                    mitigation=t.mitigation,
                    affected_components=[],
                    affected_data_flows=[],
                    component_id=None,
                    flow_source=None,
                    flow_target=None,
                    owasp_top_10=list(t.owasp_top_10 or []),
                    cwe=list(t.cwe or []),
                    mitre_attack=list(t.mitre_attack or []),
                    nist_800_53=list(t.nist_800_53 or []),
                )
            
            existing = grouped[key]
            
            # Aggregate affected components
            if t.component_id and t.component_id not in existing.affected_components:
                existing.affected_components.append(t.component_id)
            
            # Aggregate affected data flows
            if t.flow_source and t.flow_target:
                flow_str = f"{t.flow_source} → {t.flow_target}"
                if flow_str not in existing.affected_data_flows:
                    existing.affected_data_flows.append(flow_str)
            
            # Aggregate evidence (unique only)
            for ev in t.evidence:
                if ev not in existing.evidence:
                    existing.evidence.append(ev)
            
            # Upgrade confidence if this match is more certain
            # Multiple matches = higher confidence
            confidence_levels = {"High": 3, "Medium": 2, "Low": 1}
            if confidence_levels.get(t.confidence, 1) > confidence_levels.get(existing.confidence, 1):
                existing.confidence = t.confidence
            
            # Keep highest severity
            severity_levels = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
            if severity_levels.get(t.severity, 1) > severity_levels.get(existing.severity, 1):
                existing.severity = t.severity
                existing.risk_score = max(existing.risk_score or 0, t.risk_score or 0)

        return list(grouped.values())

    def _apply_confidence_gating(self, threats: List[Threat]) -> List[Threat]:
        """
        Applies confidence-gated severity rules:
        - Low confidence: Max severity = Medium
        - Conditional findings: Prefix title with "Potential"
        """
        for t in threats:
            if t.confidence == "Low":
                # Cap severity at Medium
                if t.severity in ["Critical", "High"]:
                    t.severity = "Medium"
                    t.risk_score = min(t.risk_score or 50, 50)
                # Mark as potential in title if not already
                if not t.title.startswith("[Potential]") and not t.title.startswith("[Conditional]"):
                    t.title = f"[Potential] {t.title}"
        
        return threats

    def _classify_tiers(self, threats: List[Threat]) -> List[Threat]:
        """
        Classifies threats into Confirmed vs Potential based on:
        - Confidence level
        - Amount of evidence
        - Number of affected components
        """
        for t in threats:
            # Confirmed: High confidence OR multiple evidence points
            if t.confidence == "High":
                t.tier = "Confirmed"
            elif t.confidence == "Medium" and len(t.evidence) >= 2:
                t.tier = "Confirmed"
            elif len(t.affected_components) >= 2 or len(t.affected_data_flows) >= 2:
                # Widespread issue = Confirmed
                t.tier = "Confirmed"
            else:
                t.tier = "Potential"
        
        return threats

    def _normalize_stride(self, threats: List[Threat]) -> List[Threat]:
        """
        Maps internal categories to STRIDE.
        """
        for t in threats:
            t.stride_category = STRIDE_MAPPING.get(t.category, t.category)
        return threats

    def _calculate_score(self, threats: List[Threat]) -> int:
        """
        Calculates security score (0-100) with:
        - Confidence weighting
        - Compounding for shared components
        - Post-aggregation calculation
        """
        if not threats:
            return 100
        
        base_score = 100
        total_deduction = 0
        
        # Confidence weights
        confidence_weights = {"High": 1.0, "Medium": 0.6, "Low": 0.3}
        
        confirmed_critical = 0
        confirmed_high = 0
        
        for t in threats:
            weight = confidence_weights.get(t.confidence, 0.5)
            
            # Base deduction from risk_score
            risk = t.risk_score or 0
            base_deduction = (risk / 10) * weight
            
            # Amplify for widespread impact
            impact_multiplier = 1.0
            total_affected = len(t.affected_components) + len(t.affected_data_flows)
            if total_affected > 3:
                impact_multiplier = 1.3
            elif total_affected > 1:
                impact_multiplier = 1.1
            
            deduction = base_deduction * impact_multiplier
            total_deduction += deduction
            
            # Track confirmed high/critical for compounding
            if t.tier == "Confirmed":
                if t.severity == "Critical":
                    confirmed_critical += 1
                elif t.severity == "High":
                    confirmed_high += 1
        
        # Compounding penalties for multiple critical issues
        if confirmed_critical > 1:
            total_deduction += (confirmed_critical - 1) * 8
        if confirmed_high > 2:
            total_deduction += (confirmed_high - 2) * 4

        final_score = max(0, int(base_score - total_deduction))
        return final_score
