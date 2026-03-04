import logging
from typing import List, Dict
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

class ThreatAnalyzer:
    def __init__(self):
        self.rule_engine = RuleEngine()
        self._semantic_matcher = None
        self._attack_chain_analyzer = None
        self._severity_classifier = None
        self._stride_classifier = None
        self._init_ml_components()
    
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

    def analyze_from_text(self, description: str, project_name: str = "Untitled Project") -> AnalysisResult:
        parser = ArchitectureParser()
        system_architecture = parser.parse(description)
        return self.analyze(system_architecture, project_name)

    def analyze(self, architecture: SystemArchitecture, project_name: str = "Untitled Project") -> AnalysisResult:
        builder = GraphBuilder(architecture)
        graph = builder.get_graph()
        
        raw_threats = []

        # ========================================
        # PHASE 0.5 (NEW): Architecture Intelligence
        # ========================================
        arch_insights = []
        if ARCH_INTELLIGENCE_AVAILABLE:
            try:
                intel = ArchitectureIntelligence()
                insights = intel.analyze(graph, architecture)
                arch_insights = intel.get_insights_dict()
                logger.info(f"Architecture intelligence found {len(arch_insights)} insights")
            except Exception as e:
                logger.warning(f"Architecture intelligence failed: {e}")

        # Analyze Components (Nodes) — Rule-based
        for node_id, data in graph.nodes(data=True):
            threats = self.rule_engine.evaluate_component(node_id, data)
            raw_threats.extend(threats)

        # Analyze Flows (Edges) — Rule-based
        for u, v, data in graph.edges(data=True):
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
        if self._semantic_matcher:
            semantic_threats = self._discover_semantic_threats(architecture, graph)
            raw_threats.extend(semantic_threats)
        
        # ========================================
        # PHASE 2: Aggregate by threat_id
        # ========================================
        aggregated_threats = self._aggregate_threats_by_id(raw_threats)
        
        # ========================================
        # PHASE 2.5 (NEW): ML Severity Refinement  
        # ========================================
        if self._severity_classifier:
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
        if self._attack_chain_analyzer:
            try:
                kb_threats = self.rule_engine.get_all_threats()
                self._attack_chain_analyzer.build_threat_graph(kb_threats)
                attack_chain_summary = self._attack_chain_analyzer.get_summary()
                logger.info(f"Attack chain analysis: {attack_chain_summary.get('chains', 0)} chains found")
            except Exception as e:
                logger.warning(f"Attack chain analysis failed: {e}")
        
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
            'semantic_matching': self._semantic_matcher is not None,
            'stride_classifier': self._stride_classifier is not None and self._stride_classifier.is_trained,
            'stride_classifier_accuracy': self._stride_classifier.accuracy if self._stride_classifier and self._stride_classifier.is_trained else 0.0,
            'severity_classifier': self._severity_classifier is not None,
            'attack_chains': self._attack_chain_analyzer is not None,
            'nlp_parser': architecture.metadata.get('nlp_enhanced', False),
        }
        
        # Generate comprehensive markdown report
        result.report_markdown = ReportGenerator.generate_markdown(result)
        
        return result
    
    def _discover_semantic_threats(self, architecture: SystemArchitecture, graph) -> List[Threat]:
        """
        Use semantic similarity to discover threats that keyword-based rules might miss.
        Only adds threats with high confidence semantic match (score > 0.6).
        """
        semantic_threats = []
        existing_ids = set()
        
        for node_id, data in graph.nodes(data=True):
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
            results = self._semantic_matcher.find_relevant_threats(
                description, comp_type, top_k=5
            )
            
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
        for threat in threats:
            context = {}
            # Find the component this threat relates to
            for comp in architecture.components:
                if comp.id in (threat.affected_components or []) or comp.id == threat.component_id:
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
