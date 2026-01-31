from typing import List, Dict
from .graph_builder import GraphBuilder
from .rules import RuleEngine
from .parser import ArchitectureParser
from .mermaid_generator import generate_mermaid
from .reporter import ReportGenerator
from ..models import AnalysisResult, Threat, SystemArchitecture

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

    def analyze_from_text(self, description: str, project_name: str = "Untitled Project") -> AnalysisResult:
        parser = ArchitectureParser()
        system_architecture = parser.parse(description)
        return self.analyze(system_architecture, project_name)

    def analyze(self, architecture: SystemArchitecture, project_name: str = "Untitled Project") -> AnalysisResult:
        builder = GraphBuilder(architecture)
        graph = builder.get_graph()
        
        raw_threats = []

        # Analyze Components (Nodes)
        for node_id, data in graph.nodes(data=True):
            threats = self.rule_engine.evaluate_component(node_id, data)
            raw_threats.extend(threats)

        # Analyze Flows (Edges)
        for u, v, data in graph.edges(data=True):
            threats = self.rule_engine.evaluate_flow(u, v, data)
            raw_threats.extend(threats)

        # ========================================
        # PHASE 1: Aggregate by threat_id
        # ========================================
        aggregated_threats = self._aggregate_threats_by_id(raw_threats)
        
        # ========================================
        # PHASE 2: Apply Confidence-Gated Severity
        # ========================================
        gated_threats = self._apply_confidence_gating(aggregated_threats)
        
        # ========================================
        # PHASE 3: Classify into Confirmed vs Potential
        # ========================================
        classified_threats = self._classify_tiers(gated_threats)
        
        # ========================================
        # PHASE 4: Normalize STRIDE Categories
        # ========================================
        normalized_threats = self._normalize_stride(classified_threats)
        
        # ========================================
        # PHASE 5: Calculate Risk Score (post-aggregation)
        # ========================================
        score = self._calculate_score(normalized_threats)
        
        # Generate Mermaid Diagram
        diagram = generate_mermaid(graph)

        # Build Result
        confirmed = [t for t in normalized_threats if t.tier == "Confirmed"]
        potential = [t for t in normalized_threats if t.tier == "Potential"]
        
        result = AnalysisResult(
            project_name=project_name,
            summary=f"Analysis complete. {len(confirmed)} confirmed risks, {len(potential)} potential risks.",
            threats=normalized_threats,
            architecture=architecture,
            score=score,
            mermaid_diagram=diagram
        )
        
        # Generate Report
        result.report_markdown = ReportGenerator.generate_markdown(result)
        
        return result

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
                    flow_target=None
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
