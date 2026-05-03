import hashlib
import json
import logging
from collections import OrderedDict
from datetime import datetime
from typing import Any, Dict, List, Optional

from .analysis_gaps import detect_missing_elements
from .architecture_intelligence import ArchitectureIntelligence
from .attack_path_engine import generate_attack_paths
from .contextual_threat_engine import ContextualThreatEngine
from .deduplication_engine import deduplicate_threats
from .graph_builder import GraphBuilder
from .impact_mapper import map_business_impact
from .mermaid_generator import generate_mermaid
from .parser import ArchitectureParser
from .reporter import ReportGenerator
from ..knowledge_base.loader import get_knowledge_base, reload_knowledge_base
from ..models import AnalysisResult, SystemArchitecture, Threat

logger = logging.getLogger(__name__)


DOMAIN_PLAYBOOK = {
    "general": {
        "label": "General software system",
        "headline": "Prioritize exposed interfaces, sensitive stores, and trust-boundary crossings first.",
        "priority_controls": ["authentication", "authorization", "encryption", "logging"],
        "high_risk_areas": ["public entry points", "sensitive storage", "external integrations"],
    },
    "saas": {
        "label": "Multi-tenant SaaS",
        "headline": "Tenant isolation, admin workflows, and identity federation should dominate review order.",
        "priority_controls": ["tenant isolation", "RBAC", "audit trails", "API authorization"],
        "high_risk_areas": ["cross-tenant access", "admin tooling", "identity providers"],
    },
    "fintech": {
        "label": "Fintech or payments",
        "headline": "Payment flows, secrets handling, and transaction integrity need the strongest controls.",
        "priority_controls": ["strong auth", "key management", "transaction integrity", "egress controls"],
        "high_risk_areas": ["payment APIs", "credential stores", "third-party payment links"],
    },
    "healthcare": {
        "label": "Healthcare or PHI system",
        "headline": "PHI storage, long-lived sessions, and auditability drive the highest impact risk.",
        "priority_controls": ["least privilege", "audit logging", "DLP", "session controls"],
        "high_risk_areas": ["record access", "download paths", "clinical integrations"],
    },
    "ai": {
        "label": "AI or LLM application",
        "headline": "Prompt injection, retrieval leakage, and tool authorization should be reviewed as first-order architecture risks.",
        "priority_controls": ["retrieval isolation", "tool-call authorization", "data minimization", "artifact integrity"],
        "high_risk_areas": ["prompt inputs", "vector stores", "tool execution", "model outputs"],
    },
    "platform": {
        "label": "Cloud platform or Kubernetes stack",
        "headline": "Workload identity, segmentation, and platform control-plane access are the dominant design concerns.",
        "priority_controls": ["least-privilege IAM", "network policy", "secret isolation", "supply-chain integrity"],
        "high_risk_areas": ["control plane", "shared infrastructure", "cluster ingress", "build pipeline"],
    },
}

STRIDE_MAPPING = {
    "Authentication": "Spoofing",
    "Authorization": "Elevation of Privilege",
    "Data Breach": "Information Disclosure",
    "Injection": "Tampering",
    "Lateral Movement": "Elevation of Privilege",
}


class ThreatAnalyzer:
    def __init__(self):
        self.knowledge_base = get_knowledge_base()
        self.contextual_engine = ContextualThreatEngine(self.knowledge_base)
        self._parsed_arch_cache: OrderedDict[str, SystemArchitecture] = OrderedDict()
        self._graph_cache: OrderedDict[str, object] = OrderedDict()
        self._report_cache: OrderedDict[str, str] = OrderedDict()

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
        encoded = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _architecture_signature(self, architecture: SystemArchitecture) -> str:
        payload = architecture.model_dump() if hasattr(architecture, "model_dump") else architecture.dict()
        return self._stable_hash(payload)

    def _get_cached_graph(self, architecture: SystemArchitecture):
        signature = self._architecture_signature(architecture)
        cached_graph = self._cache_get(self._graph_cache, signature)
        if cached_graph is not None:
            return cached_graph
        graph = GraphBuilder(architecture).get_graph()
        self._cache_set(self._graph_cache, signature, graph, max_size=32)
        return graph

    def _generate_report_markdown(self, result: AnalysisResult) -> str:
        cache_key = self._stable_hash({
            "project_name": result.project_name,
            "architecture": self._architecture_signature(result.architecture),
            "threats": [threat.id for threat in result.threats],
            "score": result.score,
        })
        cached = self._cache_get(self._report_cache, cache_key)
        if cached is not None:
            return cached
        report = ReportGenerator.generate_markdown(result)
        self._cache_set(self._report_cache, cache_key, report, max_size=32)
        return report

    def reload_local_intelligence(self) -> Dict[str, object]:
        self.knowledge_base = reload_knowledge_base()
        self.contextual_engine = ContextualThreatEngine(self.knowledge_base)
        self._parsed_arch_cache.clear()
        self._graph_cache.clear()
        self._report_cache.clear()
        return {
            "knowledge_base_threats": len(self.knowledge_base.get_all_threats()),
            "cached_architectures_cleared": True,
            "cached_graphs_cleared": True,
        }

    def _normalize_analysis_mode(self, analysis_mode: str = "standard", use_local_slm: bool = True) -> str:
        if analysis_mode not in {"fast", "standard", "deep"}:
            return "standard"
        if analysis_mode == "fast" and not use_local_slm:
            return "fast"
        return analysis_mode

    def _analysis_flags(self, analysis_mode: str = "standard", use_local_slm: bool = True) -> Dict[str, bool]:
        mode = self._normalize_analysis_mode(analysis_mode, use_local_slm)
        return {
            "mode": mode,
            "architecture_intelligence": mode in {"standard", "deep"},
            "attack_chains": mode in {"standard", "deep"},
            "deep_context": mode == "deep",
            "local_intelligence": use_local_slm,
        }

    def analyze_from_text(
        self,
        description: str,
        project_name: str = "Untitled Project",
        use_local_slm: bool = True,
        analysis_mode: str = "standard",
        domain_profile: str = "general",
    ) -> AnalysisResult:
        cache_key = self._stable_hash({"description": description})
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
            domain_profile=domain_profile,
        )

    def analyze(
        self,
        architecture: SystemArchitecture,
        project_name: str = "Untitled Project",
        use_local_slm: bool = True,
        analysis_mode: str = "standard",
        domain_profile: str = "general",
    ) -> AnalysisResult:
        analysis_flags = self._analysis_flags(analysis_mode, use_local_slm)
        graph = self._get_cached_graph(architecture)

        threats = self.contextual_engine.analyze(architecture)
        threats = self._process_known_issues(architecture, threats)
        threats = self._normalize_stride(threats)
        threats = self._ensure_architecture_links(threats, architecture)
        attack_paths = generate_attack_paths(architecture, threats)
        threats = self._attach_attack_paths(threats, attack_paths)
        threats = deduplicate_threats(threats)
        threats = self._normalize_stride(threats)
        threats = self._classify_tiers(threats)
        threats = self._enrich_threat_explanations(threats, architecture)
        architecture_insights = []
        if analysis_flags["architecture_intelligence"]:
            try:
                architecture_insights = [item.to_dict() for item in ArchitectureIntelligence().analyze(graph, architecture)]
            except Exception as exc:
                logger.warning("Architecture intelligence failed: %s", exc)

        missing_information = detect_missing_elements(architecture)
        score = self._calculate_score(threats)
        diagram = generate_mermaid(graph, threats=threats, enhanced=True)

        confirmed = [threat for threat in threats if threat.tier == "Confirmed"]
        potential = [threat for threat in threats if threat.tier == "Potential"]

        result = AnalysisResult(
            project_name=project_name,
            summary=(
                f"Context-aware analysis complete. "
                f"{len(confirmed)} confirmed risks, {len(potential)} assumption-sensitive risks, "
                f"and {len(attack_paths)} modeled attack paths."
            ),
            threats=threats,
            architecture=architecture,
            score=score,
            mermaid_diagram=diagram,
            diagram=diagram,
            timestamp=datetime.now().isoformat(),
        )

        result.attack_chains = {
            "paths": attack_paths,
            "count": len(attack_paths),
        }
        result.architecture_insights = architecture_insights
        result.ml_enhanced = {
            "analysis_mode": analysis_flags["mode"],
            "local_intelligence": analysis_flags["local_intelligence"],
            "architecture_modeled": True,
            "attack_paths": True,
            "contextual_threat_engine": True,
        }
        result.coverage = self._build_coverage(architecture, threats, analysis_flags, missing_information)
        result.follow_up_questions = self._build_follow_up_questions(architecture, threats, missing_information)
        result.review_summary = self._build_review_summary(threats)
        result.domain_context = self._build_domain_context(domain_profile, architecture, threats)
        result.ai_security_lens = self._build_ai_security_lens(architecture, threats)
        result.priority_actions = self._build_priority_actions(threats)
        result.report_markdown = self._generate_report_markdown(result)
        return result

    def _process_known_issues(self, architecture: SystemArchitecture, threats: List[Threat]) -> List[Threat]:
        known_issues = architecture.metadata.get("known_issues", [])
        for issue in known_issues:
            description = issue.get("description", "Known security issue identified in source material.")
            severity = issue.get("severity", "medium").title()
            threat = Threat(
                id=issue.get("suggested_threat_id") or f"KNOWN-{len(threats)+1}",
                category="Tampering",
                title=f"Known issue: {description[:72]}",
                description=description,
                severity=severity,
                likelihood="High",
                impact="High" if severity in {"Critical", "High"} else "Medium",
                risk_score=90 if severity == "Critical" else 75 if severity == "High" else 55,
                confidence="High",
                mitigation=f"Resolve the explicitly documented issue: {description}",
                component=None,
                data_flow=None,
                asset=None,
                root_cause="The design input explicitly lists this weakness as already present.",
                realistic_attack_scenario=f"An attacker exploits the already-known weakness exactly where the design states it exists: {description}",
                attack_scenario=f"An attacker exploits the already-known weakness exactly where the design states it exists: {description}",
                business_impact=map_business_impact({"title": description, "root_cause": description}),
                evidence=[f"Known issue from design input: {description}"],
                affected_components=[],
                affected_data_flows=[],
                affected_assets=[],
                tier="Confirmed",
                status="Identified",
            )
            threats.append(threat)
        return threats

    def _normalize_stride(self, threats: List[Threat]) -> List[Threat]:
        for threat in threats:
            threat.stride_category = STRIDE_MAPPING.get(threat.category, threat.category)
        return threats

    def _classify_tiers(self, threats: List[Threat]) -> List[Threat]:
        for threat in threats:
            if threat.confidence == "High":
                threat.tier = "Confirmed"
            elif threat.related_data_flow or threat.affected_component:
                threat.tier = "Confirmed" if len(threat.evidence) >= 2 else "Potential"
            else:
                threat.tier = "Potential"
        return threats

    def _ensure_architecture_links(self, threats: List[Threat], architecture: SystemArchitecture) -> List[Threat]:
        component_to_flows: Dict[str, List[str]] = {}
        component_to_assets: Dict[str, List[str]] = {}
        default_component = architecture.components[0].id if architecture.components else None
        default_flow = f"{architecture.flows[0].source_id}->{architecture.flows[0].target_id}" if architecture.flows else None
        default_asset = architecture.assets[0].name if architecture.assets else None

        for flow in architecture.flows:
            flow_ref = f"{flow.source_id}->{flow.target_id}"
            component_to_flows.setdefault(flow.source_id, []).append(flow_ref)
            component_to_flows.setdefault(flow.target_id, []).append(flow_ref)

        for asset in architecture.assets:
            if asset.related_component_id:
                component_to_assets.setdefault(asset.related_component_id, []).append(asset.name)

        for threat in threats:
            threat.component = threat.component or threat.affected_component or threat.component_id or default_component
            if threat.component and not threat.affected_components:
                threat.affected_components = [threat.component]

            if not threat.data_flow:
                candidate_flows = component_to_flows.get(threat.component or "", [])
                if candidate_flows:
                    threat.data_flow = candidate_flows[0]
                    threat.related_data_flow = threat.related_data_flow or threat.data_flow
            threat.data_flow = threat.data_flow or default_flow
            if threat.data_flow and threat.data_flow.replace("->", " → ") not in threat.affected_data_flows:
                threat.affected_data_flows.append(threat.data_flow.replace("->", " → "))

            if not threat.asset:
                candidate_assets = component_to_assets.get(threat.component or "", [])
                if candidate_assets:
                    threat.asset = candidate_assets[0]
            threat.asset = threat.asset or default_asset
            if threat.asset and threat.asset not in threat.affected_assets:
                threat.affected_assets.append(threat.asset)

        return threats

    def _attach_attack_paths(self, threats: List[Threat], attack_paths: List[Dict[str, Any]]) -> List[Threat]:
        for threat in threats:
            for path in attack_paths:
                if path.get("related_threat_id") == threat.id:
                    threat.attack_path = path
                    if path.get("steps"):
                        threat.attack_scenario = threat.attack_scenario or " ".join(path["steps"])
                    break
        return threats

    def _enrich_threat_explanations(self, threats: List[Threat], architecture: SystemArchitecture) -> List[Threat]:
        component_map = {component.id: component for component in architecture.components}
        for threat in threats:
            component = component_map.get(threat.affected_component or threat.component_id or "")
            threat.explanation.update({
                "component_name": component.name if component else None,
                "trust_level": component.trust_level if component else None,
                "asset_sensitivity": threat.data_sensitivity,
                "root_cause": threat.root_cause,
            })
        return threats

    def _build_coverage(
        self,
        architecture: SystemArchitecture,
        threats: List[Threat],
        analysis_flags: Dict[str, bool],
        missing_information: List[Dict[str, str]],
    ) -> Dict[str, object]:
        assumptions = architecture.metadata.get("assumptions", [])
        assumed_flows = sum(1 for flow in architecture.flows if flow.assumed)
        return {
            "analysis_mode": analysis_flags["mode"],
            "components_analyzed": len(architecture.components),
            "flows_analyzed": len(architecture.flows),
            "trust_boundaries_modeled": len(architecture.trust_boundaries),
            "assets_classified": len(architecture.assets),
            "assumption_count": len(assumptions),
            "assumed_flows": assumed_flows,
            "threats_identified": len(threats),
            "document_driven_analysis": False,
            "missing_information": missing_information,
            "assumptions": assumptions,
        }

    def _build_follow_up_questions(
        self,
        architecture: SystemArchitecture,
        threats: List[Threat],
        missing_information: List[Dict[str, str]],
    ) -> List[Dict[str, Any]]:
        prompts = []
        for index, gap in enumerate(missing_information[:8], start=1):
            prompts.append({
                "id": f"gap-{index}",
                "scope": gap["type"],
                "type": gap["type"],
                "priority": "high" if "auth" in gap["type"] or "data_flows" in gap["type"] else "medium",
                "question": gap["message"],
                "rationale": "Clarifying this item will tighten contextual threat accuracy and reduce assumed paths.",
                "related_components": [],
                "related_threat_count": len([threat for threat in threats if threat.tier == "Potential"]),
            })
        return prompts

    def _build_review_summary(self, threats: List[Threat]) -> Dict[str, Any]:
        by_severity: Dict[str, int] = {}
        by_tier: Dict[str, int] = {}
        for threat in threats:
            by_severity[threat.severity] = by_severity.get(threat.severity, 0) + 1
            by_tier[threat.tier] = by_tier.get(threat.tier, 0) + 1
        return {
            "total": len(threats),
            "by_severity": by_severity,
            "by_tier": by_tier,
        }

    def _build_domain_context(self, domain_profile: str, architecture: SystemArchitecture, threats: List[Threat]) -> Dict[str, Any]:
        playbook = DOMAIN_PLAYBOOK.get(domain_profile, DOMAIN_PLAYBOOK["general"])
        top_risks = [threat.title for threat in sorted(threats, key=lambda item: item.risk_score or 0, reverse=True)[:3]]
        return {
            "profile": domain_profile,
            "label": playbook["label"],
            "headline": playbook["headline"],
            "priority_controls": playbook["priority_controls"],
            "high_risk_areas": playbook["high_risk_areas"],
            "top_contextual_risks": top_risks,
        }

    def _build_ai_security_lens(self, architecture: SystemArchitecture, threats: List[Threat]) -> Dict[str, Any]:
        ai_threats = [threat for threat in threats if threat.mitre_atlas or "LLM" in threat.title or "prompt" in (threat.realistic_attack_scenario or "").lower()]
        return {
            "enabled": any((component.properties or {}).get("ml_pipeline") or component.type == "ML Service" for component in architecture.components),
            "overview": f"{len(ai_threats)} AI-contextual threats identified." if ai_threats else "No strong AI-native threat chain was detected from the current model.",
            "items": [
                {
                    "id": threat.id,
                    "label": threat.title,
                    "level": threat.severity.lower(),
                    "count": 1,
                    "summary": threat.realistic_attack_scenario,
                }
                for threat in ai_threats[:5]
            ],
        }

    def _build_priority_actions(self, threats: List[Threat]) -> List[Dict[str, Any]]:
        actions = []
        for threat in sorted(threats, key=lambda item: item.risk_score or 0, reverse=True)[:3]:
            actions.append({
                "title": threat.title,
                "priority": threat.severity,
                "why_now": threat.root_cause or threat.description,
                "action": threat.mitigation,
                "focus_area": [threat.affected_component] if threat.affected_component else [],
            })
        return actions

    def _calculate_score(self, threats: List[Threat]) -> int:
        if not threats:
            return 100
        deduction = 0
        for threat in threats:
            weight = 1.0 if threat.tier == "Confirmed" else 0.6
            deduction += ((threat.risk_score or 0) / 10) * weight
        return max(0, min(100, int(100 - deduction)))
