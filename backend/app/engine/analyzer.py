import hashlib
import json
import logging
import re
from collections import OrderedDict
from datetime import datetime
from typing import Any, Dict, List, Optional

from .analysis_gaps import detect_missing_elements
from .architecture_intelligence import ArchitectureIntelligence
from .attack_path_engine import generate_attack_paths
from .contextual_threat_engine import ContextualThreatEngine
from .canonical_model import canonicalize_architecture
from .deduplication_engine import deduplicate_threats
from .disagreement_engine import DisagreementEngine
from .graph_builder import GraphBuilder
from .impact_mapper import map_business_impact
from .mermaid_generator import generate_mermaid
from .output_model import build_system_model, group_findings, normalize_finding_output, risk_methodology
from .knowledge_threat_engine import KnowledgeThreatEngine
from .local_intelligence import LocalIntelligence
from .parser import ArchitectureParser
from .reporter import ReportGenerator
from .risk_scoring import calculate_risk
from .confidence_calibration import ConfidenceCalibrator
from .stride_coverage_engine import StrideCoverageEngine
from .specialist_router import SpecialistRouter
from .specialist_orchestrator import SpecialistOrchestrator
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
        self.knowledge_engine = KnowledgeThreatEngine(self.knowledge_base)
        self.stride_coverage_engine = StrideCoverageEngine()
        self.specialist_router = SpecialistRouter()
        self.specialist_orchestrator = SpecialistOrchestrator(self.knowledge_base)
        self.local_intelligence = LocalIntelligence(self.knowledge_base)
        self.confidence_calibrator = ConfidenceCalibrator()
        self.disagreement_engine = DisagreementEngine()
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
        from .embedding_service import reset_vector_store
        from .semantic_matcher import reset_semantic_matcher
        from .stride_classifier import reset_stride_classifier

        reset_semantic_matcher()
        reset_vector_store()
        reset_stride_classifier()
        self.knowledge_base = reload_knowledge_base()
        self.contextual_engine = ContextualThreatEngine(self.knowledge_base)
        self.knowledge_engine = KnowledgeThreatEngine(self.knowledge_base)
        self.specialist_orchestrator = SpecialistOrchestrator(self.knowledge_base)
        self.local_intelligence = LocalIntelligence(self.knowledge_base)
        self.confidence_calibrator = ConfidenceCalibrator()
        self.disagreement_engine = DisagreementEngine()
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
        source_documents: Optional[List[Dict[str, Any]]] = None,
    ) -> AnalysisResult:
        cache_key = self._stable_hash({"description": description, "source_documents": source_documents or []})
        system_architecture = self._cache_get(self._parsed_arch_cache, cache_key)
        if system_architecture is None:
            parser = ArchitectureParser()
            system_architecture = parser.parse(description)
            if source_documents:
                metadata = system_architecture.metadata or {}
                metadata["source_documents"] = source_documents
                system_architecture.metadata = metadata
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
        architecture, architecture_validation = canonicalize_architecture(architecture)
        graph = self._get_cached_graph(architecture)

        threats, specialist_diagnostics = self.specialist_orchestrator.analyze(architecture)
        specialist_route = specialist_diagnostics
        kb_diagnostics = specialist_diagnostics["knowledge_diagnostics"]
        threats = self._process_known_issues(architecture, threats)
        threats = self._normalize_stride(threats)
        threats = self._ensure_architecture_links(threats, architecture)
        threats = normalize_finding_output(threats, architecture)
        threats = self._apply_risk_model(threats, architecture)
        threats = deduplicate_threats(threats)
        coverage_candidates, _ = self.stride_coverage_engine.assess(
            architecture, threats, generate_candidates=True,
        )
        threats.extend(coverage_candidates)
        threats = self._normalize_stride(threats)
        threats = normalize_finding_output(threats, architecture)
        threats = self._apply_risk_model(threats, architecture)
        threats = deduplicate_threats(threats)
        threats, local_diagnostics = self.local_intelligence.enrich(
            architecture, threats, enabled=analysis_flags["local_intelligence"],
        )
        disagreement_diagnostics = self.disagreement_engine.assess(threats, local_diagnostics)
        threats, confidence_diagnostics = self.confidence_calibrator.calibrate(threats, architecture)
        threats = self._apply_risk_model(threats, architecture)
        threats = self._classify_tiers(threats)
        threats = self._suppress_potentials_superseded_by_known_issues(threats)
        _, stride_coverage = self.stride_coverage_engine.assess(
            architecture, threats, generate_candidates=False,
        )
        attack_paths = generate_attack_paths(architecture, threats)
        threats = self._attach_attack_paths(threats, attack_paths)
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
        result.system_model = build_system_model(architecture)
        result.stride_coverage = stride_coverage
        result.architecture_validation = architecture_validation
        result.engine_status = {
            "canonical_model": {"status": "active", "version": architecture_validation["version"]},
            "rule_engine": {"status": "active", "findings": len(threats)},
            "knowledge_base": {
                "status": "active",
                "schema_version": "canonical-kb-3.0",
                "threats": len(self.knowledge_base.get_all_threats()),
                "typed_rules": len(self.knowledge_base.get_typed_rules()),
                "deterministic_rules": sum(
                    item.rule_kind == "deterministic" for item in self.knowledge_base.get_typed_rules()
                ),
                "candidate_only_rules": sum(
                    item.rule_kind == "candidate" for item in self.knowledge_base.get_typed_rules()
                ),
                "validation_issues": len(self.knowledge_base.validation_issues),
                **kb_diagnostics,
            },
            "specialist_router": specialist_route,
            "local_intelligence": local_diagnostics,
            "disagreements": disagreement_diagnostics,
            "confidence_calibration": confidence_diagnostics,
            "stride_coverage": {
                "status": "active", "version": stride_coverage["version"],
                "applicable_cells": stride_coverage["applicable_cells"],
                "unknown_cells": stride_coverage["unknown_cells"],
            },
            "quality_gate": self._runtime_quality_gate(
                architecture_validation, threats, stride_coverage, local_diagnostics,
                disagreement_diagnostics,
            ),
        }
        result.finding_groups = group_findings(threats)
        result.risk_methodology = risk_methodology()
        result.architecture_insights = architecture_insights
        result.ml_enhanced = {
            "analysis_mode": analysis_flags["mode"],
            "local_intelligence": local_diagnostics["status"],
            "semantic_matching": local_diagnostics["semantic_retrieval"],
            "stride_classifier": local_diagnostics["stride_classifier"],
            "architecture_modeled": True,
            "attack_paths": True,
            "attack_chains": True,
            "contextual_threat_engine": True,
        }
        result.coverage = self._build_coverage(architecture, threats, analysis_flags, missing_information)
        result.follow_up_questions = self._build_follow_up_questions(
            architecture, threats, missing_information, stride_coverage, disagreement_diagnostics,
        )
        result.review_summary = self._build_review_summary(threats)
        result.domain_context = self._build_domain_context(domain_profile, architecture, threats)
        result.ai_security_lens = self._build_ai_security_lens(architecture, threats)
        result.priority_actions = self._build_priority_actions(threats)
        result.report_markdown = self._generate_report_markdown(result)
        return result

    @staticmethod
    def _runtime_quality_gate(
        architecture_validation: Dict[str, Any],
        threats: List[Threat],
        stride_coverage: Dict[str, Any],
        local_diagnostics: Optional[Dict[str, Any]] = None,
        disagreement_diagnostics: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        confirmed_without_evidence = sum(
            threat.tier == "Confirmed" and not threat.evidence_details for threat in threats
        )
        unmapped = sum(
            not (threat.affected_components or threat.affected_data_flows or threat.affected_assets)
            for threat in threats
        )
        confirmed_unmapped = sum(
            threat.tier == "Confirmed"
            and not (threat.affected_components or threat.affected_data_flows or threat.affected_assets)
            for threat in threats
        )
        omitted_components = int(
            (((local_diagnostics or {}).get("challenger") or {}).get("omitted_component_count") or 0)
        )
        duplicate_aliases = int(
            (((local_diagnostics or {}).get("challenger") or {}).get("duplicate_alias_count") or 0)
        )
        unclassified_known_issues = sum(
            threat.tier == "Confirmed" and str(threat.id).startswith("UNCLASSIFIED-KNOWN-ISSUE")
            for threat in threats
        )
        hard_failure = (
            not architecture_validation.get("valid", False)
            or confirmed_without_evidence > 0
            or confirmed_unmapped > 0
            or omitted_components > 0
            or duplicate_aliases > 0
            or unclassified_known_issues > 0
        )
        unresolved_disagreements = int((disagreement_diagnostics or {}).get("unresolved_count") or 0)
        status = "fail" if hard_failure else "review" if (
            unmapped or stride_coverage.get("unknown_cells") or unresolved_disagreements
        ) else "pass"
        return {
            "status": status,
            "architecture_valid": architecture_validation.get("valid", False),
            "confirmed_without_evidence": confirmed_without_evidence,
            "unmapped_findings": unmapped,
            "confirmed_unmapped_findings": confirmed_unmapped,
            "omitted_named_components": omitted_components,
            "duplicate_component_aliases": duplicate_aliases,
            "unclassified_known_issues": unclassified_known_issues,
            "unknown_stride_cells": stride_coverage.get("unknown_cells", 0),
            "unresolved_engine_disagreements": unresolved_disagreements,
            "publication_status": "blocked" if hard_failure else "review" if status == "review" else "ready",
            "policy": "Invalid topology, omitted or duplicate components, unclassified known issues, confirmed findings without evidence, or confirmed findings without scope block final report publication.",
        }

    @staticmethod
    def _suppress_potentials_superseded_by_known_issues(threats: List[Threat]) -> List[Threat]:
        """Do not repeat an explicit source weakness as a generic question."""
        confirmed_pairs = set()
        for threat in threats:
            source_refs = {
                str(item.get("source_ref") or "") for item in (threat.evidence_details or [])
            }
            if threat.tier != "Confirmed" or not any(re.fullmatch(r"K\d+", ref) for ref in source_refs):
                continue
            category = threat.stride_category or threat.category
            component_ids = set(threat.affected_components or [])
            if threat.affected_component:
                component_ids.add(threat.affected_component)
            confirmed_pairs.update((component_id, category) for component_id in component_ids if component_id)

        filtered = []
        for threat in threats:
            category = threat.stride_category or threat.category
            component_ids = set(threat.affected_components or [])
            if threat.affected_component:
                component_ids.add(threat.affected_component)
            superseded = threat.tier == "Potential" and any(
                (component_id, category) in confirmed_pairs for component_id in component_ids
            )
            if not superseded:
                filtered.append(threat)
        return filtered

    def refresh_result_artifacts(
        self,
        result: AnalysisResult,
        domain_profile: str = "general",
        analysis_mode: str = "standard",
        use_local_slm: bool = True,
    ) -> AnalysisResult:
        """Rebuild report fields after threats have been externally updated."""
        analysis_flags = self._analysis_flags(analysis_mode, use_local_slm)
        architecture = result.architecture
        threats = self._normalize_stride(result.threats)
        threats = self._ensure_architecture_links(threats, architecture)
        threats = normalize_finding_output(threats, architecture)
        threats = self._apply_risk_model(threats, architecture)
        threats = self._classify_tiers(threats)
        threats = self._suppress_potentials_superseded_by_known_issues(threats)
        threats, local_diagnostics = self.local_intelligence.enrich(
            architecture, threats, enabled=analysis_flags["local_intelligence"],
        )
        disagreement_diagnostics = self.disagreement_engine.assess(threats, local_diagnostics)
        threats, confidence_diagnostics = self.confidence_calibrator.calibrate(threats, architecture)
        threats = self._apply_risk_model(threats, architecture)
        _, stride_coverage = self.stride_coverage_engine.assess(
            architecture, threats, generate_candidates=False,
        )
        threats = self._enrich_threat_explanations(threats, architecture)
        result.threats = threats

        missing_information = detect_missing_elements(architecture)
        confirmed = [threat for threat in threats if threat.tier == "Confirmed"]
        potential = [threat for threat in threats if threat.tier == "Potential"]

        result.score = self._calculate_score(threats)
        result.summary = (
            f"Context-aware analysis complete. "
            f"{len(confirmed)} confirmed risks, {len(potential)} assumption-sensitive risks, "
            f"and {len((result.attack_chains or {}).get('paths', []))} modeled attack paths."
        )
        result.coverage = self._build_coverage(architecture, threats, analysis_flags, missing_information)
        result.follow_up_questions = self._build_follow_up_questions(
            architecture, threats, missing_information, stride_coverage, disagreement_diagnostics,
        )
        result.review_summary = self._build_review_summary(threats)
        result.domain_context = self._build_domain_context(domain_profile, architecture, threats)
        result.ai_security_lens = self._build_ai_security_lens(architecture, threats)
        result.priority_actions = self._build_priority_actions(threats)
        result.system_model = build_system_model(architecture)
        result.stride_coverage = stride_coverage
        result.engine_status = {
            **(result.engine_status or {}),
            "local_intelligence": local_diagnostics,
            "disagreements": disagreement_diagnostics,
            "confidence_calibration": confidence_diagnostics,
            "stride_coverage": {
                "status": "active", "version": stride_coverage["version"],
                "applicable_cells": stride_coverage["applicable_cells"],
                "unknown_cells": stride_coverage["unknown_cells"],
            },
            "quality_gate": self._runtime_quality_gate(
                result.architecture_validation or {"valid": True}, threats, stride_coverage, local_diagnostics,
                disagreement_diagnostics,
            ),
        }
        result.finding_groups = group_findings(threats)
        result.risk_methodology = risk_methodology()
        result.report_markdown = self._generate_report_markdown(result)
        return result

    def _process_known_issues(self, architecture: SystemArchitecture, threats: List[Threat]) -> List[Threat]:
        metadata = architecture.metadata or {}
        known_issues = metadata.get("known_issues", [])
        component_ids = {component.id for component in architecture.components or []}
        for issue_index, issue in enumerate(known_issues, 1):
            description = issue.get("description", "Known security issue identified in source material.")
            severity = issue.get("severity", "medium").title()
            threat_id = issue.get("suggested_threat_id") or "KNOWN"
            source_record_id = issue.get("source_record_id")
            # Preserve every known issue even where multiple instances map to a
            # single taxonomy rule. Deduplication must never drop source facts.
            threat_id = f"{threat_id}-{source_record_id or f'{issue_index:02d}'}"
            category = issue.get("category", "Tampering")
            affected_components = [
                component_id for component_id in issue.get("component_hints", [])
                if component_id in component_ids
            ]
            primary_component = affected_components[0] if affected_components else None
            threat = Threat(
                id=threat_id,
                category=category,
                stride_category=category,
                affected_stride_categories=issue.get("affected_stride_categories") or [category],
                title=f"Known issue: {description[:72]}",
                description=description,
                severity=severity,
                likelihood="High",
                impact="High" if severity in {"Critical", "High"} else "Medium",
                risk_score=90 if severity == "Critical" else 75 if severity == "High" else 55,
                confidence="High",
                mitigation=issue.get("mitigation") or f"Resolve the explicitly documented issue: {description}",
                component=primary_component,
                data_flow=None,
                asset=None,
                affected_component=primary_component,
                component_id=primary_component,
                root_cause="The design input explicitly lists this weakness as already present.",
                realistic_attack_scenario=f"An attacker exploits the already-known weakness exactly where the design states it exists: {description}",
                attack_scenario=f"An attacker exploits the already-known weakness exactly where the design states it exists: {description}",
                business_impact=map_business_impact({"title": description, "root_cause": description}),
                evidence=[f"Known issue from design input: {description}"],
                evidence_details=[{
                    "source_type": "architecture_input",
                    "source_ref": source_record_id or f"K{issue_index}",
                    "line": None,
                    "statement": description,
                    "confidence": "High",
                }],
                affected_components=affected_components,
                affected_data_flows=[],
                affected_assets=[],
                tier="Confirmed",
                status="Identified",
                finding_type="control_gap",
                owasp_top_10=issue.get("owasp_top_10", []),
                cwe=issue.get("cwe", []),
                explanation={
                    "scope_resolution": issue.get("component_resolution", "unresolved"),
                    "scope_warning": None if primary_component else "Confirmed source issue; affected component requires analyst mapping.",
                },
            )
            threats.append(threat)

        # Static findings are explicit source or configuration evidence, not
        # assumptions. Keep them separate from generic architecture rules.
        source_findings = (
            [("iac", item) for item in metadata.get("iac_findings", [])]
            + [("code", item) for item in metadata.get("security_findings", [])]
        )
        for source_kind, finding in source_findings:
            severity = str(finding.get("severity", "Medium")).title()
            severity_score = {"Critical": 95, "High": 80, "Medium": 55, "Low": 30}.get(severity, 55)
            finding_text = f"{finding.get('rule_id', '')} {finding.get('title', '')}".upper()
            exposure = "public" if any(token in finding_text for token in ("PUBLIC", "OPEN", "INTERNET")) else "internal"
            resource_id = finding.get("resource_id")
            component_id = resource_id if resource_id in component_ids else (
                "source" if source_kind == "code" and "source" in component_ids else None
            )
            evidence = finding.get("evidence", []) or [finding.get("description", "Static analysis rule matched.")]
            threats.append(Threat(
                id=finding.get("id") or f"IAC-{len(threats) + 1}",
                category=finding.get("category", "Tampering"),
                title=finding.get("title", "Security finding"),
                description=finding.get("description", "An insecure source or configuration pattern was detected."),
                severity=severity,
                likelihood="High" if severity in {"Critical", "High"} else "Medium",
                impact="Critical" if severity == "Critical" else "High" if severity == "High" else "Medium",
                risk_score=severity_score,
                confidence="High",
                mitigation=finding.get("mitigation", "Correct the insecure source or configuration pattern."),
                component_id=component_id,
                component=component_id,
                root_cause=f"Security rule {finding.get('rule_id', 'unknown')} matched {finding.get('resource_id', 'unknown')}.",
                realistic_attack_scenario=finding.get("description", "An attacker exploits the insecure source or infrastructure configuration."),
                attack_scenario=finding.get("description", "An attacker exploits the insecure source or infrastructure configuration."),
                business_impact=map_business_impact({"title": finding.get("title", "Security finding"), "severity": severity}),
                evidence=evidence,
                evidence_details=[{
                    "source_type": source_kind,
                    "source_ref": str(resource_id or finding.get("rule_id") or "source"),
                    "line": finding.get("line"),
                    "statement": item,
                    "confidence": "High",
                } for item in evidence],
                cwe=finding.get("cwe", []),
                owasp_top_10=["A05:2021 Security Misconfiguration"],
                exposure=exposure,
                data_sensitivity="sensitive",
                exploit_complexity="Low" if severity in {"Critical", "High"} else "Medium",
                privilege_required="None" if exposure == "public" else "Low",
                affected_components=[component_id] if component_id else [],
                tier="Confirmed",
                status="Identified",
                finding_type=source_kind,
            ))
        return threats

    def _normalize_stride(self, threats: List[Threat]) -> List[Threat]:
        for threat in threats:
            threat.stride_category = STRIDE_MAPPING.get(threat.category, threat.category)
        return threats

    def _classify_tiers(self, threats: List[Threat]) -> List[Threat]:
        for threat in threats:
            if threat.confidence_score is not None:
                direct = bool((threat.explanation or {}).get("confidence_calibration", {}).get("direct_evidence"))
                threat.tier = "Confirmed" if direct and threat.confidence_score >= 0.8 else "Potential"
            elif threat.finding_type in {"code", "iac"} and threat.evidence_details:
                threat.tier = "Confirmed"
            elif threat.finding_type in {"architecture", "control_gap"} and threat.confidence in {"Low", "Medium"}:
                threat.tier = "Potential"
            elif threat.confidence == "High" and threat.evidence_details:
                threat.tier = "Confirmed"
            elif threat.related_data_flow or threat.affected_component:
                threat.tier = "Confirmed" if len(threat.evidence) >= 2 else "Potential"
            else:
                threat.tier = "Potential"
        return threats

    def _apply_risk_model(self, threats: List[Threat], architecture: Optional[SystemArchitecture] = None) -> List[Threat]:
        """Apply one transparent technical risk calculation to every finding."""
        severity_rank = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        components = {item.id: item for item in (architecture.components if architecture else [])}
        flows = {
            f"{item.source_id}->{item.target_id}": item for item in (architecture.flows if architecture else [])
        }
        for threat in threats:
            direct_evidence = threat.finding_type in {"code", "iac"} or bool(threat.evidence_details)
            component = components.get(threat.component or threat.affected_component or threat.component_id or "")
            flow_ref = (threat.data_flow or threat.related_data_flow or "").replace(" â†’ ", "->")
            flow = flows.get(flow_ref)
            control_assertions = (component.properties or {}).get("control_assertions", {}) if component else {}
            present_controls = sum(value == "present" for value in control_assertions.values())
            risk = calculate_risk({
                "category": threat.category,
                "exposure": threat.exposure,
                "data_sensitivity": threat.data_sensitivity,
                "exploit_complexity": threat.exploit_complexity,
                "privilege_required": threat.privilege_required,
                "evidence_confidence": threat.confidence,
                "compensating_controls": present_controls,
                "crosses_trust_boundary": bool(flow and (flow.properties or {}).get("crosses_trust_boundary")),
                "blast_radius": len(set(threat.affected_components or [])),
            })
            calculated_severity = risk["severity"]
            if direct_evidence and severity_rank.get(threat.severity, 1) > severity_rank.get(calculated_severity, 1):
                calculated_severity = threat.severity
            threat.severity = calculated_severity
            threat.likelihood = risk["likelihood"]
            threat.impact = risk["impact"]
            threat.risk_score = max(threat.risk_score or 0, risk["risk_score"])
            threat.risk_factors = risk["risk_factors"]
        return threats

    def _ensure_architecture_links(self, threats: List[Threat], architecture: SystemArchitecture) -> List[Threat]:
        component_to_assets: Dict[str, List[str]] = {}
        for asset in architecture.assets:
            if asset.related_component_id:
                component_to_assets.setdefault(asset.related_component_id, []).append(asset.name)

        for threat in threats:
            threat.component = threat.component or threat.affected_component or threat.component_id
            if threat.component and not threat.affected_components:
                threat.affected_components = [threat.component]

            if threat.data_flow and threat.data_flow.replace("->", " → ") not in threat.affected_data_flows:
                threat.affected_data_flows.append(threat.data_flow.replace("->", " → "))

            if not threat.asset:
                candidate_assets = component_to_assets.get(threat.component or "", [])
                if candidate_assets:
                    threat.asset = candidate_assets[0]
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
        stride_coverage: Optional[Dict[str, Any]] = None,
        disagreement_diagnostics: Optional[Dict[str, Any]] = None,
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
        represented = {(item["scope"], item["type"]) for item in prompts}
        for cell in (stride_coverage or {}).get("cells", []):
            if cell.get("status") != "unknown" or len(prompts) >= 12:
                continue
            key = (cell["element_id"], cell["category"])
            if key in represented:
                continue
            prompts.append({
                "id": f"stride-gap-{len(prompts) + 1}",
                "scope": cell["element_id"],
                "type": cell["category"],
                "priority": "high" if cell["category"] in {"Spoofing", "Information Disclosure", "Elevation of Privilege"} else "medium",
                "question": f"What verified controls address {cell['category']} for {cell['element_name']}?",
                "rationale": cell["rationale"],
                "related_components": [cell["element_id"]] if cell["element_kind"] == "component" else [],
                "related_threat_count": 0,
            })
            represented.add(key)
        for item in (disagreement_diagnostics or {}).get("items", []):
            if len(prompts) >= 16:
                break
            prompts.append({
                "id": item["id"],
                "scope": item.get("element_id") or item.get("finding_id") or "analysis",
                "type": "engine_disagreement",
                "priority": "high" if item.get("status") == "review_required" else "medium",
                "question": item.get("question"),
                "rationale": item.get("resolution"),
                "related_components": [item["element_id"]] if item.get("element_id") else [],
                "related_threat_count": 1 if item.get("finding_id") else 0,
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
