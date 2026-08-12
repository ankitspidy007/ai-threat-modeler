"""Unified orchestration for architecture, code, IaC, and domain specialists."""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List, Tuple

from .contextual_threat_engine import ContextualThreatEngine
from .knowledge_threat_engine import KnowledgeThreatEngine
from .specialist_router import SpecialistRouter
from ..models import Threat


class SpecialistOrchestrator:
    def __init__(self, knowledge_base):
        self.knowledge_base = knowledge_base
        self.contextual = ContextualThreatEngine(knowledge_base)
        self.knowledge = KnowledgeThreatEngine(knowledge_base)
        self.router = SpecialistRouter()

    def analyze(self, architecture) -> Tuple[List[Threat], Dict[str, Any]]:
        route = self.router.route(architecture, self.knowledge_base.loaded_modules)
        contextual = self.contextual.analyze(architecture)
        knowledge, kb_diagnostics = self.knowledge.analyze(
            architecture, allowed_modules=route["active_modules"],
        )
        findings = [*contextual, *knowledge]
        specialist_counts = Counter()
        for finding in findings:
            specialist = _finding_specialist(finding, architecture)
            specialist_counts[specialist] += 1
            finding.explanation = {
                **(finding.explanation or {}),
                "specialist_engine": specialist,
            }

        metadata = architecture.metadata or {}
        source_adapters = []
        if metadata.get("iac_findings"):
            source_adapters.append("iac_static_analysis")
        if metadata.get("security_findings"):
            source_adapters.append("code_static_analysis")
        if metadata.get("known_issues"):
            source_adapters.append("declared_control_gaps")

        diagnostics = {
            "status": "active",
            **route,
            "source_adapters": source_adapters,
            "contextual_findings": len(contextual),
            "knowledge_findings": len(knowledge),
            "findings_by_specialist": dict(specialist_counts),
            "knowledge_diagnostics": kb_diagnostics,
            "contract": "Every specialist consumes and returns canonical component, flow, asset, evidence, and taxonomy IDs.",
        }
        return findings, diagnostics


def _finding_specialist(finding: Threat, architecture) -> str:
    components = {item.id: item for item in architecture.components or []}
    component = components.get(finding.component or finding.affected_component or "")
    context = " ".join(filter(None, [
        finding.title,
        finding.description,
        component.name if component else "",
        component.type if component else "",
        str((component.properties or {}).get("cloud_provider") or "") if component else "",
    ])).lower()
    if any(term in context for term in ("prompt", "llm", "agent", "mcp", "retrieval", "model")):
        return "ai_agent"
    if any(term in context for term in ("stripe", "payment", "refund", "cardholder", "webhook")):
        return "payments"
    if any(term in context for term in ("kubernetes", "container", "pod", "cluster", "service account")):
        return "container_platform"
    if any(term in context for term in ("aws", "azure", "gcp", "iam", "s3", "kms", "lambda")):
        return "cloud_iam"
    if any(term in context for term in ("oauth", "jwt", "session", "identity", "authentication")):
        return "identity_session"
    if any(term in context for term in ("database", "redis", "postgres", "mongo", "storage", "data")):
        return "data_security"
    return "web_api"
