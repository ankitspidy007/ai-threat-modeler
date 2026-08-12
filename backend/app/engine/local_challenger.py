"""Constrained local architecture and coverage challenger."""

from __future__ import annotations

import re
from typing import Any, Dict, List

from .nlp_processor import TECH_COMPONENT_MAP
from .stride_coverage_engine import StrideCoverageEngine


class LocalChallenger:
    """Produces structured review candidates, never ungrounded findings."""

    def challenge(self, architecture, findings, retrieved_rules: List[Dict[str, Any]]) -> Dict[str, Any]:
        _, coverage = StrideCoverageEngine().assess(
            architecture, findings, generate_candidates=False,
        )
        unknown = {
            (cell["element_id"], cell["category"]): cell
            for cell in coverage["cells"] if cell["status"] == "unknown"
        }
        review_candidates = []
        for rule in retrieved_rules:
            score = float(rule.get("retrieval_score") or 0)
            if score < 0.4:
                continue
            category = rule.get("stride_category") or rule.get("category")
            for scope in rule.get("retrieved_for") or []:
                element_id, separator, retrieved_category = scope.rpartition(":")
                if not separator or retrieved_category != category:
                    continue
                cell = unknown.get((element_id, category))
                if not cell:
                    continue
                review_candidates.append({
                    "candidate_rule_id": rule["id"],
                    "element_id": element_id,
                    "element_name": cell["element_name"],
                    "stride_category": category,
                    "retrieval_score": round(score, 4),
                    "status": "information_required",
                    "required_evidence": (rule.get("applicability") or {}).get("required_signals", []),
                    "negating_controls": rule.get("negating_controls") or [],
                    "question": f"Is {rule['title']} applicable to {cell['element_name']}, and what source or configuration evidence proves or negates it?",
                })
        review_candidates.sort(key=lambda item: item["retrieval_score"], reverse=True)

        omitted = self._omitted_literal_components(architecture)
        duplicates = self._duplicate_component_aliases(architecture)
        return {
            "version": "local-challenger-1.0",
            "mode": "constrained_semantic_challenger",
            "review_candidates": review_candidates[:30],
            "review_candidate_count": len(review_candidates),
            "omitted_literal_components": omitted,
            "omitted_component_count": len(omitted),
            "duplicate_component_aliases": duplicates,
            "duplicate_alias_count": len(duplicates),
            "unknown_stride_cells_reviewed": len(unknown),
            "finding_authority": False,
            "contract": "The local model can rank candidates and detect extraction omissions; only evidence predicates can create findings.",
        }

    @staticmethod
    def _omitted_literal_components(architecture) -> List[Dict[str, str]]:
        source = str((architecture.metadata or {}).get("architecture_text") or "").lower()
        represented = " ".join(
            f"{item.id} {item.name} {item.type} {(item.properties or {}).get('technology', '')}"
            for item in architecture.components or []
        ).lower()
        omitted = []
        represented_types = {item.type for item in architecture.components or []}
        equivalent_types = {
            "rest api": {"API"},
            "api server": {"API"},
            "web service": {"API", "Service"},
            "frontend": {"WebClient"},
            "spa": {"WebClient"},
            "vector store": {"Database"},
            "vector database": {"Database"},
            "mcp server": {"MCP Server"},
            "shell executor": {"Tool", "MCP Server"},
            "filesystem": {"Tool", "MCP Server"},
        }
        # Prefer longest aliases so "azure openai" is not reduced to "openai".
        for technology in sorted(TECH_COMPONENT_MAP, key=len, reverse=True):
            if len(technology) < 3:
                continue
            pattern = r"(?<![a-z0-9])" + re.escape(technology) + r"(?![a-z0-9])"
            if not re.search(pattern, source) or re.search(pattern, represented):
                continue
            if represented_types & equivalent_types.get(technology, set()):
                continue
            if any(item["technology"] in technology or technology in item["technology"] for item in omitted):
                continue
            omitted.append({
                "technology": technology,
                "expected_type": TECH_COMPONENT_MAP[technology],
                "source_evidence": technology,
                "status": "extraction_review_required",
            })
        logical_terms = {
            "eventbridge": "Queue", "step functions": "Service", "aws glue": "Service",
            "athena": "Service", "scim endpoint": "API", "agent orchestrator": "ML Service",
            "policy service": "Service", "workflow service": "Service", "memory service": "Service",
            "code execution service": "Service", "approval service": "Service",
            "browser tool": "Tool", "observability vendor": "Monitoring", "self-hosted model": "ML Service",
        }
        for term, expected_type in logical_terms.items():
            if term in source and term not in represented and not any(
                item["technology"] in term or term in item["technology"] for item in omitted
            ):
                omitted.append({
                    "technology": term,
                    "expected_type": expected_type,
                    "source_evidence": term,
                    "status": "extraction_review_required",
                })
        return omitted

    @staticmethod
    def _duplicate_component_aliases(architecture) -> List[Dict[str, str]]:
        alias_groups = (
            {"aws_api_gateway", "api_gateway"},
            {"key_vault", "vault"},
            {"okta", "okta_external"},
            {"azure_openai", "openai"},
            {"pinecone", "vector_store", "vector_database"},
        )
        component_ids = {item.id for item in architecture.components or []}
        duplicates = []
        for aliases in alias_groups:
            present = sorted(component_ids & aliases)
            if len(present) > 1:
                duplicates.append({"aliases": ", ".join(present), "status": "merge_required"})
        return duplicates
