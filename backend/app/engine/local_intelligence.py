"""Truthful local semantic retrieval and STRIDE classification integration."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from .stride_coverage_engine import STRIDE_CATEGORIES
from .local_challenger import LocalChallenger
from .structured_local_slm import StructuredLocalSLM


class LocalIntelligence:
    def __init__(self, knowledge_base):
        self.knowledge_base = knowledge_base
        self.matcher = None
        self.classifier = None
        self.initialization_errors: List[str] = []
        self.challenger = LocalChallenger()
        self.structured_slm = StructuredLocalSLM()
        self._initialize()

    def _initialize(self) -> None:
        try:
            from .semantic_matcher import get_semantic_matcher
            self.matcher = get_semantic_matcher()
            self.matcher.vectorize_knowledge_base(self.knowledge_base.get_all_threats())
        except Exception as exc:
            self.initialization_errors.append(f"semantic matcher: {exc}")
        try:
            from .stride_classifier import get_stride_classifier
            self.classifier = get_stride_classifier()
            if self.classifier.is_available:
                self.classifier.load_or_train(self.knowledge_base.get_all_threats())
        except Exception as exc:
            self.initialization_errors.append(f"STRIDE classifier: {exc}")

    def enrich(self, architecture, threats, enabled: bool = True) -> Tuple[List, Dict[str, Any]]:
        if not enabled:
            return threats, {
                "status": "disabled", "semantic_retrieval": "disabled",
                "stride_classifier": "disabled", "retrieved_candidates": 0,
            }

        retrieved, retrieval_diagnostics = self._retrieve(architecture)
        classified = 0
        conflicts = 0
        classifier_ready = bool(self.classifier and self.classifier.is_trained)
        for threat in threats:
            text = f"{threat.title}. {threat.description}. {threat.root_cause or ''}"
            scores = {}
            predicted = "Unknown"
            if classifier_ready:
                predicted, scores = self.classifier.predict(text)
            elif self.matcher:
                try:
                    scores = self.matcher.classify_stride(text)
                    predicted = max(scores, key=scores.get) if scores and max(scores.values()) > 0 else "Unknown"
                except Exception:
                    scores = {}
            if predicted != "Unknown":
                classified += 1
                deterministic = threat.stride_category or threat.category
                if predicted != deterministic and scores.get(predicted, 0) >= 0.65:
                    conflicts += 1
                threat.explanation = threat.explanation or {}
                threat.explanation["local_stride_review"] = {
                    "deterministic_category": deterministic,
                    "predicted_category": predicted,
                    "scores": {key: round(value, 4) for key, value in scores.items()},
                    "decision": "deterministic category retained; classifier is advisory",
                }

        embedding_service = getattr(self.matcher, "_embedding_service", None) if self.matcher else None
        embedding_backend = getattr(embedding_service, "backend", "unavailable")
        full_embeddings = embedding_backend == "sentence_transformer"
        status = "active" if full_embeddings and classifier_ready else "degraded"
        if not self.matcher and not self.classifier:
            status = "unavailable"
        challenger = self.challenger.challenge(architecture, threats, retrieved)
        challenger["structured_slm"] = self.structured_slm.review(architecture, threats)
        diagnostics = {
            "status": status,
            "semantic_retrieval": "active" if full_embeddings else "local_hashing" if embedding_service else "lexical_fallback",
            "embedding_backend": embedding_backend,
            "stride_classifier": "active" if classifier_ready else "advisory_zero_shot" if self.matcher else "unavailable",
            "retrieved_candidates": len(retrieved),
            "candidate_threat_ids": [item["id"] for item in retrieved[:50]],
            "retrieval_domains": sorted(getattr(self.matcher, "_domain_stores", {}).keys()) if self.matcher else [],
            "reranker": getattr(getattr(self.matcher, "_reranker", None), "backend", "unavailable"),
            **retrieval_diagnostics,
            "findings_reviewed": classified,
            "classification_conflicts": conflicts,
            "errors": self.initialization_errors,
            "challenger": challenger,
            "claim": "Semantic models rank and review candidates; deterministic evidence rules decide findings.",
        }
        return threats, diagnostics

    def _retrieve(self, architecture) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        candidates: Dict[str, Dict[str, Any]] = {}
        queries = 0
        retrieved_by_element: Dict[str, Dict[str, int]] = {}
        for component in architecture.components or []:
            query = " ".join(filter(None, [
                component.name, component.type,
                str((component.properties or {}).get("db_type") or ""),
                str((component.properties or {}).get("cloud_provider") or ""),
                str((component.properties or {}).get("data_sensitivity") or ""),
            ]))
            retrieved_by_element[component.id] = {}
            cloud = str((component.properties or {}).get("cloud_provider") or "") or None
            for category in STRIDE_CATEGORIES:
                queries += 1
                results = []
                if self.matcher:
                    try:
                        results = self.matcher.find_relevant_threats(
                            query,
                            component.type,
                            top_k=5,
                            stride_category=category,
                            cloud_provider=cloud,
                        )
                    except Exception:
                        results = []
                if not results:
                    results = [
                        ({"original": item}, score)
                        for item, score in self._lexical_candidates(query, component.type, category)
                    ]
                accepted = 0
                for metadata, score in results:
                    original = metadata.get("original") or metadata
                    if score < 0.3:
                        continue
                    item = dict(original)
                    item["retrieval_score"] = max(float(score), candidates.get(item["id"], {}).get("retrieval_score", 0))
                    item["semantic_score"] = metadata.get("semantic_score")
                    item["reranker_score"] = metadata.get("reranker_score")
                    item["reranker_backend"] = metadata.get("reranker_backend")
                    item["hard_negative_reasons"] = metadata.get("hard_negative_reasons") or []
                    item["retrieved_for"] = sorted(set([
                        *(candidates.get(item["id"], {}).get("retrieved_for") or []),
                        f"{component.id}:{category}",
                    ]))
                    candidates[item["id"]] = item
                    accepted += 1
                retrieved_by_element[component.id][category] = accepted

        # Flows are first-class retrieval scopes because authentication,
        # integrity and confidentiality rules often apply to an interaction,
        # not either endpoint in isolation.
        component_map = {component.id: component for component in architecture.components or []}
        for flow in architecture.flows or []:
            flow_id = f"flow:{flow.source_id}->{flow.target_id}"
            source = component_map.get(flow.source_id)
            target = component_map.get(flow.target_id)
            query = f"{source.name if source else flow.source_id} to {target.name if target else flow.target_id} {flow.protocol} {flow.data_type} data flow"
            retrieved_by_element[flow_id] = {}
            for category in STRIDE_CATEGORIES:
                queries += 1
                results = []
                if self.matcher:
                    try:
                        results = self.matcher.find_relevant_threats(
                            query, "Data Flow", top_k=3, stride_category=category,
                        )
                    except Exception:
                        results = []
                accepted = 0
                for metadata, score in results:
                    original = metadata.get("original") or metadata
                    if score < 0.3:
                        continue
                    item = dict(original)
                    item["retrieval_score"] = max(float(score), candidates.get(item["id"], {}).get("retrieval_score", 0))
                    item["retrieved_for"] = sorted(set([
                        *(candidates.get(item["id"], {}).get("retrieved_for") or []),
                        f"{flow_id}:{category}",
                    ]))
                    candidates[item["id"]] = item
                    accepted += 1
                retrieved_by_element[flow_id][category] = accepted

        ranked = sorted(candidates.values(), key=lambda item: item.get("retrieval_score", 0), reverse=True)
        diagnostics = {
            "retrieval_strategy": "per-element-per-STRIDE hybrid retrieval with metadata filters",
            "retrieval_queries": queries,
            "retrieval_by_element": retrieved_by_element,
        }
        return ranked, diagnostics

    def _lexical_candidates(self, query: str, component_type: str, category: str | None = None) -> List[Tuple[Dict[str, Any], float]]:
        query_tokens = _tokens(query)
        ranked = []
        for threat in self.knowledge_base.get_all_threats():
            if category and (threat.get("stride_category") or threat.get("category")) != category:
                continue
            components = {str(value).lower() for value in threat.get("components") or []}
            component_match = "any" in components or component_type.lower() in components
            threat_tokens = _tokens(" ".join([
                threat.get("title", ""), threat.get("description", ""),
                " ".join(threat.get("tags") or []), " ".join(threat.get("components") or []),
            ]))
            overlap = len(query_tokens & threat_tokens)
            if component_match or overlap:
                score = min(0.75, (0.3 if component_match else 0) + overlap * 0.08)
                ranked.append((threat, score))
        ranked.sort(key=lambda item: item[1], reverse=True)
        return ranked[:12]


def _tokens(value: str) -> set[str]:
    stop = {"the", "and", "for", "with", "from", "service", "component", "data"}
    return {token for token in re.findall(r"[a-z0-9]+", value.lower()) if len(token) > 2 and token not in stop}
