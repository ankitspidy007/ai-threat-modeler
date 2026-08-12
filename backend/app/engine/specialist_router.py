"""Route a canonical architecture to relevant security specialist packs."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Set


CONDITIONAL_MODULES = {
    "cloud_aws_threats.json",
    "cloud_azure_threats.json",
    "cloud_gcp_threats.json",
    "container_k8s_threats.json",
    "serverless_threats.json",
    "custom_ai_llm_threats.json",
    "ai_agent_threats.json",
    "rag_vector_store_threats.json",
    "data_pipeline_threats.json",
}


class SpecialistRouter:
    """Select specialist analyzers from explicit architecture signals only."""

    def route(self, architecture, loaded_modules: List[str]) -> Dict[str, Any]:
        evidence_parts = [str((architecture.metadata or {}).get("architecture_text") or "")]
        for item in architecture.components or []:
            evidence_parts.append(f"{item.id} {item.name} {item.type}")
            for key, value in (item.properties or {}).items():
                if value is None or value is False or (
                    isinstance(value, str) and value.lower() in {"", "none", "unknown"}
                ):
                    continue
                if isinstance(value, (str, int, float, bool)):
                    evidence_parts.append(f"{key}={value}")
                elif isinstance(value, list) and value:
                    evidence_parts.append(f"{key}={' '.join(map(str, value))}")
        text = " ".join(evidence_parts).lower()
        specialists: Set[str] = {"stride", "web_api", "identity", "data_store"}
        selected = set(loaded_modules) - CONDITIONAL_MODULES

        if _contains(text, "aws", "amazon", "lambda", "s3", "dynamodb", "cognito", "cloudtrail", "kms", "eks"):
            specialists.add("aws_cloud")
            selected.add("cloud_aws_threats.json")
        if _contains(text, "azure", "entra", "azure ad", "blob storage", "aks", "key vault"):
            specialists.add("azure_cloud")
            selected.add("cloud_azure_threats.json")
        if _contains(text, "gcp", "google cloud", "cloud run", "gke", "bigquery", "vertex ai"):
            specialists.add("gcp_cloud")
            selected.add("cloud_gcp_threats.json")
        if _contains(text, "kubernetes", "k8s", "eks", "aks", "gke", "container", "docker"):
            specialists.add("kubernetes_container")
            selected.add("container_k8s_threats.json")
        if _contains(text, "lambda", "cloud function", "cloud run", "serverless", "azure function"):
            specialists.add("serverless")
            selected.add("serverless_threats.json")
        if _contains(text, "llm", "bedrock", "openai", "gemini", "claude", "prompt", "model endpoint"):
            specialists.add("ai_llm")
            selected.add("custom_ai_llm_threats.json")
        if _contains(text, "agent", "mcp", "tool call", "cursor"):
            specialists.add("ai_agent_mcp")
            selected.update({"ai_agent_threats.json", "custom_ai_llm_threats.json"})
        if _contains(text, "rag", "vector", "opensearch", "pinecone", "qdrant", "weaviate"):
            specialists.add("rag_vector")
            selected.add("rag_vector_store_threats.json")
        if _contains(text, "kafka", "etl", "pipeline", "data lake", "warehouse", "spark", "airflow"):
            specialists.add("data_pipeline")
            selected.add("data_pipeline_threats.json")
        if _contains(text, "stripe", "payment", "refund", "checkout", "cardholder", "pci"):
            specialists.add("payments")
        if _contains(text, "fhir", "hl7", "phi", "hipaa", "patient"):
            specialists.add("healthcare")

        return {
            "version": "specialist-router-1.0",
            "active_specialists": sorted(specialists),
            "active_modules": sorted(selected & set(loaded_modules)),
            "inactive_conditional_modules": sorted(CONDITIONAL_MODULES - selected),
            "basis": "literal canonical component, technology, property, and architecture evidence",
        }


def _contains(text: str, *terms: str) -> bool:
    return any(
        re.search(r"(?<![a-z0-9])" + re.escape(term) + r"(?![a-z0-9])", text)
        for term in terms
    )
