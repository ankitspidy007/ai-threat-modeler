"""Evidence-based confidence calibration for normalized findings."""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List, Tuple

from ..models import Threat


SOURCE_WEIGHT = {
    "code": 0.98,
    "iac": 0.98,
    "static_analysis": 0.96,
    "architecture_input": 0.9,
    "rule_evaluation": 0.82,
    "coverage_assessment": 0.86,
    "llm_challenger": 0.62,
    "architecture": 0.55,
    "inference": 0.45,
}
DIRECT_SOURCES = {"code", "iac", "static_analysis", "architecture_input", "rule_evaluation", "coverage_assessment"}


class ConfidenceCalibrator:
    def calibrate(self, threats: List[Threat], architecture) -> Tuple[List[Threat], Dict[str, Any]]:
        flows = {
            f"{item.source_id}->{item.target_id}": item for item in architecture.flows or []
        }
        distribution = Counter()
        for threat in threats:
            sources = {
                str(item.get("source_type") or "").lower()
                for item in (threat.evidence_details or [])
            }
            source_score = max((SOURCE_WEIGHT.get(item, 0.5) for item in sources), default=0.35)
            if threat.finding_type in {"code", "iac"}:
                source_score = max(source_score, 0.98)
            source_refs = {str(item.get("source_ref") or "") for item in (threat.evidence_details or [])}
            declared_issue = any(ref.startswith("K") and ref[1:].isdigit() for ref in source_refs)
            if declared_issue:
                source_score = max(source_score, 0.97)

            scoped = bool(threat.affected_components or threat.affected_data_flows or threat.affected_assets)
            score = source_score + (0.04 if scoped else -0.18)
            flow_ref = (threat.data_flow or threat.related_data_flow or "").replace(" â†’ ", "->")
            flow = flows.get(flow_ref)
            if flow and flow.assumed:
                score -= 0.12
            if not threat.root_cause or not (threat.attack_scenario or threat.realistic_attack_scenario):
                score -= 0.05
            direct = bool(sources & DIRECT_SOURCES) or threat.finding_type in {"code", "iac"}
            if not direct and threat.explanation and threat.explanation.get("local_stride_review", {}).get("decision"):
                review = threat.explanation["local_stride_review"]
                if review.get("predicted_category") not in {None, "Unknown", threat.stride_category, threat.category}:
                    score -= 0.05
            score = round(min(0.99, max(0.05, score)), 2)

            control_state = (threat.explanation or {}).get("control_state")
            if control_state == "unknown":
                score = min(score, 0.74)
            if declared_issue:
                score = max(score, 0.9)

            label = "High" if score >= 0.8 else "Medium" if score >= 0.55 else "Low"
            threat.confidence_score = score
            threat.confidence = label
            threat.tier = "Confirmed" if direct and score >= 0.8 and control_state != "unknown" else "Potential"
            threat.explanation = {
                **(threat.explanation or {}),
                "confidence_calibration": {
                    "score": score,
                    "label": label,
                    "direct_evidence": direct,
                    "evidence_sources": sorted(sources),
                    "scoped": scoped,
                    "assumed_flow": bool(flow and flow.assumed),
                    "version": "confidence-1.0",
                },
            }
            distribution[f"{threat.tier}:{label}"] += 1

        return threats, {
            "status": "active",
            "version": "confidence-1.0",
            "distribution": dict(distribution),
            "policy": "Confirmed requires direct evidence, canonical scope, and confidence score >= 0.80.",
        }
