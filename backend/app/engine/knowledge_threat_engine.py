"""Execute normalized knowledge-base predicates against the canonical model."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from ..models import Threat


AI_RULE_MODULES = {
    "custom_ai_llm_threats.json", "ai_agent_threats.json",
    "rag_vector_store_threats.json",
}


class KnowledgeThreatEngine:
    def __init__(self, knowledge_base):
        self.knowledge_base = knowledge_base

    def analyze(self, architecture, allowed_modules: Optional[List[str]] = None) -> Tuple[List[Threat], Dict[str, Any]]:
        findings: List[Threat] = []
        evaluated = 0
        applicable = 0
        skipped_by_route = 0
        allowed = set(allowed_modules or [])
        for component in architecture.components or []:
            props = component.properties or {}
            for typed_rule in self.knowledge_base.get_typed_rules():
                rule = typed_rule.model_dump()
                if allowed and rule.get("source_module") not in allowed:
                    skipped_by_route += 1
                    continue
                detection = rule.get("detection") or {}
                if not detection.get("auto_detectable") or not detection.get("logic"):
                    continue
                evaluated += 1
                if rule.get("source_module") in AI_RULE_MODULES and not _ai_rule_scope(component):
                    continue
                if not _component_matches(component, rule):
                    continue
                if _negated_by_control(props, rule):
                    continue
                applicable += 1
                matched, evidence_fields = _evaluate_logic(detection["logic"], props)
                if not matched:
                    continue
                evidence = _component_evidence(component, evidence_fields)
                confidence = "High" if _has_direct_evidence(component, evidence_fields) else "Medium"
                findings.append(_to_threat(rule, component, evidence, confidence, evidence_fields))

        diagnostics = {
            "engine": "normalized_kb_predicates",
            "rules": len(self.knowledge_base.get_all_threats()),
            "predicates_evaluated": evaluated,
            "applicable_predicates": applicable,
            "findings": len(findings),
            "skipped_by_specialist_route": skipped_by_route,
            "active_modules": sorted(allowed),
        }
        return findings, diagnostics


# The knowledge base and the canonical model name some things differently, and
# a name that never matches disables the predicate silently: every rule about a
# bucket, including unencrypted storage and public access, skipped Object Storage
# components because "storagebucket" shares no substring with "object storage".
_RESOURCE_TYPE_SYNONYMS: Dict[str, Tuple[str, ...]] = {
    "storagebucket": ("object storage", "bucket", "blob storage", "file store", "data lake"),
    "cache": ("redis", "memcached", "elasticache"),
}


def _component_matches(component, rule: Dict[str, Any]) -> bool:
    expected = {str(item).lower() for item in rule.get("components") or ["Any"]}
    if "any" in expected:
        return True
    expected |= {
        synonym
        for candidate in tuple(expected)
        for synonym in _RESOURCE_TYPE_SYNONYMS.get(candidate, ())
    }
    component_tokens = {
        component.type.lower(), component.id.lower(), component.name.lower(),
        str((component.properties or {}).get("db_type") or "").lower(),
        str((component.properties or {}).get("iac_resource_type") or "").lower(),
    }
    # Spacing is not meaning: a rule written for "IdentityProvider" is about the
    # same component as one written for "Identity Provider", and comparing the
    # two literally left the rule matching nothing at all.
    expected = {_squashed(candidate) for candidate in expected if candidate}
    component_tokens = {_squashed(token) for token in component_tokens if token}
    return any(
        candidate and any(candidate == token or candidate in token or token in candidate for token in component_tokens if token)
        for candidate in expected
    )


def _squashed(value: str) -> str:
    return re.sub(r"[\s_-]+", "", value)


def _ai_rule_scope(component) -> bool:
    props = component.properties or {}
    return bool(
        component.type == "ML Service"
        or props.get("ai_scope")
        or props.get("vector_store")
        or props.get("agentic")
        or props.get("mcp_enabled")
    )


def _negated_by_control(props: Dict[str, Any], rule: Dict[str, Any]) -> bool:
    """Suppress a candidate when the architecture explicitly states a negating control."""
    assertions = props.get("control_assertions") or {}
    for control in rule.get("negating_controls") or []:
        normalized = str(control).strip().lower().replace(" ", "_").replace("-", "_")
        if assertions.get(normalized) == "present":
            return True
        value = props.get(normalized)
        if value is True or (isinstance(value, str) and value not in {"", "none", "unknown"}):
            return True
    return False


def _evaluate_logic(logic: Dict[str, Any], props: Dict[str, Any]) -> Tuple[bool, List[str]]:
    operator = str(logic.get("operator") or "AND").upper()
    results = []
    fields = []
    for condition in logic.get("conditions") or []:
        if "conditions" in condition:
            matched, nested_fields = _evaluate_logic(condition, props)
            results.append(matched)
            fields.extend(nested_fields)
            continue
        field = str(condition.get("field") or "")
        if not field:
            continue
        actual = _nested_value(props, field)
        expected = condition.get("value")
        op = str(condition.get("op") or "==").lower()
        explicit_negations = set(props.get("explicit_negations") or [])
        results.append(_compare(actual, expected, op, explicitly_absent=field in explicit_negations))
        fields.append(field)
    if not results:
        return False, fields
    return (any(results) if operator == "OR" else all(results)), fields


def _nested_value(props: Dict[str, Any], field: str) -> Any:
    value: Any = props
    for part in field.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _compare(actual: Any, expected: Any, op: str, explicitly_absent: bool = False) -> bool:
    if op in {"==", "eq"}:
        return actual == expected
    if op in {"!=", "ne"}:
        return actual is not None and actual != expected
    if op == "in":
        return actual in (expected or [])
    if op in {"not_in", "not in"}:
        return actual is not None and actual not in (expected or [])
    if op in {"exists", "is_set"}:
        return actual is not None
    if op in {"missing", "not_set"}:
        return explicitly_absent
    if op in {"contains"}:
        return expected in actual if isinstance(actual, (str, list, tuple, set)) else False
    return False


def _has_direct_evidence(component, fields: List[str]) -> bool:
    props = component.properties or {}
    explicit_negations = set(props.get("explicit_negations") or [])
    if component.confidence != "High":
        return False
    for field in fields:
        value = props.get(field)
        if field in explicit_negations or (value is not None and value != "unknown"):
            return True
    return False


def _component_evidence(component, fields: List[str]) -> List[Dict[str, Any]]:
    evidence = list(component.evidence or [])
    props = component.properties or {}
    assertions = ", ".join(f"{field}={props.get(field)!r}" for field in fields)
    evidence.append({
        "source_type": "rule_evaluation",
        "source_ref": component.id,
        "line": None,
        "statement": f"Matched component properties: {assertions}",
        "confidence": "High" if component.confidence == "High" else "Medium",
    })
    return evidence


def _to_threat(rule: Dict[str, Any], component, evidence: List[Dict[str, Any]], confidence: str,
               matched_controls: Optional[List[str]] = None) -> Threat:
    severity = rule.get("severity") or "Medium"
    category = rule.get("stride_category") or rule.get("category") or "Unknown"
    return Threat(
        id=f"KB-{rule['id']}-{component.id}",
        category=category,
        stride_category=category,
        title=rule.get("title") or rule["id"],
        description=rule.get("description") or rule.get("attack_vector") or rule["id"],
        severity=severity,
        severity_source="rule",
        likelihood=rule.get("likelihood") or "Medium",
        impact="High" if severity in {"Critical", "High"} else "Medium",
        confidence=confidence,
        tier="Confirmed" if confidence == "High" else "Potential",
        finding_type="control_gap",
        mitigation=rule.get("mitigation") or "Implement and verify the required security control.",
        component=component.id,
        affected_component=component.id,
        component_id=component.id,
        affected_components=[component.id],
        root_cause=f"Knowledge-base predicate {rule['id']} matched the canonical component properties.",
        realistic_attack_scenario=rule.get("attack_vector") or rule.get("description"),
        attack_scenario=rule.get("attack_vector") or rule.get("description"),
        evidence=[item["statement"] for item in evidence],
        evidence_details=evidence,
        preconditions=rule.get("preconditions") or [],
        owasp_top_10=rule.get("owasp_top_10") or [],
        cwe=rule.get("cwe") or [],
        mitre_attack=rule.get("mitre_attack") or [],
        mitre_atlas=rule.get("mitre_atlas") or [],
        nist_800_53=rule.get("nist_800_53") or [],
        exposure="public" if component.trust_level in {"public", "external"} else "internal",
        data_sensitivity=(component.properties or {}).get("data_sensitivity") or "internal",
        exploit_complexity="Low" if component.trust_level in {"public", "external"} else "Medium",
        privilege_required="None" if component.trust_level in {"public", "external"} else "Low",
        # Which control decided the finding, so a second route to the same
        # problem can recognise it instead of reporting it again.
        explanation={"matched_controls": sorted(set(matched_controls or ()))},
    )
