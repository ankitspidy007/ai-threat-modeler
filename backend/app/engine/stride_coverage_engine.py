"""Exhaustive STRIDE applicability and coverage assessment."""

from __future__ import annotations

import re
from collections import Counter
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..models import Threat


STRIDE_CATEGORIES = (
    "Spoofing", "Tampering", "Repudiation", "Information Disclosure",
    "Denial of Service", "Elevation of Privilege",
)

CATEGORY_CODE = {
    "Spoofing": "S", "Tampering": "T", "Repudiation": "R",
    "Information Disclosure": "I", "Denial of Service": "D",
    "Elevation of Privilege": "E",
}

ACTIVE_COMPONENTS = {
    "API", "API Gateway", "Service", "ML Service", "WebClient", "Mobile App",
    "Identity Provider", "Queue", "IoT Device", "Load Balancer", "CDN",
}
DATA_COMPONENTS = {"Database", "Object Storage", "Data Warehouse", "Secrets Manager", "Backup"}


class StrideCoverageEngine:
    def assess(self, architecture, existing_threats: List[Threat], generate_candidates: bool = True) -> Tuple[List[Threat], Dict[str, Any]]:
        elements = list(self._elements(architecture))
        existing_index = self._finding_index(existing_threats)
        unknown_candidate_targets = _select_unknown_candidate_targets(elements, existing_index)
        cells: List[Dict[str, Any]] = []
        candidates: List[Threat] = []

        for element in elements:
            for category in STRIDE_CATEGORIES:
                applicable, rationale = _applicability(element, category)
                if not applicable:
                    cells.append(_cell(element, category, "not_applicable", rationale, [], []))
                    continue

                linked = existing_index.get((element["id"], category), [])
                if linked:
                    cells.append(_cell(
                        element, category, "finding", "One or more findings cover this STRIDE cell.",
                        [threat.id for threat in linked], [],
                    ))
                    continue

                control_state, controls, control_rationale = _control_state(element, category)
                status = "control_present" if control_state == "present" else "finding" if control_state == "absent" else "unknown"
                candidate: Optional[Threat] = None
                # Explicitly absent controls are findings. For architecture-only
                # input, surface one representative, high-value Potential threat
                # per unresolved STRIDE category. This gives users an actionable
                # threat model without mislabeling an unspecified control as a
                # confirmed vulnerability.
                should_surface_unknown = (
                    control_state == "unknown"
                    and unknown_candidate_targets.get(category) == element["id"]
                )
                if generate_candidates and (control_state == "absent" or should_surface_unknown):
                    candidate = _candidate_threat(element, category, control_state, controls)
                    candidates.append(candidate)
                    status = "finding" if control_state == "absent" else "potential"
                cells.append(_cell(
                    element, category, status, control_rationale,
                    [candidate.id] if candidate else [], controls,
                ))

        status_counts = Counter(cell["status"] for cell in cells)
        category_summary = {}
        for category in STRIDE_CATEGORIES:
            category_cells = [cell for cell in cells if cell["category"] == category]
            category_summary[category] = dict(Counter(cell["status"] for cell in category_cells))

        assessed = len(cells) - status_counts.get("not_applicable", 0)
        resolved = status_counts.get("finding", 0) + status_counts.get("control_present", 0)
        unresolved = status_counts.get("unknown", 0) + status_counts.get("potential", 0)
        coverage = {
            "version": "stride-coverage-3.0",
            "categories": list(STRIDE_CATEGORIES),
            "elements_assessed": len(elements),
            "applicable_cells": assessed,
            "resolved_cells": resolved,
            "unknown_cells": unresolved,
            "assessment_percent": 100.0,
            "evidence_resolution_percent": round((resolved / assessed) * 100, 1) if assessed else 100.0,
            # Compatibility for existing clients. This measures evidence
            # resolution, not whether every category was assessed.
            "coverage_percent": round((resolved / assessed) * 100, 1) if assessed else 100.0,
            "status_counts": dict(status_counts),
            "category_summary": category_summary,
            "elements": elements,
            "cells": cells,
            "guarantee": "Every modeled element was evaluated for every STRIDE category; selected unknown-control cells are visible only as Potential architecture threats, never as confirmed vulnerabilities.",
        }
        return candidates, coverage

    @staticmethod
    def _finding_index(threats: List[Threat]) -> Dict[Tuple[str, str], List[Threat]]:
        index: Dict[Tuple[str, str], List[Threat]] = {}
        for threat in threats:
            category = threat.stride_category or threat.category
            coverage_element_id = (threat.explanation or {}).get("coverage_element_id")
            if coverage_element_id:
                index.setdefault((coverage_element_id, category), []).append(threat)
            component_ids = set(threat.affected_components or [])
            if threat.component:
                component_ids.add(threat.component)
            if threat.affected_component:
                component_ids.add(threat.affected_component)
            for component_id in component_ids:
                index.setdefault((component_id, category), []).append(threat)
            flow_refs = set((threat.affected_data_flows or []))
            if threat.data_flow:
                flow_refs.add(threat.data_flow)
            if threat.related_data_flow:
                flow_refs.add(threat.related_data_flow)
            for flow_ref in flow_refs:
                normalized = flow_ref.replace(" → ", "->")
                index.setdefault((f"flow:{normalized}", category), []).append(threat)
            for asset in threat.affected_assets or ([] if not threat.asset else [threat.asset]):
                index.setdefault((f"asset:{asset}", category), []).append(threat)
        return index

    @staticmethod
    def _elements(architecture) -> Iterable[Dict[str, Any]]:
        for component in architecture.components or []:
            yield {
                "id": component.id,
                "name": component.name,
                "kind": "component",
                "type": component.type,
                "trust_level": component.trust_level,
                "properties": component.properties or {},
                "evidence": component.evidence or [],
                "confidence": component.confidence,
            }
        for flow in architecture.flows or []:
            yield {
                "id": f"flow:{flow.source_id}->{flow.target_id}",
                "name": f"{flow.source_id} -> {flow.target_id}",
                "kind": "flow",
                "type": "Data Flow",
                "trust_level": (flow.properties or {}).get("trust_boundary", "unknown"),
                "properties": {**(flow.properties or {}), "protocol": flow.protocol, "data_type": flow.data_type, "assumed": flow.assumed},
                "evidence": flow.evidence or [],
                "confidence": flow.confidence,
            }
        for asset in architecture.assets or []:
            yield {
                "id": f"asset:{asset.name}",
                "name": asset.name,
                "kind": "asset",
                "type": asset.asset_type,
                "trust_level": "restricted" if asset.sensitivity not in {"public", "internal"} else "internal",
                "properties": {"sensitivity": asset.sensitivity, "location": asset.location},
                "evidence": asset.evidence or [],
                "confidence": asset.confidence,
            }
        for boundary in architecture.trust_boundaries or []:
            yield {
                "id": f"boundary:{boundary.name}",
                "name": boundary.name,
                "kind": "boundary",
                "type": boundary.boundary_type,
                "trust_level": boundary.boundary_type,
                "properties": {"components": boundary.components},
                "evidence": boundary.evidence or [],
                "confidence": boundary.confidence,
            }
        for actor in (architecture.metadata or {}).get("actors", []):
            yield {
                "id": f"actor:{actor['id']}",
                "name": actor["name"],
                "kind": "actor",
                "type": "Actor",
                "trust_level": "external" if actor["id"] in {"user", "customer", "partner", "vendor", "attacker"} else "internal",
                "properties": actor,
                "evidence": [],
                "confidence": "High",
            }


def _applicability(element: Dict[str, Any], category: str) -> Tuple[bool, str]:
    kind = element["kind"]
    component_type = element["type"]
    props = element["properties"]
    if kind == "component":
        if component_type in ACTIVE_COMPONENTS:
            return True, f"{category} applies to active process or identity component {element['name']}."
        if component_type in DATA_COMPONENTS:
            if category == "Spoofing" and not (props.get("db_type") == "redis" or props.get("data_sensitivity") in {"credentials", "secrets"}):
                return False, "Identity spoofing is assessed on the access process unless the store holds sessions or credentials."
            return True, f"{category} applies to protected data component {element['name']}."
        if component_type == "Compute":
            return category in {"Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege"}, "Compute is assessed for host integrity, accountability, confidentiality, availability, and workload privilege."
        return category in {"Tampering", "Repudiation", "Information Disclosure", "Denial of Service"}, "Infrastructure elements are assessed for integrity, accountability, confidentiality, and availability."
    if kind == "flow":
        if category == "Elevation of Privilege" and props.get("data_type") not in {"credentials", "secrets", "pii", "phi", "financial"}:
            return False, "Privilege escalation is assessed on this flow only when it carries privileged or sensitive context."
        return True, f"{category} applies to data moving across this interaction."
    if kind == "asset":
        if category == "Spoofing":
            return False, "Assets do not authenticate; spoofing is assessed on actors and access processes."
        return True, f"{category} applies to the confidentiality, integrity, accountability, availability, or authorization of this asset."
    if kind == "boundary":
        if category == "Repudiation":
            return False, "Repudiation is assessed on actions and flows crossing this boundary."
        return True, f"{category} applies at this trust transition."
    if kind == "actor":
        return category in {"Spoofing", "Repudiation", "Elevation of Privilege"}, "Actors are assessed for identity, accountability, and privilege abuse."
    return False, "The category is not applicable to this element type."


def _control_state(element: Dict[str, Any], category: str) -> Tuple[str, List[str], str]:
    props = element["properties"]
    kind = element["kind"]
    controls = _expected_controls(kind, category)
    values = []
    for control in controls:
        if control == "transport_encryption":
            protocol = str(props.get("protocol") or "").lower()
            values.append(True if protocol in {"https", "tls", "mtls", "wss", "grpcs"} else False if protocol in {"http", "ws"} else None)
        elif control == "authorization":
            values.append(True if props.get("rbac_enabled") or props.get("abac_enabled") else False if props.get("authorization") == "none" else None)
        elif control == "resilience":
            values.append(True if any(props.get(key) for key in ("multi_region", "replication", "backup_enabled", "autoscaling")) else None)
        elif control == "integrity_validation":
            values.append(True if any(props.get(key) for key in ("input_validation", "webhook_signature_validation", "container_image_provenance")) else False if props.get("input_validation") is False else None)
        else:
            values.append(props.get(control))

    if any(value is False or value == "none" for value in values):
        return "absent", controls, f"A relevant control is explicitly absent: {', '.join(controls)}."
    if any(value is True or (isinstance(value, str) and value not in {"", "none", "unknown"}) for value in values):
        return "present", controls, f"At least one relevant control is stated: {', '.join(controls)}."
    return "unknown", controls, f"The architecture does not specify: {', '.join(controls)}."


def _expected_controls(kind: str, category: str) -> List[str]:
    mapping = {
        "Spoofing": ["auth_type", "mfa_enabled", "mtls_enabled"],
        "Tampering": ["integrity_validation", "input_validation"],
        "Repudiation": ["audit_logging", "logging_enabled"],
        "Information Disclosure": ["encryption_at_rest", "encryption_in_transit", "transport_encryption", "dlp_enabled"],
        "Denial of Service": ["rate_limiting", "waf_enabled", "resilience"],
        "Elevation of Privilege": ["authorization", "rbac_enabled", "abac_enabled"],
    }
    controls = mapping[category]
    if kind == "flow":
        return {
            "Spoofing": ["mtls_enabled", "auth_type"],
            "Tampering": ["integrity_validation", "webhook_signature_validation"],
            "Repudiation": ["audit_logging", "logging_enabled"],
            "Information Disclosure": ["transport_encryption"],
            "Denial of Service": ["rate_limiting"],
            "Elevation of Privilege": ["authorization"],
        }[category]
    if kind == "actor":
        return {"Spoofing": ["auth_type", "mfa_enabled"], "Repudiation": ["audit_logging"], "Elevation of Privilege": ["authorization"]}.get(category, controls)
    return controls


def _risk_relevant(element: Dict[str, Any], category: str) -> bool:
    props = element["properties"]
    trust = element["trust_level"]
    kind = element["kind"]
    component_type = element["type"]
    sensitive = props.get("data_sensitivity") in {"pii", "phi", "financial", "credentials", "secrets"} or props.get("sensitivity") not in {None, "public", "internal"}
    if kind == "flow":
        return not props.get("assumed") and bool(
            props.get("crosses_trust_boundary") or trust in {"internet", "external"}
            or props.get("data_type") in {"pii", "phi", "financial", "credentials", "secrets"}
        )
    if kind in {"boundary", "actor", "asset"}:
        return False
    if trust in {"public", "external"}:
        return True
    if component_type == "Identity Provider":
        return category in {"Spoofing", "Repudiation", "Denial of Service", "Elevation of Privilege"}
    if component_type == "Compute":
        return category in {"Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege"}
    if component_type == "Object Storage":
        return category in {"Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege"}
    if component_type in DATA_COMPONENTS and sensitive:
        return category in {"Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege"}
    if props.get("db_type") == "redis" and category in {"Spoofing", "Tampering", "Information Disclosure", "Denial of Service"}:
        return True
    if component_type in {"API", "API Gateway", "Service", "ML Service"}:
        return category in {"Spoofing", "Elevation of Privilege"}
    return False


def _select_unknown_candidate_targets(
    elements: List[Dict[str, Any]],
    existing_index: Dict[Tuple[str, str], List[Threat]],
) -> Dict[str, str]:
    """Choose one representative unresolved element for each STRIDE category."""
    selected: Dict[str, Tuple[int, str]] = {}
    for element in elements:
        for category in STRIDE_CATEGORIES:
            applicable, _ = _applicability(element, category)
            if not applicable or existing_index.get((element["id"], category)):
                continue
            state, _, _ = _control_state(element, category)
            if state != "unknown" or not _risk_relevant(element, category):
                continue
            score = _unknown_candidate_priority(element, category)
            current = selected.get(category)
            if current is None or score > current[0]:
                selected[category] = (score, element["id"])
    return {category: item[1] for category, item in selected.items()}


def _unknown_candidate_priority(element: Dict[str, Any], category: str) -> int:
    component_type = element["type"]
    public = element["trust_level"] in {"public", "external"}
    preferences = {
        "Spoofing": {"Identity Provider": 100, "API": 90, "WebClient": 85, "Service": 75},
        "Tampering": {"API": 100, "WebClient": 95, "Object Storage": 90, "Compute": 85},
        "Repudiation": {"Identity Provider": 100, "Compute": 95, "API": 90, "Object Storage": 85},
        "Information Disclosure": {"Object Storage": 100, "Database": 100, "API": 90, "WebClient": 80, "Compute": 75},
        "Denial of Service": {"WebClient": 100, "API": 100, "Compute": 95, "Identity Provider": 90},
        "Elevation of Privilege": {"Compute": 100, "API": 95, "Identity Provider": 90, "Object Storage": 85},
    }
    return preferences.get(category, {}).get(component_type, 50) + (10 if public else 0)


def _candidate_threat(element: Dict[str, Any], category: str, state: str, controls: List[str]) -> Threat:
    code = CATEGORY_CODE[category]
    element_id = re.sub(r"[^A-Za-z0-9]+", "-", element["id"]).strip("-").upper()
    explicit_absence = state == "absent"
    confidence = "High" if explicit_absence and element["confidence"] == "High" else "Medium"
    title = _title(category, element)
    mitigation = _mitigation(category, controls)
    evidence_details = list(element.get("evidence") or [])
    evidence_details.append({
        "source_type": "coverage_assessment",
        "source_ref": element["id"],
        "line": None,
        "statement": (
            f"Required controls explicitly absent: {', '.join(controls)}."
            if explicit_absence else f"Required controls not specified: {', '.join(controls)}."
        ),
        "confidence": confidence,
    })
    component = element["id"] if element["kind"] == "component" else None
    flow = element["id"].removeprefix("flow:") if element["kind"] == "flow" else None
    asset = element["name"] if element["kind"] == "asset" else None
    severity = "High" if explicit_absence and (element["trust_level"] in {"public", "external"} or category in {"Information Disclosure", "Elevation of Privilege"}) else "Medium"
    return Threat(
        id=f"STRIDE-{code}-{element_id}",
        category=category,
        stride_category=category,
        title=title,
        description=f"{category} was assessed for {element['name']}; the required control set is {'explicitly absent' if explicit_absence else 'not documented'}.",
        severity=severity,
        likelihood="High" if explicit_absence else "Medium",
        impact="High" if severity == "High" else "Medium",
        confidence=confidence,
        tier="Confirmed" if confidence == "High" else "Potential",
        finding_type="control_gap" if explicit_absence else "validation_question",
        affected_stride_categories=[category],
        mitigation=mitigation,
        specific_control=", ".join(controls),
        implementation_detail=mitigation,
        component=component,
        affected_component=component,
        component_id=component,
        data_flow=flow,
        related_data_flow=flow,
        asset=asset,
        affected_components=[component] if component else [],
        affected_data_flows=[flow] if flow else [],
        affected_assets=[asset] if asset else [],
        root_cause=f"The architecture does not establish the {category} control contract for {element['name']}.",
        realistic_attack_scenario=_scenario(category, element),
        attack_scenario=_scenario(category, element),
        evidence=[item["statement"] for item in evidence_details],
        evidence_details=evidence_details,
        preconditions=[f"The attacker can interact with or reach {element['name']} under the modeled trust assumptions."],
        exposure="public" if element["trust_level"] in {"public", "external"} else "internal",
        data_sensitivity=element["properties"].get("data_sensitivity") or element["properties"].get("sensitivity") or "internal",
        exploit_complexity="Low" if explicit_absence else "Medium",
        privilege_required="None" if element["trust_level"] in {"public", "external"} else "Low",
        explanation={"coverage_element_id": element["id"], "control_state": state},
    )


def _cell(element: Dict[str, Any], category: str, status: str, rationale: str, finding_ids: List[str], controls: List[str]) -> Dict[str, Any]:
    return {
        "element_id": element["id"], "element_name": element["name"],
        "element_kind": element["kind"], "element_type": element["type"],
        "category": category, "status": status, "rationale": rationale,
        "finding_ids": finding_ids, "controls": controls,
    }


def _title(category: str, element: Dict[str, Any]) -> str:
    component_type = element["type"]
    specialized = {
        ("Spoofing", "API"): "Backend token validation and identity enforcement require validation",
        ("Spoofing", "Identity Provider"): "Identity-provider token and session controls require validation",
        ("Tampering", "WebClient"): "Public web input and request-integrity controls require validation",
        ("Repudiation", "Identity Provider"): "Identity security audit trails require validation",
        ("Information Disclosure", "Object Storage"): "Object-storage access and encryption controls require validation",
        ("Denial of Service", "WebClient"): "Public website rate limiting and availability controls require validation",
        ("Denial of Service", "API"): "API rate limiting and resource bounds require validation",
        ("Elevation of Privilege", "Compute"): "Compute workload identity and instance-role privilege require validation",
    }
    if (category, component_type) in specialized:
        return f"{specialized[(category, component_type)]} for {element['name']}"
    titles = {
        "Spoofing": "Identity spoofing controls require validation",
        "Tampering": "Integrity and tampering controls require validation",
        "Repudiation": "Security auditability requires validation",
        "Information Disclosure": "Sensitive-data disclosure controls require validation",
        "Denial of Service": "Availability and resource-exhaustion controls require validation",
        "Elevation of Privilege": "Authorization and least-privilege controls require validation",
    }
    return f"{titles[category]} for {element['name']}"


def _mitigation(category: str, controls: List[str]) -> str:
    guidance = {
        "Spoofing": "Define strong workload or user authentication, token validation, replay protection, and MFA or mTLS where applicable.",
        "Tampering": "Validate untrusted input, authenticate messages, enforce integrity checks, and protect deployment and data modification paths.",
        "Repudiation": "Emit identity-bound, tamper-evident audit events with synchronized timestamps, protected retention, and alerting.",
        "Information Disclosure": "Enforce least-privilege data access, transport and storage encryption, data minimization, and egress controls.",
        "Denial of Service": "Define quotas, rate limits, timeouts, bounded workloads, autoscaling, redundancy, and tested recovery objectives.",
        "Elevation of Privilege": "Enforce server-side authorization, tenant and object ownership checks, scoped workload identity, and separation of duties.",
    }
    return f"Validate and implement {', '.join(controls)}. {guidance[category]}"


def _scenario(category: str, element: Dict[str, Any]) -> str:
    actions = {
        "Spoofing": "impersonates a trusted user, workload, or partner",
        "Tampering": "alters requests, messages, configuration, or stored data",
        "Repudiation": "performs a sensitive action that cannot be reliably attributed",
        "Information Disclosure": "obtains protected data through an insufficiently defined confidentiality boundary",
        "Denial of Service": "exhausts a bounded resource or disrupts a critical dependency",
        "Elevation of Privilege": "bypasses authorization or abuses an over-privileged identity",
    }
    return f"An attacker who can reach {element['name']} {actions[category]} because the required control contract is absent or unspecified."
