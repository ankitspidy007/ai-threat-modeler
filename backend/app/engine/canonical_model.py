"""Evidence-aware normalization for the architecture intermediate model."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from ..models import SystemArchitecture


CONTROL_KEYS = (
    "auth_type", "mfa_enabled", "rbac_enabled", "abac_enabled", "input_validation",
    "rate_limiting", "waf_enabled", "encryption_at_rest", "encryption_in_transit",
    "logging_enabled", "audit_logging", "mtls_enabled", "private_subnet",
    "secrets_management", "container_image_provenance", "query_depth_limiting",
    "webhook_signature_validation", "dlp_enabled",
)

BLOCKING_ISSUE_TYPES = {
    "duplicate_component_id", "invalid_flow", "invalid_boundary_membership",
    "contradictory_control",
}


def canonicalize_architecture(architecture: SystemArchitecture) -> Tuple[SystemArchitecture, Dict[str, Any]]:
    """Attach provenance, confidence, actors, identities, and validation gaps.

    The parser remains responsible for extraction. This pass establishes one
    contract for downstream engines, including IaC-created architectures.
    """
    metadata = architecture.metadata or {}
    source_text = metadata.get("source_text") or metadata.get("architecture_text") or ""
    source_documents = metadata.get("source_documents") or []
    component_ids = {component.id for component in architecture.components or []}
    issues: List[Dict[str, Any]] = []
    component_id_counts: Dict[str, int] = {}
    component_name_counts: Dict[str, int] = {}
    for component in architecture.components or []:
        component_id_counts[component.id] = component_id_counts.get(component.id, 0) + 1
        normalized_name = component.name.strip().lower()
        component_name_counts[normalized_name] = component_name_counts.get(normalized_name, 0) + 1
    for component_id, count in component_id_counts.items():
        if count > 1:
            issues.append(_gap(
                "duplicate_component_id", component_id,
                f"Component ID {component_id} is declared {count} times.", "High",
            ))
    for name, count in component_name_counts.items():
        if name and count > 1:
            issues.append(_gap(
                "duplicate_component_name", name,
                f"Component name {name} is declared {count} times.", "Medium",
            ))

    for component in architecture.components or []:
        props = component.properties or {}
        line_number, statement = _find_component_evidence(source_text, component.name, component.id)
        explicit = bool(statement) or bool(props.get("authoritative") or props.get("authoritative_external_entity"))
        component.confidence = "High" if explicit else "Medium"
        component.evidence = component.evidence or [_evidence(
            "architecture_input" if explicit else "inference",
            _source_ref(source_documents),
            statement or f"Component {component.name} inferred from architecture context.",
            line_number,
            component.confidence,
        )]
        props["evidence_status"] = "explicit" if explicit else "inferred"
        props["control_assertions"] = {
            key: _assertion_status(props.get(key)) for key in CONTROL_KEYS
        }
        contradictory = sorted(
            key for key in set(props.get("explicit_negations") or [])
            if props.get(key) is True or (
                isinstance(props.get(key), str) and props.get(key) not in {"", "none", "unknown"}
            )
        )
        if contradictory:
            issues.append(_gap(
                "contradictory_control", component.id,
                f"Control evidence is both present and absent for: {', '.join(contradictory)}.", "High",
            ))
        component.properties = props

        if component.type in {"API", "API Gateway", "Service", "ML Service", "Identity Provider"}:
            if props.get("auth_type") in {None, "", "unknown"}:
                issues.append(_gap(
                    "authentication", component.id,
                    f"Authentication is not specified for {component.name}.",
                    "High" if component.trust_level in {"public", "external"} else "Medium",
                ))
            if not props.get("rbac_enabled") and not props.get("abac_enabled"):
                issues.append(_gap(
                    "authorization", component.id,
                    f"Authorization policy is not specified for {component.name}.", "Medium",
                ))

    flow_keys = set()
    boundary_crossings = []
    for flow in architecture.flows or []:
        explicit = not flow.assumed
        statement = (flow.properties or {}).get("evidence") or (
            f"Explicit flow {flow.source_id} to {flow.target_id}." if explicit
            else f"Flow {flow.source_id} to {flow.target_id} inferred by architecture rules."
        )
        flow.confidence = "High" if explicit else "Medium"
        flow.evidence = flow.evidence or [_evidence(
            "architecture_input" if explicit else "inference",
            _source_ref(source_documents), statement, None, flow.confidence,
        )]
        if flow.source_id not in component_ids or flow.target_id not in component_ids:
            issues.append(_gap(
                "invalid_flow", f"{flow.source_id}->{flow.target_id}",
                "A modeled data flow references a component that does not exist.", "High",
            ))
            continue
        if flow.source_id == flow.target_id:
            issues.append(_gap(
                "self_referential_flow", f"{flow.source_id}->{flow.target_id}",
                "A data flow cannot establish a meaningful trust transition to itself.", "Medium",
            ))
        flow_key = (flow.source_id, flow.target_id, (flow.protocol or "").lower(), flow.data_type)
        if flow_key in flow_keys:
            issues.append(_gap(
                "duplicate_flow", f"{flow.source_id}->{flow.target_id}",
                "The same source, destination, protocol, and data type are modeled more than once.", "Medium",
            ))
        flow_keys.add(flow_key)
        source = next(item for item in architecture.components if item.id == flow.source_id)
        target = next(item for item in architecture.components if item.id == flow.target_id)
        explicit_crossing = bool((flow.properties or {}).get("crosses_trust_boundary"))
        actual_crossing = source.trust_level != target.trust_level
        if explicit_crossing and not actual_crossing:
            issues.append(_gap(
                "boundary_contradiction", f"{flow.source_id}->{flow.target_id}",
                "The flow is marked as boundary-crossing but both endpoints have the same trust level.", "Medium",
            ))
        if actual_crossing:
            boundary_crossings.append({
                "flow": f"{flow.source_id}->{flow.target_id}",
                "source_trust": source.trust_level,
                "target_trust": target.trust_level,
                "explicit": not flow.assumed,
            })

    for boundary in architecture.trust_boundaries or []:
        unknown_members = sorted(set(boundary.components or []) - component_ids)
        if unknown_members:
            issues.append(_gap(
                "invalid_boundary_membership", f"boundary:{boundary.name}",
                f"Trust boundary references unknown components: {', '.join(unknown_members)}.", "High",
            ))
        if not boundary.components:
            issues.append(_gap(
                "empty_boundary", f"boundary:{boundary.name}",
                "Trust boundary does not contain any modeled components.", "Medium",
            ))

    for asset in architecture.assets or []:
        component = next((item for item in architecture.components if item.id == asset.related_component_id), None)
        asset.confidence = component.confidence if component else "Medium"
        asset.evidence = asset.evidence or (component.evidence if component else [_evidence(
            "inference", _source_ref(source_documents),
            f"Asset {asset.name} inferred from storage and data classification.", None, "Medium",
        )])

    if metadata.get("authoritative_model") and metadata.get("actors"):
        actors = metadata["actors"]
        identities = metadata.get("identities", [])
    else:
        actors, identities = _extract_actors_and_identities(source_text, architecture)
    metadata["actors"] = actors
    metadata["identities"] = identities
    metadata["canonical_model_version"] = "3.0"
    metadata["source_provenance"] = source_documents or [{"filename": "architecture input", "role": "source_design"}]
    metadata["boundary_crossings"] = boundary_crossings
    metadata["architecture_contract"] = {
        "component_ids_unique": not any(item["type"] == "duplicate_component_id" for item in issues),
        "flows_resolve": not any(item["type"] == "invalid_flow" for item in issues),
        "boundaries_resolve": not any(item["type"] == "invalid_boundary_membership" for item in issues),
        "controls_consistent": not any(item["type"] == "contradictory_control" for item in issues),
        "evidence_required": True,
    }
    metadata["architecture_ir"] = _architecture_ir(architecture, actors, identities, issues)
    architecture.metadata = metadata

    explicit_flows = sum(1 for flow in architecture.flows or [] if not flow.assumed)
    blocking_issues = [item for item in issues if item["type"] in BLOCKING_ISSUE_TYPES]
    validation = {
        "version": "canonical-3.0",
        "valid": not blocking_issues,
        "issues": issues,
        "quality_gate": {
            "status": "pass" if not blocking_issues else "fail",
            "blocking_issues": len(blocking_issues),
            "high_priority_review_gaps": sum(
                item["severity"] == "High" and item["type"] not in BLOCKING_ISSUE_TYPES for item in issues
            ),
            "warning_issues": sum(item["severity"] != "High" for item in issues),
            "boundary_crossings": len(boundary_crossings),
        },
        "counts": {
            "components": len(architecture.components or []),
            "explicit_components": sum(1 for component in architecture.components or [] if component.confidence == "High"),
            "flows": len(architecture.flows or []),
            "explicit_flows": explicit_flows,
            "inferred_flows": len(architecture.flows or []) - explicit_flows,
            "actors": len(actors),
            "identities": len(identities),
        },
    }
    return architecture, validation


def _find_component_evidence(text: str, name: str, component_id: str) -> Tuple[int | None, str]:
    candidates = {
        name.lower(), component_id.lower().replace("_", " "),
    }
    for index, line in enumerate((text or "").splitlines(), 1):
        lowered = line.lower()
        if any(candidate and re.search(r"(?<![a-z0-9])" + re.escape(candidate) + r"(?![a-z0-9])", lowered) for candidate in candidates):
            return index, line.strip()
    return None, ""


def _extract_actors_and_identities(text: str, architecture: SystemArchitecture) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    actor_terms = ("user", "customer", "admin", "administrator", "doctor", "nurse", "developer", "operator", "partner", "vendor", "attacker")
    actors = []
    lowered = (text or "").lower()
    for actor in actor_terms:
        if re.search(r"(?<![a-z])" + re.escape(actor) + r"s?(?![a-z])", lowered):
            actors.append({"id": actor, "name": actor.title(), "evidence_status": "explicit"})

    identities = []
    for component in architecture.components or []:
        props = component.properties or {}
        if component.type == "Identity Provider" or props.get("auth_type") not in {None, "", "none", "unknown"}:
            identities.append({
                "component_id": component.id,
                "provider": props.get("auth_type") or component.name,
                "mfa": props.get("mfa_enabled"),
                "authorization": "ABAC" if props.get("abac_enabled") else "RBAC" if props.get("rbac_enabled") else "unknown",
                "evidence_status": props.get("evidence_status", "inferred"),
            })
    return actors, identities


def _assertion_status(value: Any) -> str:
    if value is True or (isinstance(value, str) and value not in {"", "none", "unknown"}):
        return "present"
    if value is False or value == "none":
        return "absent"
    return "unknown"


def _source_ref(source_documents: List[Dict[str, Any]]) -> str:
    if source_documents:
        return str(source_documents[0].get("filename") or "uploaded design")
    return "architecture input"


def _evidence(source_type: str, source_ref: str, statement: str, line: int | None, confidence: str) -> Dict[str, Any]:
    return {
        "source_type": source_type,
        "source_ref": source_ref,
        "line": line,
        "statement": statement,
        "confidence": confidence,
    }


def _gap(gap_type: str, scope: str, message: str, severity: str) -> Dict[str, Any]:
    return {"type": gap_type, "scope": scope, "message": message, "severity": severity}


def _architecture_ir(
    architecture: SystemArchitecture,
    actors: List[Dict[str, Any]],
    identities: List[Dict[str, Any]],
    validation_issues: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Return the evidence-backed intermediate representation manifest."""
    return {
        "version": "architecture-ir-1.0",
        "components": [{
            "id": item.id,
            "name": item.name,
            "type": item.type,
            "trust_level": item.trust_level,
            "confidence": item.confidence,
            "evidence": item.evidence,
            "control_assertions": (item.properties or {}).get("control_assertions", {}),
        } for item in architecture.components or []],
        "flows": [{
            "id": f"{item.source_id}->{item.target_id}",
            "source_id": item.source_id,
            "target_id": item.target_id,
            "protocol": item.protocol,
            "data_type": item.data_type,
            "claim_status": "inferred" if item.assumed else "explicit",
            "confidence": item.confidence,
            "evidence": item.evidence,
        } for item in architecture.flows or []],
        "boundaries": [item.model_dump() for item in architecture.trust_boundaries or []],
        "assets": [item.model_dump() for item in architecture.assets or []],
        "actors": actors,
        "identities": identities,
        "unresolved_claims": [
            item for item in validation_issues
            if item["type"] in {"invalid_flow", "invalid_boundary_membership", "contradictory_control"}
        ],
        "contract": "Every downstream engine consumes canonical IDs and provenance from this IR; inferred claims remain distinguishable from explicit source facts.",
    }
