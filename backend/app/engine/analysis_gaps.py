from typing import Dict, List


def detect_missing_elements(system_model) -> List[Dict[str, str]]:
    gaps: List[Dict[str, str]] = []
    components = system_model.components or []
    flows = system_model.flows or []

    if components and not flows:
        gaps.append({
            "type": "missing_data_flows",
            "message": "No explicit data flows were provided; communication paths were inferred heuristically.",
        })
    elif any(getattr(flow, "assumed", False) for flow in flows):
        gaps.append({
            "type": "missing_data_flows",
            "message": "Some data flows were missing and had to be inferred. Validate source, destination, and protocol details.",
        })

    auth_components = [component for component in components if component.type in {"API", "Service", "API Gateway", "Identity Provider"}]
    if auth_components and any((component.properties or {}).get("auth_type") in {None, "", "none"} for component in auth_components):
        gaps.append({
            "type": "missing_auth_model",
            "message": "One or more exposed application components do not have a defined authentication or authorization model.",
        })

    storage_types = {"Database", "Object Storage", "Data Warehouse", "Secrets Manager"}
    if not any(component.type in storage_types for component in components):
        gaps.append({
            "type": "missing_storage_layer",
            "message": "No storage layer was identified. Confirm where application data, logs, and secrets are stored.",
        })

    external_components = [
        component for component in components
        if (component.properties or {}).get("external") or component.trust_level == "external"
    ]
    if external_components and not any(
        flow.target_id in {component.id for component in external_components} or flow.source_id in {component.id for component in external_components}
        for flow in flows
    ):
        gaps.append({
            "type": "undefined_external_integrations",
            "message": "External integrations were referenced but the specific interaction flows are undefined.",
        })

    return gaps
