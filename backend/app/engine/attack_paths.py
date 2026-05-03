from typing import Dict, List


def generate_attack_paths(system_model) -> List[Dict]:
    components = {component.id: component for component in system_model.components or []}
    flows = system_model.flows or []
    paths: List[Dict] = []

    for flow in flows:
        source = components.get(flow.source_id)
        target = components.get(flow.target_id)
        if not source or not target:
            continue

        source_exposed = source.trust_level in {"public", "external"} or (source.properties or {}).get("public_access")
        target_sensitive = (target.properties or {}).get("data_sensitivity") in {"pii", "financial", "credentials", "phi", "secrets"}

        if source_exposed and target.type in {"API", "Service", "ML Service"}:
            steps = [
                f"Attacker reaches exposed component {source.name}",
                f"Traffic flows to {target.name} over {flow.protocol}",
            ]
            impact = "Unauthorized access"

            if (target.properties or {}).get("auth_type") in {None, "", "none"}:
                steps.append(f"Missing or weak authentication on {target.name} allows direct action execution")
                impact = "Account or service compromise"

            if target.type == "ML Service" or (target.properties or {}).get("ml_pipeline"):
                steps.extend([
                    f"Untrusted content is processed by {target.name}",
                    "Prompt or tool execution context is manipulated",
                ])
                impact = "Prompt injection or data exfiltration"

            if target_sensitive:
                steps.append(f"Sensitive data handled by {target.name} becomes reachable from the exposed path")
                impact = "Sensitive data disclosure"

            paths.append({
                "entry_point": source.name,
                "steps": steps,
                "impact": impact,
                "related_flow": f"{flow.source_id}->{flow.target_id}",
            })

        if target.trust_level == "external" and (source.properties or {}).get("data_sensitivity") in {"pii", "financial", "credentials", "phi", "secrets"}:
            paths.append({
                "entry_point": source.name,
                "steps": [
                    f"Application component {source.name} prepares sensitive records",
                    f"Sensitive data traverses {flow.protocol} to external integration {target.name}",
                    "Insufficient egress validation or minimization exposes more data than intended",
                ],
                "impact": "Third-party data leakage",
                "related_flow": f"{flow.source_id}->{flow.target_id}",
            })

    return paths
