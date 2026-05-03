from typing import Dict, List


def generate_attack_paths(system_model, threats) -> List[Dict]:
    components = {component.id: component for component in system_model.components or []}
    flows = {f"{flow.source_id}->{flow.target_id}": flow for flow in system_model.flows or []}
    paths: List[Dict] = []

    for threat in threats:
        component_id = threat.component or threat.affected_component or threat.component_id
        flow_ref = threat.data_flow or threat.related_data_flow
        asset_name = threat.asset or (threat.affected_assets[0] if getattr(threat, "affected_assets", None) else None)
        component = components.get(component_id) if component_id else None
        flow = flows.get(flow_ref) if flow_ref else None

        if threat.id.startswith("CTX-AI") or "prompt injection" in (threat.title or "").lower():
            rag_steps = _build_rag_steps(system_model, threat)
            paths.append({
                "entry_point": rag_steps[0],
                "steps": rag_steps[1:],
                "target_component": component.name if component else "ML Service",
                "impact": threat.business_impact or threat.impact or "Model decision manipulation",
                "related_threat_id": threat.id,
            })
            continue

        steps = []
        entry_point = component.name if component else "System entry point"
        if flow and flow.source_id in components:
            source = components[flow.source_id]
            target = components.get(flow.target_id)
            entry_point = source.name
            steps.append(f"Attacker reaches {source.name} through the exposed or trusted interaction path.")
            steps.append(f"Traffic follows system flow {source.name} -> {target.name if target else flow.target_id} over {flow.protocol}.")
        elif component:
            steps.append(f"Attacker targets component {component.name}.")

        if threat.attack_scenario or threat.realistic_attack_scenario:
            steps.append(threat.attack_scenario or threat.realistic_attack_scenario)
        if asset_name:
            steps.append(f"The attack reaches protected asset {asset_name}.")

        paths.append({
            "entry_point": entry_point,
            "steps": steps,
            "target_component": component.name if component else "Unknown component",
            "impact": threat.business_impact or threat.impact or "Operational impact",
            "related_threat_id": threat.id,
        })

    return paths


def _build_rag_steps(system_model, threat) -> List[str]:
    components = {component.id: component for component in system_model.components or []}
    flow_refs = [flow_ref.replace(" → ", "->") for flow_ref in (threat.affected_data_flows or [])]
    upload_step = "User uploads malicious document or content."
    retrieval_step = "Content is embedded and stored in retrieval memory."
    inference_step = "Retrieved content is injected into model inference context."
    action_step = "Model output manipulates decisioning or triggers unsafe tool execution."

    for flow_ref in flow_refs:
        source_id, _, target_id = flow_ref.partition("->")
        source = components.get(source_id)
        target = components.get(target_id)
        if source and target:
            if "upload" in source.name.lower() or source.trust_level in {"public", "external"}:
                upload_step = f"User-controlled content enters via {source.name}."
            if "vector" in target.name.lower() or "storage" in target.name.lower():
                retrieval_step = f"Content is stored or indexed in {target.name} for retrieval."
            if "ml" in target.type.lower() or "model" in target.name.lower():
                inference_step = f"Retrieved context reaches {target.name} during inference."

    return [upload_step, retrieval_step, inference_step, action_step]
