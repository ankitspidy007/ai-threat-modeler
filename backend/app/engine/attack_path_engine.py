"""Evidence-aware attack paths over the canonical architecture graph."""

from __future__ import annotations

from collections import deque
from typing import Dict, List, Optional, Tuple

from . import graph


def generate_attack_paths(system_model, threats) -> List[Dict]:
    components = {component.id: component for component in system_model.components or []}
    flows = list(system_model.flows or [])
    adjacency: Dict[str, List[Tuple[str, object]]] = {}
    for flow in flows:
        adjacency.setdefault(flow.source_id, []).append((flow.target_id, flow))

    entry_points = [
        component.id for component in components.values()
        if component.trust_level in {"public", "external"} or (component.properties or {}).get("public_access")
    ]
    paths: List[Dict] = []
    for threat in threats:
        # Potential control questions are not exploitable attack paths. A path
        # requires a confirmed finding, a mapped target, and a graph-reachable
        # entry point.
        if threat.tier != "Confirmed":
            continue
        target = _target_component(threat, components)
        if not target:
            paths.append(_unresolved_path(threat))
            continue

        route = _best_route(entry_points, target, adjacency)
        if route is None and threat.data_flow:
            source, _, flow_target = threat.data_flow.replace(" → ", "->").partition("->")
            if source in components and flow_target in components:
                flow = next((item for item in flows if item.source_id == source and item.target_id == flow_target), None)
                route = [(source, None), (flow_target, flow)]
        # A finding on a component that faces the public is reached at that
        # component, with no hops before it. This is the last resort rather than
        # a candidate route, because a zero-hop route is always the shortest and
        # would otherwise win over the real path through the architecture,
        # reporting every path as beginning at its own target.
        if route is None and (threat.exposure == "public" or target in entry_points):
            route = [(target, None)]

        if route is None:
            paths.append(
                _component_local_path(threat, target, components)
                if target in components else _unresolved_path(threat)
            )
            continue

        hops = []
        steps = []
        inferred_hops = 0
        for index in range(1, len(route)):
            source_id = route[index - 1][0]
            target_id, flow = route[index]
            if flow is None:
                continue
            inferred = bool(flow.assumed)
            inferred_hops += int(inferred)
            source = components[source_id]
            destination = components[target_id]
            hop = {
                "source": source_id,
                "target": target_id,
                "protocol": flow.protocol,
                "data_type": flow.data_type,
                "evidence_status": "inferred" if inferred else "explicit",
            }
            hops.append(hop)
            steps.append(
                f"{'Inferred' if inferred else 'Explicit'} flow: {source.name} -> {destination.name} over {flow.protocol}."
            )
        scenario = threat.attack_scenario or threat.realistic_attack_scenario
        if scenario:
            steps.append(scenario)
        if threat.asset:
            steps.append(f"The path affects protected asset {threat.asset}.")

        # A path that stops at the weak component understates it. What the
        # architecture connects downstream is what the attacker gains next, and
        # naming the sensitive stores among them is the difference between "this
        # service is exposed" and "this service is the way to the records".
        onward = sorted(graph.downstream(target, flows))
        exposed_stores = [
            components[component_id].name for component_id in onward
            if graph.rank((components[component_id].properties or {}).get("data_sensitivity")) >= 3
        ]
        if exposed_stores:
            steps.append(
                "From there the path reaches sensitive data held by "
                + ", ".join(exposed_stores)
                + "."
            )

        entry_id = route[0][0]
        confidence = "High" if inferred_hops == 0 and threat.confidence == "High" else "Medium"
        paths.append({
            "id": f"PATH-{threat.id}",
            "entry_point": components[entry_id].name,
            "entry_component_id": entry_id,
            "steps": steps,
            "hops": hops,
            "target_component": components[target].name,
            "target_component_id": target,
            "impact": threat.business_impact or threat.impact or "Operational impact",
            "related_threat_id": threat.id,
            "finding_type": threat.finding_type,
            "confidence": confidence,
            "severity": threat.severity,
            "preconditions": threat.preconditions,
            "evidence": threat.evidence_details or _fallback_evidence(threat),
            "path_status": "explicit" if inferred_hops == 0 else "partially_inferred",
            "inferred_hops": inferred_hops,
            "onward_reach": onward,
            "sensitive_data_reached": exposed_stores,
        })
    return paths


def _target_component(threat, components: Dict[str, object]) -> Optional[str]:
    for candidate in (threat.component, threat.affected_component, threat.component_id):
        if candidate in components:
            return candidate
    if threat.data_flow or threat.related_data_flow:
        flow_ref = (threat.data_flow or threat.related_data_flow).replace(" → ", "->")
        _, _, target = flow_ref.partition("->")
        if target in components:
            return target
    for candidate in threat.affected_components or []:
        if candidate in components:
            return candidate
    return None


def _best_route(entries: List[str], target: str, adjacency: Dict[str, List[Tuple[str, object]]]):
    candidates = []
    for entry in entries:
        route = _route(entry, target, adjacency)
        if route:
            inferred = sum(1 for _, flow in route[1:] if flow and flow.assumed)
            candidates.append((inferred, len(route), route))
    if not candidates:
        return None
    candidates.sort(key=lambda item: (item[0], item[1]))
    return candidates[0][2]


def _route(source: str, target: str, adjacency: Dict[str, List[Tuple[str, object]]]):
    if source == target:
        return [(source, None)]
    queue = deque([(source, [(source, None)])])
    visited = {source}
    while queue:
        node, route = queue.popleft()
        edges = sorted(adjacency.get(node, []), key=lambda item: bool(item[1].assumed))
        for next_node, flow in edges:
            if next_node in visited:
                continue
            next_route = [*route, (next_node, flow)]
            if next_node == target:
                return next_route
            visited.add(next_node)
            queue.append((next_node, next_route))
    return None


def _component_local_path(threat, target: str, components: Dict[str, object]) -> Dict:
    component = components[target]
    scenario = threat.attack_scenario or threat.realistic_attack_scenario or threat.description
    return {
        "id": f"PATH-{threat.id}",
        "entry_point": "Unspecified prerequisite",
        "entry_component_id": None,
        "steps": [f"No graph route from a modeled external entry point to {component.name} was established.", scenario],
        "hops": [],
        "target_component": component.name,
        "target_component_id": target,
        "impact": threat.business_impact or threat.impact or "Operational impact",
        "related_threat_id": threat.id,
        "finding_type": threat.finding_type,
        "confidence": "Low" if threat.confidence != "High" else "Medium",
        "severity": threat.severity,
        "preconditions": threat.preconditions,
        "evidence": threat.evidence_details or _fallback_evidence(threat),
        "path_status": "unresolved_entry_path",
        "inferred_hops": 0,
        "onward_reach": [],
        "sensitive_data_reached": [],
    }


def _unresolved_path(threat) -> Dict:
    return {
        "id": f"PATH-{threat.id}",
        "entry_point": "Unmapped",
        "entry_component_id": None,
        "steps": ["The finding is supported, but its affected component is not mapped to the architecture graph."],
        "hops": [],
        "target_component": "Unmapped",
        "target_component_id": None,
        "impact": threat.business_impact or threat.impact or "Operational impact",
        "related_threat_id": threat.id,
        "finding_type": threat.finding_type,
        "confidence": "Low",
        "severity": threat.severity,
        "preconditions": threat.preconditions,
        "evidence": threat.evidence_details or _fallback_evidence(threat),
        "path_status": "unmapped",
        "inferred_hops": 0,
        "onward_reach": [],
        "sensitive_data_reached": [],
    }


def _fallback_evidence(threat) -> List[Dict]:
    return [{
        "source_type": "architecture",
        "source_ref": threat.component or threat.affected_component or "architecture input",
        "line": None,
        "statement": evidence,
        "confidence": threat.confidence,
    } for evidence in (threat.evidence or [])]
