"""Reachability and sensitivity over the architecture graph.

Several passes ask the same question - what can be reached from here, and what
does it carry - and each had its own partial answer. Risk scoring measured blast
radius by counting the components a finding happened to name, which is almost
always one. Data sensitivity was read only off the component whose own
description mentioned it, so a database holding patient records was unclassified
whenever the word "patient" appeared in the sentence about the API that writes
them. Both are properties of the graph rather than of a single element, so they
are answered here once and used everywhere.
"""

from __future__ import annotations

from collections import deque
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

#: How much a classification raises the stakes, used to pick between two claims
#: about the same component. Unranked values are treated as the baseline.
SENSITIVITY_RANK: Dict[str, int] = {
    "public": 0,
    "application_data": 1,
    "internal": 1,
    "proprietary": 2,
    "sensitive": 2,
    "pii": 3,
    "phi": 4,
    "financial": 4,
    "credentials": 5,
    "secrets": 5,
}

#: Types whose contents define what the components talking to them handle. A
#: service that connects to a database of patient records handles patient
#: records, whichever way the request arrow points. A secrets manager is absent
#: on purpose: nearly every component reads configuration from one, so treating
#: that as a property of the component would classify the whole architecture.
DATA_STORE_TYPES = frozenset({"Database", "Object Storage", "Queue"})


def rank(sensitivity: Optional[str]) -> int:
    return SENSITIVITY_RANK.get(str(sensitivity or "").lower(), 1)


def most_sensitive(*values: Optional[str]) -> Optional[str]:
    """The value of greatest concern among those given."""
    present = [value for value in values if value]
    if not present:
        return None
    return max(present, key=rank)


def outgoing(flows: Iterable[Any]) -> Dict[str, List[Any]]:
    """component id -> the flows leaving it."""
    edges: Dict[str, List[Any]] = {}
    for flow in flows or []:
        edges.setdefault(flow.source_id, []).append(flow)
    return edges


def downstream(
    start: str,
    flows: Iterable[Any],
    include_assumed: bool = True,
) -> Set[str]:
    """Everything reachable by following flows out of ``start``.

    This is what an attacker who holds ``start`` can go on to touch, which is the
    honest measure of how much one weak component costs. ``start`` itself is left
    out so the result reads as "and this much besides".
    """
    edges = outgoing(flows)
    seen: Set[str] = set()
    queue = deque([start])
    while queue:
        node = queue.popleft()
        for flow in edges.get(node, []):
            if not include_assumed and flow.assumed:
                continue
            if flow.target_id in seen or flow.target_id == start:
                continue
            seen.add(flow.target_id)
            queue.append(flow.target_id)
    return seen


def touching(component_id: str, flows: Iterable[Any]) -> List[Any]:
    """Every flow with this component at either end."""
    return [
        flow for flow in flows or []
        if component_id in (flow.source_id, flow.target_id)
    ]


def propagate_sensitivity(
    components: Dict[str, Any],
    flows: Iterable[Any],
) -> Dict[str, Tuple[str, str]]:
    """Carry each classification along the paths the data actually travels.

    A classification stated about one component describes the data, not the
    component, so it holds wherever that data goes. Only components the
    description left unclassified are filled in, and each gets the reason
    recorded, so a stated classification is never overruled by a deduction and a
    reviewer can see which are which.

    Returns component id -> (sensitivity, the reason it was assigned).
    """
    declared = {
        component_id: (component.properties or {}).get("data_sensitivity")
        for component_id, component in components.items()
    }
    resolved = {cid: value for cid, value in declared.items() if value}
    reasons: Dict[str, Tuple[str, str]] = {}
    flow_list = [
        flow for flow in flows or []
        if flow.source_id in components and flow.target_id in components
    ]

    # Bounded because each pass can only raise a component's rank, and the ranks
    # are finite; the component count is a safe ceiling on how far a value moves.
    for _ in range(len(components) + 1):
        changed = False
        for flow in flow_list:
            source, target = flow.source_id, flow.target_id
            for origin, destination in (
                (source, target),
                # Reading from a store means handling what the store holds.
                (target, source) if components[target].type in DATA_STORE_TYPES else (None, None),
            ):
                if origin is None or declared.get(destination):
                    continue
                carried = resolved.get(origin)
                if not carried or rank(carried) <= rank(resolved.get(destination)):
                    continue
                resolved[destination] = carried
                reasons[destination] = (
                    carried,
                    f"carried from {components[origin].name} over "
                    f"{components[source].name} -> {components[target].name}",
                )
                changed = True
        if not changed:
            break
    return reasons
