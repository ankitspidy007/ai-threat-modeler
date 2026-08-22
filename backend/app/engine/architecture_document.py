"""Render a parsed architecture back into the table format the parser reads.

An analysis is currently a one-way trip: a description goes in, a report comes
out, and the model the engine actually reasoned about is discarded. So a reviewer
who notices a missing component has to go back to the prose and run the whole
thing again, guessing at what the extractor will do differently this time.

Emitting the model in the same format the parser accepts closes that loop. The
document below is the model, so amending it means adding a row rather than
rewriting a description, and re-parsing it is deterministic: the structured path
does no inference, so nothing else in the model moves while you fix one thing.

Two properties of the model have to survive the trip or the second analysis
quietly says more than the first did:

  Unknown is not the same as absent. A control the description never mentioned
  is None, and one the description denied is False. Collapsing those into "not
  listed" would turn a stated weakness back into an open question.

  Inferred is not the same as stated. A flow the extractor guessed is marked
  assumed, and writing it into a table as an ordinary row would promote a guess
  into an assertion with the reviewer's name on it.

Both are therefore written down explicitly rather than left to be re-derived.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from ..models import Component, SystemArchitecture

#: Keys that describe how the model was built rather than what it contains, or
#: that the parser re-derives from the technology column on its own.
_BOOKKEEPING_KEYS = frozenset({
    'authoritative',
    'authoritative_external_entity',
    'boundary_crossing',
    'cloud_provider',
    'compliance_frameworks',
    'crosses_trust_boundary',
    'db_type',
    'description',
    'evidence',
    'evidence_status',
    'external',
    'extraction_method',
    'intermediate_hops',
    'name',
    'route',
    'source_record_id',
    'technology',
    'trust_level',
    'type',
})


def _cell(value: Any) -> str:
    """A single table cell, with the column separator escaped as ingestion does."""
    text = '' if value is None else str(value)
    return ' '.join(text.split()).replace('|', '&#124;')


def _table(number: int, headers: Iterable[str], rows: Iterable[Iterable[Any]]) -> List[str]:
    lines = [f'[Table {number}]', 'Row 1: ' + ' | '.join(_cell(header) for header in headers)]
    for index, row in enumerate(rows, start=2):
        lines.append(f'Row {index}: ' + ' | '.join(_cell(value) for value in row))
    # A table with a header and no rows tells the parser nothing and would make
    # the document look like it asserts an empty inventory.
    return lines if len(lines) > 2 else []


def _controls(component: Component) -> str:
    """The component's known control state, including what is known to be absent."""
    entries: List[str] = []
    for key, value in sorted((component.properties or {}).items()):
        if key in _BOOKKEEPING_KEYS:
            continue
        if isinstance(value, bool):
            entries.append(key if value else f'{key}=no')
        elif key == 'auth_type' and value and str(value).lower() != 'unknown':
            entries.append(f'{key}={value}')
    return ', '.join(entries)


def render(architecture: SystemArchitecture) -> str:
    """The architecture as a document the parser accepts unchanged."""
    metadata: Dict[str, Any] = architecture.metadata or {}

    # Externals are recreated from the names their flows use, so listing them as
    # components would re-import them as ordinary internal nodes.
    internal = [
        component for component in architecture.components
        if not (component.properties or {}).get('external')
    ]
    labels: Dict[str, str] = {}
    document_id: Dict[str, str] = {}
    for index, component in enumerate(internal, start=1):
        document_id[component.id] = f'C{index}'
        labels[component.id] = f'C{index}'
    for component in architecture.components:
        if component.id not in labels:
            labels[component.id] = component.name

    lines: List[str] = [
        '# Architecture model',
        '#',
        '# Emitted by the analyzer from the model it analyzed. Edit a row and',
        '# submit this document to re-analyze; ids are positional labels only and',
        '# carry no meaning, so you may renumber or append freely.',
        '#',
        "# Controls: 'name' means present, 'name=no' means known to be absent, and",
        '# omission means unknown. Flows marked assumed were inferred rather than',
        '# stated; confirm them by changing the column to stated, or delete them.',
        '',
    ]

    number = 1
    lines += _table(
        number,
        ['ID', 'Component', 'Type', 'Technology', 'Trust level', 'Controls', 'Responsibility / Data'],
        (
            [
                document_id[component.id],
                component.name,
                component.type,
                (component.properties or {}).get('technology', ''),
                component.trust_level,
                _controls(component),
                component.description or '',
            ]
            for component in internal
        ),
    )

    number += 1
    boundary_rows = []
    for index, boundary in enumerate(architecture.trust_boundaries, start=1):
        members = [labels[member] for member in boundary.components if member in labels]
        boundary_rows.append([
            f'TB{index}',
            boundary.name,
            boundary.boundary_type,
            ', '.join(members) or (boundary.description or ''),
        ])
    if boundary_rows:
        lines += [''] + _table(number, ['ID', 'Boundary', 'Trust level', 'Contents'], boundary_rows)
        number += 1

    flow_rows = []
    for index, flow in enumerate(architecture.flows, start=1):
        source = labels.get(flow.source_id)
        target = labels.get(flow.target_id)
        if not source or not target:
            continue
        properties = flow.properties or {}
        flow_rows.append([
            f'F{index}',
            f'{source} -> {target}',
            flow.protocol or 'HTTPS',
            properties.get('data') or flow.data_type or '',
            'assumed' if flow.assumed else 'stated',
        ])
    lines += [''] + _table(
        number, ['ID', 'Source and Destination', 'Protocol', 'Data', 'Evidence'], flow_rows
    )
    number += 1

    assets = [
        [
            f'AS{index}',
            asset.name,
            asset.sensitivity,
            (asset.evidence[0].get('statement') if asset.evidence else '') or asset.asset_type,
        ]
        for index, asset in enumerate(architecture.assets, start=1)
    ]
    if assets:
        lines += [''] + _table(
            number, ['ID', 'Asset', 'Classification', 'Required property'], assets
        )
        number += 1

    actors = [
        [
            actor.get('id') or f'A{index}',
            actor.get('name', ''),
            actor.get('identity', ''),
            actor.get('intended_privilege', ''),
        ]
        for index, actor in enumerate(metadata.get('actors') or [], start=1)
    ]
    if actors:
        lines += [''] + _table(
            number, ['ID', 'Actor', 'Identity', 'Intended privilege'], actors
        )
        number += 1

    issues = [
        [
            issue.get('source_record_id') or f'K{index}',
            issue.get('category') or 'General',
            issue.get('description') or '',
        ]
        for index, issue in enumerate(metadata.get('known_issues') or [], start=1)
    ]
    if issues:
        lines += [''] + _table(number, ['ID', 'Area', 'Known condition'], issues)

    return '\n'.join(lines).rstrip() + '\n'


def render_or_none(architecture: Optional[SystemArchitecture]) -> Optional[str]:
    if architecture is None or not architecture.components:
        return None
    return render(architecture)
