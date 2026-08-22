"""Every finding says which flows relate to it, or why none do.

A blank flow list on a finding is ambiguous: it can mean the weakness is local
to one component, or that the architecture never described a path at all. The
second is a gap in the model, so the two must not look alike.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.engine.analyzer import ThreatAnalyzer
from app.engine.parser import ArchitectureParser

CONNECTED = (
    "A public React web portal calls a Node.js REST API over HTTPS. The API "
    "stores patient records in a PostgreSQL database. The portal has no MFA."
)

UNCONNECTED = "The system uses a PostgreSQL database. The database has no encryption at rest."


@pytest.fixture(scope='module')
def connected():
    return ThreatAnalyzer().analyze_from_text(
        CONNECTED, project_name='Flow Context', use_local_slm=False,
    )


def test_no_finding_is_left_without_a_flow_context(connected):
    for threat in connected.threats:
        assert (threat.explanation or {}).get('flow_context'), (
            f"{threat.id} gives the reader no way to tell why its flow list looks as it does"
        )


def test_a_component_scoped_finding_names_the_flows_that_touch_it(connected):
    portal = [threat for threat in connected.threats if threat.component == 'react']
    assert portal, 'the portal should carry findings'
    for threat in portal:
        explanation = threat.explanation or {}
        if threat.affected_data_flows:
            continue
        labels = [flow['label'] for flow in explanation.get('component_flows') or []]
        assert any('Node.js' in label for label in labels), (
            f"{threat.id} should name the portal's flow to the API"
        )


def test_a_derived_flow_records_its_direction_and_protocol(connected):
    flows = [
        flow
        for threat in connected.threats
        for flow in (threat.explanation or {}).get('component_flows') or []
    ]
    assert flows
    for flow in flows:
        assert flow['direction'] in {'inbound', 'outbound'}
        assert flow['protocol']
        assert 'label' in flow and '→' in flow['label']


def test_a_finding_is_not_credited_with_a_flow_it_did_not_examine(connected):
    """Flows touching a component are context, not the subject of the finding."""
    for threat in connected.threats:
        if (threat.explanation or {}).get('flow_context') == 'component_flows':
            assert not threat.affected_data_flows


def test_an_architecture_without_flows_says_so_rather_than_showing_nothing():
    result = ThreatAnalyzer().analyze_from_text(
        UNCONNECTED, project_name='No Flows', use_local_slm=False,
    )
    assert not result.architecture.flows
    assert result.threats
    for threat in result.threats:
        assert (threat.explanation or {}).get('flow_context') == 'no_flows_modeled'


def test_a_flow_between_two_trust_levels_is_marked_as_crossing():
    architecture = ArchitectureParser().parse(CONNECTED)
    crossing = [
        flow for flow in architecture.flows
        if (flow.properties or {}).get('crosses_trust_boundary')
    ]
    assert crossing, 'a public portal calling an internal API crosses a boundary'
    for flow in crossing:
        properties = flow.properties or {}
        assert properties['source_trust_level'] != properties['target_trust_level']


def test_a_guessed_flow_stays_marked_as_guessed():
    """Template-derived flows are assumptions and must not read as described."""
    architecture = ArchitectureParser().parse(
        'A React web portal serves customers. A PostgreSQL database holds orders.'
    )
    for flow in architecture.flows:
        if (flow.properties or {}).get('origin') == 'assumed':
            assert flow.assumed is True
            assert (flow.properties or {})['assumed'] is True
