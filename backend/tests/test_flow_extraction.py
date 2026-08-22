"""A described data flow must be modelled as described, and no more than that."""

import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.engine.parser import ArchitectureParser


DESCRIPTION = """
A React web portal and an iOS mobile app call an API gateway over HTTPS.
The API gateway routes to a payments service and an accounts service.
The payments service calls Stripe for card capture.
The payments service stores transactions in a PostgreSQL database and publishes events to a Kafka queue.
A settlement worker consumes from Kafka and writes files to an S3 bucket.
Auth0 provides identity.
An admin portal lets support staff issue refunds.
"""


@pytest.fixture(scope='module')
def architecture():
    return ArchitectureParser().parse(DESCRIPTION)


@pytest.fixture(scope='module')
def flows(architecture):
    return {(flow.source_id, flow.target_id): flow for flow in architecture.flows}


def test_each_described_flow_is_modelled_in_the_direction_described(flows):
    for pair in (
        ('react', 'api_gateway'),
        ('mobile_app', 'api_gateway'),
        ('api_gateway', 'payments_service'),
        ('api_gateway', 'accounts_service'),
        ('payments_service', 'stripe_external'),
        ('payments_service', 'postgresql'),
        ('payments_service', 'kafka'),
        ('kafka', 'settlement_worker'),
        ('settlement_worker', 's3'),
    ):
        assert pair in flows, f'described flow is missing: {pair[0]} -> {pair[1]}'
        assert flows[pair].properties['origin'] == 'stated'
        assert flows[pair].assumed is False


def test_a_described_flow_carries_the_sentence_that_states_it(flows):
    flow = flows[('payments_service', 'postgresql')]

    assert flow.evidence[0]['statement'].startswith('The payments service stores transactions')
    assert flow.properties['stated_relationship'] == 'stores transactions in'
    assert flow.confidence == 'High'


def test_a_subject_carries_across_and_rather_than_the_previous_object(flows):
    """"...stores transactions in Postgres and publishes events to Kafka"."""
    assert ('payments_service', 'kafka') in flows
    assert ('postgresql', 'kafka') not in flows


def test_consuming_from_a_queue_flows_out_of_the_queue(flows):
    assert ('kafka', 'settlement_worker') in flows
    assert ('settlement_worker', 'kafka') not in flows


def test_no_flow_is_invented_between_unrelated_components(flows):
    for pair in (
        ('accounts_service', 'postgresql'),
        ('accounts_service', 's3'),
        ('settlement_worker', 'postgresql'),
        ('accounts_service', 'auth0'),
        ('api_gateway', 'settlement_worker'),
    ):
        assert pair not in flows, f'flow was invented: {pair[0]} -> {pair[1]}'


def test_a_component_left_unconnected_gets_one_stated_assumption(flows, architecture):
    """Auth0 is named but no flow to it is described, so the gap is declared."""
    assumed = {pair: flow for pair, flow in flows.items() if flow.properties.get('origin') == 'assumed'}

    assert [pair for pair in assumed if pair[1] == 'auth0'] == [('payments_service', 'auth0')]
    for flow in assumed.values():
        assert flow.assumed is True
        assert flow.confidence == 'Low'
        assert 'No data flow was described' in flow.properties['assumption']

    scopes = {assumption['scope'] for assumption in architecture.metadata.get('assumptions', [])}
    assert 'payments_service->auth0' in scopes


def test_a_relative_pronoun_hands_the_subject_to_the_component_just_named():
    """"a portal calls a gateway which routes to a service" has no direct path."""
    architecture = ArchitectureParser().parse(
        'A React portal calls an AWS API Gateway which routes to a Spring Boot '
        'payments service.'
    )
    flows = {
        (flow.source_id, flow.target_id)
        for flow in architecture.flows
        if flow.properties.get('origin') == 'stated'
    }
    names = {component.id: component.name for component in architecture.components}
    portal = next(cid for cid, name in names.items() if 'ortal' in name)
    gateway = next(cid for cid, name in names.items() if 'ateway' in name)
    service = next(cid for cid, name in names.items() if 'ayments' in name)

    assert (portal, gateway) in flows
    assert (gateway, service) in flows
    assert (portal, service) not in flows


def test_what_stands_behind_a_destination_is_not_also_a_destination():
    """"routes to a service backed by a database and a bucket" states one path."""
    architecture = ArchitectureParser().parse(
        'A React portal calls an AWS API Gateway which routes to a Spring Boot '
        'payments service backed by an Aurora PostgreSQL database and an S3 '
        'receipts bucket.'
    )
    stated = {
        (flow.source_id, flow.target_id)
        for flow in architecture.flows
        if flow.properties.get('origin') == 'stated'
    }
    names = {component.id: component.name for component in architecture.components}
    gateway = next(cid for cid, name in names.items() if 'ateway' in name)
    database = next(cid for cid, name in names.items() if 'urora' in name or 'ostgre' in name.lower())

    # The database stands behind the service; the gateway was never said to
    # reach it. The path to it may still be assumed, but it is not stated.
    assert (gateway, database) not in stated


def test_a_sentence_broken_by_the_margin_is_still_one_sentence():
    """A wrap before a capitalized name must not make that name a subject."""
    architecture = ArchitectureParser().parse(
        'The payments service writes the transaction ledger to an Aurora\n'
        'PostgreSQL database and stores receipts in an S3 receipts bucket.\n'
    )
    stated = {
        (flow.source_id, flow.target_id)
        for flow in architecture.flows
        if flow.properties.get('origin') == 'stated'
    }
    names = {component.id: component.name for component in architecture.components}
    service = next(cid for cid, name in names.items() if 'ayments' in name)
    bucket = next(cid for cid, name in names.items() if name.lower().startswith('s3'))
    database = next(cid for cid, name in names.items() if 'ostgre' in name.lower() or 'urora' in name)

    assert (service, bucket) in stated
    assert (database, bucket) not in stated


def test_the_protocol_stated_in_the_sentence_is_used(flows):
    assert flows[('react', 'api_gateway')].protocol.upper() == 'HTTPS'
    assert flows[('payments_service', 'postgresql')].protocol.upper() == 'TCP'


def test_plain_http_is_not_reported_as_https():
    architecture = ArchitectureParser().parse(
        'The billing service sends invoices to the archive database over plain HTTP.'
    )
    flows = {(flow.source_id, flow.target_id): flow for flow in architecture.flows}

    stated = [flow for pair, flow in flows.items() if flow.properties.get('origin') == 'stated']
    assert stated and all(flow.protocol.upper() == 'HTTP' for flow in stated)


def test_an_assumed_flow_is_drawn_dotted_and_a_stated_one_is_not(architecture):
    from app.engine.graph_builder import GraphBuilder
    from app.engine.mermaid_generator import generate_mermaid

    diagram = generate_mermaid(GraphBuilder(architecture).get_graph())

    assert '-.->' in diagram
    assert '(assumed)' in diagram
    assert 'A dotted flow was assumed' in diagram
    stated_edge = next(
        line for line in diagram.splitlines() if 'api_gateway' in line and '|' in line
    )
    assert '(assumed)' not in stated_edge
