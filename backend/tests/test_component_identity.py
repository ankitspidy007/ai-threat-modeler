"""One component of the design must be one component of the model."""

import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.engine.parser import ArchitectureParser


def _components(text):
    return {component.id: component for component in ArchitectureParser().parse(text).components}


def test_a_dependency_named_and_classified_is_one_component():
    components = _components(
        'Auth0 provides identity for the payments service, which calls Stripe for card capture.'
    )

    assert 'auth0' in components
    assert 'auth0_external' not in components
    assert components['auth0'].properties['external'] is True
    assert 'auth0_external' in components['auth0'].properties['merged_aliases']


def test_a_platform_name_does_not_become_a_second_client():
    components = _components('An iOS mobile app calls the checkout API over HTTPS.')

    assert 'mobile_app' in components
    assert 'ios' not in components
    assert 'ios' in components['mobile_app'].properties['technology']


def test_a_component_is_named_as_the_description_named_it():
    components = _components('A React web portal calls the checkout API over HTTPS.')

    assert components['react'].name == 'React Web Portal'


def test_two_clients_of_the_same_type_stay_separate():
    components = _components(
        'A React web portal calls the checkout API. An admin portal lets staff issue refunds.'
    )

    assert 'react' in components
    assert 'admin_portal' in components
    assert components['admin_portal'].name == 'Admin Portal'


def test_a_platform_with_no_host_remains_the_client_itself():
    components = _components('A React single page application calls the checkout API.')

    assert 'react' in components
    assert components['react'].type == 'WebClient'


def test_merging_never_downgrades_an_exposure_fact():
    components = _components(
        'Okta is the third-party identity provider. The internal Okta tenant is publicly reachable.'
    )

    okta = components.get('okta') or components.get('okta_external')
    assert okta is not None
    assert 'okta' in okta.id
    assert okta.properties.get('external') or okta.properties.get('third_party_integration')
