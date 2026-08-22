"""A sentence must yield every weakness it states and no weakness it does not."""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.engine.known_issue_taxonomy import (
    GENERIC_WEAKNESS_RULES,
    classify_generic_weaknesses,
)
from app.engine.owasp_mapping import owasp_for
from app.engine.parser import ArchitectureParser


def _ids(text):
    return {rule['id'] for rule in classify_generic_weaknesses(text)}


def test_two_weaknesses_in_one_sentence_are_both_reported():
    ids = _ids('The orchestration service has no rate limiting and prompts are not validated.')

    assert 'GENERIC-RATE-LIMITING-001' in ids
    assert 'GENERIC-INPUT-VALIDATION-001' in ids


def test_a_second_factor_gap_is_not_an_absence_of_authentication():
    ids = _ids('The admin portal has no multi-factor authentication.')

    assert 'GENERIC-MISSING-MFA-001' in ids
    assert 'GENERIC-MISSING-AUTHENTICATION-001' not in ids


def test_an_absence_of_authentication_is_still_recognized():
    assert 'GENERIC-MISSING-AUTHENTICATION-001' in _ids(
        'The internal metrics endpoint requires no authentication.'
    )


def test_an_unscanned_upload_is_classified():
    ids = _ids('Uploaded documents are not scanned before indexing.')

    assert 'GENERIC-UNSCANNED-UPLOAD-001' in ids


def test_a_declared_veto_never_removes_the_rule_it_belongs_to():
    """Every rule with a veto must still match a sentence it is meant to catch."""
    for rule in GENERIC_WEAKNESS_RULES:
        for phrase in rule.get('unless', ()):
            assert not any(
                phrase.strip('!') in group_phrase
                for group in rule['groups'] for group_phrase in group
            ), f"{rule['id']} vetoes a phrase it matches on: {phrase}"


def test_every_finding_carries_an_owasp_category():
    from app.engine.analyzer import ThreatAnalyzer

    result = ThreatAnalyzer().analyze_from_text(
        'A React portal calls a payments API over HTTPS. The payments API stores card data '
        'in a PostgreSQL database that is not encrypted at rest and does not log admin actions.',
        'owasp_coverage',
        use_local_slm=False,
    )

    unmapped = [threat.id for threat in result.threats if not threat.owasp_top_10]
    assert unmapped == []


def test_a_stated_issue_that_cannot_be_placed_does_not_block_the_report():
    result_text = (
        'A Vue console calls an orchestration service over HTTPS.\n'
        'Known issues:\n'
        '- The quarterly access review has not been carried out.\n'
    )
    from app.engine.analyzer import ThreatAnalyzer

    result = ThreatAnalyzer().analyze_from_text(result_text, 'unplaceable', use_local_slm=False)
    gate = result.engine_status['quality_gate']

    assert gate['status'] != 'blocked'
    assert gate['declared_known_issues'] == gate['reported_known_issues'] == 1


def test_the_owasp_table_agrees_with_the_upload_rule():
    assert owasp_for(['CWE-434'], 'Tampering') == ['A04:2021 Insecure Design']


def test_stated_weaknesses_reach_the_component_named_in_part():
    architecture = ArchitectureParser().parse(
        'A Vue web console calls a FastAPI orchestration service over HTTPS. '
        'The orchestration service has no rate limiting.'
    )
    weaknesses = {
        component.id: {item['rule_id'] for item in component.properties.get('stated_weaknesses', [])}
        for component in architecture.components
    }

    assert 'GENERIC-RATE-LIMITING-001' in weaknesses['fastapi_orchestration_service']
