"""A control named in order to be denied must never be read as a control present."""

import pytest

from app.engine import control_statements


DENIED = [
    ("The clinician portal has no MFA.", 'mfa_enabled'),
    ("There is no MFA on the clinician portal.", 'mfa_enabled'),
    ("MFA is not enforced on the clinician portal.", 'mfa_enabled'),
    ("The clinician portal does not require MFA.", 'mfa_enabled'),
    ("The admin console lacks multi-factor authentication.", 'mfa_enabled'),
    ("MFA is disabled for the operations team.", 'mfa_enabled'),
    ("Administrators sign in with a single factor; MFA is missing.", 'mfa_enabled'),
    ("The API has no rate limiting.", 'rate_limiting'),
    ("Requests are accepted without throttling.", 'rate_limiting'),
    ("Rate limiting is not configured on the public edge.", 'rate_limiting'),
    ("There is no WAF in front of the public API edge.", 'waf_enabled'),
    ("Data in the ledger database is not encrypted at rest.", 'encryption_at_rest'),
    ("Backups are stored unencrypted.", 'encryption_at_rest'),
    ("The bucket holds unencrypted exports.", 'encryption_at_rest'),
    ("Audit logs are not retained.", 'logging_enabled'),
    ("The worker writes no audit trail.", 'logging_enabled'),
    ("Service to service calls use no mutual TLS.", 'mtls_enabled'),
    ("Container images are pushed without image scanning.", 'container_image_scanning'),
    ("Secrets sit in environment variables and never reach a vault.", 'secrets_management'),
    ("Traffic between pods is not restricted by network policies.", 'network_policies'),
]

AFFIRMED = [
    ("MFA is enforced on the clinician portal.", 'mfa_enabled'),
    ("The portal requires MFA for every administrator.", 'mfa_enabled'),
    ("The edge applies rate limiting per API key.", 'rate_limiting'),
    ("A WAF fronts the public API edge.", 'waf_enabled'),
    ("The ledger database is encrypted at rest with a customer-managed key.", 'encryption_at_rest'),
    ("CloudTrail records administrative activity.", 'logging_enabled'),
    ("Splunk receives the application logs.", 'centralized_logging'),
    ("Pod to pod traffic is authenticated with mutual TLS.", 'mtls_enabled'),
    ("Secrets are read from HashiCorp Vault at start-up.", 'secrets_management'),
]


@pytest.mark.parametrize("sentence,control", DENIED)
def test_a_stated_absence_denies_its_control(sentence, control):
    reading = control_statements.read(sentence)
    assert reading.denies(control), f"{control} should be denied by {sentence!r}"
    assert reading.value(control) is False


@pytest.mark.parametrize("sentence,control", AFFIRMED)
def test_a_stated_control_is_credited(sentence, control):
    reading = control_statements.read(sentence)
    assert reading.affirms(control), f"{control} should be affirmed by {sentence!r}"
    assert reading.value(control) is True


def test_a_denial_does_not_reach_across_a_second_claim():
    """One clause denying a control says nothing about the next clause's control."""
    reading = control_statements.read(
        "The portal has no MFA, and the API gateway enforces rate limiting."
    )
    assert reading.denies('mfa_enabled')
    assert reading.affirms('rate_limiting')


def test_a_denial_after_the_term_needs_the_term_s_own_verb():
    """"MFA is enforced and sessions do not expire" affirms MFA."""
    reading = control_statements.read(
        "MFA is enforced and sessions do not expire for administrators."
    )
    assert reading.affirms('mfa_enabled')


def test_a_contrastive_connector_ends_the_denial():
    reading = control_statements.read(
        "The service keeps no audit trail, but TLS terminates at the load balancer."
    )
    assert reading.denies('logging_enabled')
    assert reading.affirms('encryption_in_transit')


def test_a_control_absent_from_the_text_stays_unknown():
    reading = control_statements.read("A portal calls a service backed by a database.")
    assert reading.value('mfa_enabled') is None
    assert reading.value('encryption_at_rest') is None


def test_a_denial_outranks_a_mention_of_the_same_control():
    """Wording that both names and denies a control is a denial."""
    reading = control_statements.read("Multi-factor authentication is not available.")
    assert reading.value('mfa_enabled') is False


def test_statements_carry_the_clause_that_made_the_claim():
    found = control_statements.statements("The portal has no MFA. The edge applies rate limiting.")
    denied = [item for item in found if item.control == 'mfa_enabled' and not item.affirmed]
    assert denied and "no MFA" in denied[0].clause
