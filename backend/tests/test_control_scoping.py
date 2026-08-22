"""A control belongs to the component its sentence was about."""

from app.engine.parser import ArchitectureParser
from app.models import Component


def parse(text):
    architecture = ArchitectureParser().parse(text)
    return {component.name: component.properties or {} for component in architecture.components}


def test_a_weakness_stated_about_one_component_does_not_spread():
    props = parse(
        "A clinician portal calls a records service backed by a ledger database. "
        "The clinician portal has no MFA."
    )
    assert props["Clinician Portal"]["mfa_enabled"] is False
    assert "mfa_enabled" not in props["Records Service"]
    assert "mfa_enabled" not in props["Ledger Database"]


def test_a_control_stated_about_one_component_does_not_credit_the_others():
    props = parse(
        "A payments API writes to an orders database. "
        "The orders database is encrypted at rest with a customer-managed key."
    )
    assert props["Orders Database"]["encryption_at_rest"] is True
    assert props.get("Payments API", {}).get("encryption_at_rest") is not True


def test_both_ends_of_a_sentence_keep_a_control_that_describes_the_hop():
    """"The portal calls the API over TLS" is a fact about both ends."""
    props = parse("A clinician portal calls a records API over TLS.")
    assert props["Clinician Portal"].get("encryption_in_transit") is True
    assert props["Records API"].get("encryption_in_transit") is True


def test_a_control_stated_without_a_subject_stays_general():
    props = parse(
        "A clinician portal calls a records service backed by a ledger database. "
        "Everything is monitored."
    )
    monitored = [name for name, values in props.items() if values.get("monitoring_enabled") is True]
    assert len(monitored) > 1


def test_a_named_subject_the_model_lacks_is_not_a_verdict_on_everything():
    parser = ArchitectureParser()
    components = {
        "records_service": Component(
            id="records_service", name="Records Service", type="Service", properties={}
        )
    }
    assert parser._names_something_unmodelled("the receipts bucket is not encrypted", components)
    assert not parser._names_something_unmodelled("the records service is not encrypted", components)


def test_a_storage_bucket_named_in_prose_becomes_a_component():
    props = parse(
        "A records service stores exports in a receipts bucket. "
        "The receipts bucket is not encrypted at rest."
    )
    assert "Receipts Bucket" in props
    assert props["Receipts Bucket"]["encryption_at_rest"] is False
    assert "encryption_at_rest" not in props["Records Service"]
