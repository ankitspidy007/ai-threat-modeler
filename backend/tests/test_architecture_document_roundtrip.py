"""An emitted model must parse back into the same model.

This is what makes amending an analysis safe. If re-submitting the document the
analyzer produced changed the model, then correcting one component would move
other things as a side effect, and the reviewer could not tell which findings
changed because of their edit and which changed on their own.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.engine.architecture_document import _BOOKKEEPING_KEYS, render
from app.engine.parser import ArchitectureParser

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "reference_architecture.txt"

PROSE = """
The Aurora payments platform serves retail customers. A React web portal and an
iOS mobile app call an AWS API Gateway over HTTPS. The gateway validates tokens
with AWS Cognito and routes payment requests to a Java Spring Boot payments
service. The payments service writes the transaction ledger to an Aurora
PostgreSQL database and stores receipts in S3. MFA is enforced at the identity
service, a WAF protects the edge, and data is encrypted at rest and in transit.

Known issues:
- The JWT signing secret is committed to the repository.
- The payments database has no dedicated IAM role; every service shares one credential.
"""


def _fingerprint(architecture):
    """Everything about the model that changes what the engine will conclude.

    Provenance is excluded: a reviewed model is by definition stated rather than
    inferred, so `authoritative` flipping to True on the second pass is the point
    of the exercise and not a drift. An auth_type of "unknown" is excluded for the
    same reason it is never written down -- it is the absence of a statement, and
    means what a missing key means.
    """
    components = {
        component.name: (
            component.type,
            component.trust_level,
            tuple(sorted(
                (key, value) for key, value in (component.properties or {}).items()
                if key not in _BOOKKEEPING_KEYS
                and (
                    isinstance(value, bool)
                    or (key == "auth_type" and str(value).lower() != "unknown")
                )
            )),
        )
        for component in architecture.components
    }
    names = {component.id: component.name for component in architecture.components}
    flows = sorted(
        (
            names.get(flow.source_id, flow.source_id),
            names.get(flow.target_id, flow.target_id),
            flow.protocol,
            flow.data_type,
            flow.assumed,
        )
        for flow in architecture.flows
    )
    boundaries = sorted(
        (
            boundary.name,
            boundary.boundary_type,
            tuple(sorted(names.get(member, member) for member in boundary.components)),
        )
        for boundary in architecture.trust_boundaries
    )
    return components, flows, boundaries


@pytest.mark.parametrize(
    "source",
    [
        pytest.param(FIXTURE.read_text(encoding="utf-8"), id="structured"),
        pytest.param(PROSE, id="prose"),
    ],
)
def test_emitted_model_parses_back_unchanged(source):
    parser = ArchitectureParser()
    original = parser.parse(source)
    reparsed = parser.parse(render(original))

    assert _fingerprint(reparsed) == _fingerprint(original)


def test_a_prose_description_becomes_an_editable_document():
    """The point of the export: prose in, a table you can amend out."""
    document = render(ArchitectureParser().parse(PROSE))

    assert "[Table 1]" in document
    assert "Row 1: ID | Component | Type | Technology | Trust level | Controls" in document
    assert "Aurora" in document


def test_adding_a_component_needs_only_the_new_rows():
    """Amending is appending, and it must not disturb what was already there."""
    parser = ArchitectureParser()
    original = parser.parse(FIXTURE.read_text(encoding="utf-8"))
    document = render(original)

    component_count = len([
        line for line in document.splitlines()
        if line.startswith("Row ") and " | " in line
    ])

    lines = document.splitlines()
    # Append one component to the inventory and one flow that reaches it.
    component_end = next(
        index for index, line in enumerate(lines)
        if line.startswith("[Table 2]")
    ) - 1
    lines.insert(
        component_end,
        "Row 99: C99 | Audit archive | Amazon S3 document store | restricted |  | Immutable audit records",
    )
    amended = "\n".join(lines).replace(
        "[Table 3]",
        "[Table 3]",
    )
    amended += "\nRow 99: F99 | C7 -> C99 | HTTPS | Audit records | stated\n"

    updated = parser.parse(amended)
    names = {component.name for component in updated.components}

    assert "Audit archive" in names
    assert component_count > 0
    # Everything that was already modeled is still modeled, unchanged.
    before = {component.name: component.type for component in original.components}
    after = {component.name: component.type for component in updated.components}
    assert all(after.get(name) == component_type for name, component_type in before.items())


def test_inserting_a_row_does_not_renumber_everything_else():
    """Identity has to survive an edit, or amending detaches every annotation.

    Findings are keyed by the component they concern. If a component were its
    row label, adding one row above it would rename every component below the
    insertion, and each finding and reviewer note attached to them would appear
    to have been resolved and replaced by an identical new one.
    """
    parser = ArchitectureParser()
    before = parser.parse(
        "[Table 1]\n"
        "Row 1: ID | Component | Technology\n"
        "Row 2: C1 | Web portal | React SPA\n"
        "Row 3: C2 | Core API | Java Spring Boot\n"
        "Row 4: C3 | Ledger database | Aurora PostgreSQL\n"
        "\n"
        "[Table 2]\n"
        "Row 1: ID | Source and Destination | Protocol\n"
        "Row 2: F1 | C1 -> C2 | HTTPS\n"
        "Row 3: F2 | C2 -> C3 | TLS\n"
    )
    after = parser.parse(
        "[Table 1]\n"
        "Row 1: ID | Component | Technology\n"
        "Row 2: C1 | Web portal | React SPA\n"
        "Row 3: C2 | Audit archive | Amazon S3 document store\n"
        "Row 4: C3 | Core API | Java Spring Boot\n"
        "Row 5: C4 | Ledger database | Aurora PostgreSQL\n"
        "\n"
        "[Table 2]\n"
        "Row 1: ID | Source and Destination | Protocol\n"
        "Row 2: F1 | C1 -> C3 | HTTPS\n"
        "Row 3: F2 | C3 -> C4 | TLS\n"
        "Row 4: F3 | C3 -> C2 | HTTPS\n"
    )
    before_ids = {component.name: component.id for component in before.components}
    after_ids = {component.name: component.id for component in after.components}

    for name, identifier in before_ids.items():
        assert after_ids[name] == identifier, f"{name} changed identity when a row was inserted"
    assert "Audit archive" in after_ids


def test_control_state_survives_including_what_is_known_to_be_absent():
    parser = ArchitectureParser()
    architecture = parser.parse(
        "[Table 1]\n"
        "Row 1: ID | Component | Technology | Controls\n"
        "Row 2: C1 | Receipt store | Amazon S3 document store | encryption_at_rest=no, logging_enabled\n"
        "Row 3: C2 | Core API | Java Spring Boot | rate_limiting=no\n"
        "\n"
        "[Table 2]\n"
        "Row 1: ID | Source and Destination | Protocol\n"
        "Row 2: F1 | C2 -> C1 | HTTPS\n"
    )
    store = next(item for item in architecture.components if item.name == "Receipt store")
    assert store.properties["encryption_at_rest"] is False
    assert store.properties["logging_enabled"] is True

    reparsed = parser.parse(render(architecture))
    store_again = next(item for item in reparsed.components if item.name == "Receipt store")
    api_again = next(item for item in reparsed.components if item.name == "Core API")

    # False must not decay into None: "known to be absent" is a finding, while
    # "unknown" is only a question.
    assert store_again.properties["encryption_at_rest"] is False
    assert store_again.properties["logging_enabled"] is True
    assert api_again.properties["rate_limiting"] is False


def test_an_inferred_flow_is_not_promoted_to_a_stated_one():
    parser = ArchitectureParser()
    original = parser.parse(PROSE)
    assumed_before = sum(flow.assumed for flow in original.flows)

    reparsed = parser.parse(render(original))
    assumed_after = sum(flow.assumed for flow in reparsed.flows)

    assert assumed_after == assumed_before
    assert len(reparsed.flows) == len(original.flows)
