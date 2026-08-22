"""The authoritative table path must read the document, not the numbering.

Component typing, trust levels, control credit, boundary membership and flow
endpoints were all once keyed on the id a component happened to carry, because
the parser had been fitted to one reference document. A model that changes when
its rows are renumbered is not reading the architecture, so these tests renumber
and rename and require the result to be the same.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.engine.parser import ArchitectureParser

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "reference_architecture.txt"


@pytest.fixture(scope="module")
def reference_text() -> str:
    return FIXTURE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def reference_model(reference_text):
    return ArchitectureParser().parse(reference_text)


def _by_name(architecture):
    return {component.name: component for component in architecture.components}


def _flow_names(architecture):
    names = {component.id: component.name for component in architecture.components}
    return {
        (names[flow.source_id], names[flow.target_id])
        for flow in architecture.flows
        if flow.source_id in names and flow.target_id in names
    }


def _renumber(text: str, offset: int = 40) -> str:
    """Shift every component id, keeping the document's meaning identical."""
    return re.sub(
        r"\bC(\d+)\b",
        lambda match: f"C{int(match.group(1)) + offset}",
        text,
    )


def test_reference_fixture_parses_through_the_authoritative_path(reference_model):
    assert reference_model.metadata["authoritative_model"] is True
    assert reference_model.metadata["authoritative_parse_warnings"] == []
    assert len(reference_model.components) == 28
    assert len(reference_model.flows) == 20
    assert len(reference_model.trust_boundaries) == 9
    assert len(reference_model.assets) == 12
    assert len(reference_model.metadata["known_issues"]) == 30
    assert len(reference_model.metadata["actors"]) == 10
    assert all(not flow.assumed for flow in reference_model.flows)


def test_renumbering_every_component_changes_nothing(reference_text, reference_model):
    renumbered = ArchitectureParser().parse(_renumber(reference_text))

    assert _by_name(renumbered).keys() == _by_name(reference_model).keys()
    assert _flow_names(renumbered) == _flow_names(reference_model)

    for name, component in _by_name(reference_model).items():
        shifted = _by_name(renumbered)[name]
        assert shifted.type == component.type, name
        assert shifted.trust_level == component.trust_level, name
        assert shifted.properties.get("mfa_enabled") == component.properties.get("mfa_enabled"), name
        assert shifted.properties.get("encryption_at_rest") == component.properties.get("encryption_at_rest"), name
        assert shifted.properties.get("waf_enabled") == component.properties.get("waf_enabled"), name

    before = {boundary.name: len(boundary.components) for boundary in reference_model.trust_boundaries}
    after = {boundary.name: len(boundary.components) for boundary in renumbered.trust_boundaries}
    assert after == before


def test_component_type_comes_from_the_row_not_the_id():
    """A four-row model whose ids carry none of the old meaning still types."""
    architecture = ArchitectureParser().parse(
        "[Table 1]\n"
        "Row 1: ID | Component | Technology | Responsibility / Data\n"
        "Row 2: C71 | Clinical document store | Amazon S3 document store | Documents at rest\n"
        "Row 3: C72 | Identity service | AWS Cognito | Token issuance\n"
        "Row 4: C73 | Transactional database | Aurora PostgreSQL | Ledger\n"
        "Row 5: C74 | Customer web portal | React SPA | Customer UI\n"
        "\n"
        "[Table 2]\n"
        "Row 1: ID | Source and Destination | Protocol\n"
        "Row 2: F1 | C74 -> C72 | HTTPS\n"
        "Row 3: F2 | C74 -> C73 | HTTPS\n"
    )
    types = {component.name: component.type for component in architecture.components}
    assert types == {
        "Clinical document store": "Object Storage",
        "Identity service": "Identity Provider",
        "Transactional database": "Database",
        "Customer web portal": "WebClient",
    }

    trust = {component.name: component.trust_level for component in architecture.components}
    assert trust["Clinical document store"] == "restricted"
    assert trust["Transactional database"] == "restricted"
    assert trust["Identity service"] == "restricted"
    assert trust["Customer web portal"] == "public"


def test_flow_endpoints_are_the_ones_the_row_declares():
    """F4 and its siblings used to be rewritten to a fixed pair of components."""
    architecture = ArchitectureParser().parse(
        "[Table 1]\n"
        "Row 1: ID | Component | Technology\n"
        "Row 2: C1 | Web portal | React SPA\n"
        "Row 3: C4 | API edge | AWS API Gateway\n"
        "Row 4: C7 | Core API | Java Spring Boot\n"
        "Row 5: C14 | Ledger database | Aurora PostgreSQL\n"
        "\n"
        "[Table 2]\n"
        "Row 1: ID | Source and Destination | Protocol\n"
        "Row 2: F3 | C4 -> C7 | HTTPS\n"
        "Row 3: F4 | C4 -> C7 | HTTPS\n"
        "Row 4: F7 | C1 -> C4 | HTTPS\n"
        "Row 5: F17 | C7 -> C14 | TLS\n"
    )
    named = {component.id: component.name for component in architecture.components}
    routes = {
        flow.properties["source_record_id"]: (named[flow.source_id], named[flow.target_id])
        for flow in architecture.flows
    }
    assert routes == {
        "F3": ("API edge", "Core API"),
        "F4": ("API edge", "Core API"),
        "F7": ("Web portal", "API edge"),
        "F17": ("Core API", "Ledger database"),
    }


def test_controls_credit_the_components_they_describe():
    architecture = ArchitectureParser().parse(
        "[Table 1]\n"
        "Row 1: ID | Component | Technology\n"
        "Row 2: C30 | Identity service | AWS Cognito\n"
        "Row 3: C31 | Public API edge | AWS API Gateway\n"
        "Row 4: C32 | Internal load balancer | Private ALB\n"
        "Row 5: C33 | Receipt store | Amazon S3 document store\n"
        "\n"
        "[Table 2]\n"
        "Row 1: ID | Source and Destination | Protocol\n"
        "Row 2: F1 | C31 -> C30 | HTTPS\n"
        "Row 3: F2 | C31 -> C33 | HTTPS\n"
        "\n"
        "[Table 3]\n"
        "Row 1: Domain | Implemented controls\n"
        "Row 2: Identity | MFA enforced and OAuth2 with PKCE\n"
        "Row 3: Edge | WAF enabled and rate limiting per tenant\n"
        "Row 4: Data protection | Encryption at rest and in transit\n"
    )
    components = {component.name: component for component in architecture.components}

    assert components["Identity service"].properties["mfa_enabled"] is True
    assert components["Public API edge"].properties["waf_enabled"] is True
    assert components["Receipt store"].properties["encryption_at_rest"] is True
    assert components["Receipt store"].properties["public_access"] is False

    # An internal load balancer is not the edge the control row is talking about.
    assert "waf_enabled" not in components["Internal load balancer"].properties
    # Blocking public access is a claim about a bucket, so it is credited to the
    # store and not to every component the data protection row also covers.
    assert "s3_block_public_access" not in components["Public API edge"].properties
    assert "s3_block_public_access" not in components["Identity service"].properties


def test_boundary_membership_is_read_from_the_contents_column():
    architecture = ArchitectureParser().parse(
        "[Table 1]\n"
        "Row 1: ID | Component | Technology\n"
        "Row 2: C40 | Web portal | React SPA\n"
        "Row 3: C41 | Core API | Java Spring Boot\n"
        "Row 4: C42 | Ledger database | Aurora PostgreSQL\n"
        "\n"
        "[Table 2]\n"
        "Row 1: ID | Source and Destination | Protocol\n"
        "Row 2: F1 | C40 -> C41 | HTTPS\n"
        "Row 3: F2 | C41 -> C42 | TLS\n"
        "\n"
        "[Table 3]\n"
        "Row 1: ID | Boundary | Trust level | Contents\n"
        "Row 2: TB1 | Customer edge | public | C40\n"
        "Row 3: TB2 | Application tier | internal | C41\n"
        "Row 4: TB3 | Data tier | restricted | C42\n"
    )
    named = {component.id: component.name for component in architecture.components}
    membership = {
        boundary.name: [named[member] for member in boundary.components]
        for boundary in architecture.trust_boundaries
    }
    assert membership == {
        "Customer edge": ["Web portal"],
        "Application tier": ["Core API"],
        "Data tier": ["Ledger database"],
    }

    trust = {component.name: component.trust_level for component in architecture.components}
    assert trust == {
        "Web portal": "public",
        "Core API": "internal",
        "Ledger database": "restricted",
    }


def test_a_flow_to_an_undeclared_party_becomes_an_external_component():
    architecture = ArchitectureParser().parse(
        "[Table 1]\n"
        "Row 1: ID | Component | Technology\n"
        "Row 2: C1 | Payment service | Java Spring Boot\n"
        "Row 3: C2 | Notification service | Node.js with SendGrid integration\n"
        "\n"
        "[Table 2]\n"
        "Row 1: ID | Source and Destination | Protocol | Data\n"
        "Row 2: F1 | C1 -> Stripe | HTTPS | Payment token\n"
        "Row 3: F2 | C2 -> SendGrid | HTTPS | Notification payload\n"
    )
    external = {
        component.name: component
        for component in architecture.components
        if component.properties.get("external")
    }
    assert set(external) == {"Stripe", "SendGrid"}
    assert all(component.trust_level == "external" for component in external.values())

    # A service built "with SendGrid" must not absorb SendGrid's identity, or the
    # flow to the third party collapses into a self-loop and disappears.
    assert len(architecture.flows) == 2


def test_a_flow_naming_an_undeclared_id_is_reported_rather_than_guessed():
    architecture = ArchitectureParser().parse(
        "[Table 1]\n"
        "Row 1: ID | Component | Technology\n"
        "Row 2: C1 | Web portal | React SPA\n"
        "Row 3: C2 | Core API | Java Spring Boot\n"
        "\n"
        "[Table 2]\n"
        "Row 1: ID | Source and Destination | Protocol\n"
        "Row 2: F1 | C1 -> C2 | HTTPS\n"
        "Row 3: F2 | C2 -> C99 | TLS\n"
    )
    assert len(architecture.flows) == 1
    warnings = " ".join(architecture.metadata["authoritative_parse_warnings"])
    assert "C99" in warnings


def test_natural_multi_hop_flows_resolve_declared_inventory_before_external_nodes():
    architecture = ArchitectureParser().parse(
        "[Table 1]\n"
        "Row 1: ID | Component | Technology | Responsibility / Data\n"
        "Row 2: C1 | Public API edge | AWS API Gateway | Public request routing\n"
        "Row 3: C2 | Core API | Node.js | Application requests\n"
        "Row 4: C3 | Clinical document store | Amazon S3 | Uploaded records\n"
        "Row 5: C4 | Document ingestion | S3 event, SQS and Lambda | Scan uploads\n"
        "Row 6: C5 | Workflow bus | EventBridge, SNS and SQS | Async jobs\n"
        "\n"
        "[Table 2]\n"
        "Row 1: ID | Source and Destination | Protocol | Data | Boundary crossing\n"
        "Row 2: F1 | API Gateway -> private ALB -> Core API | HTTPS | Request | TB1 -> TB2\n"
        "Row 3: F2 | S3 -> SQS -> ingestion Lambda -> final S3 | AWS events | Object | TB2\n"
        "Row 4: F3 | Core API -> EventBridge/SQS -> workers | AWS events | Job | TB2\n"
    )

    names = {component.id: component.name for component in architecture.components}
    flows = {
        flow.properties["source_record_id"]: (names[flow.source_id], names[flow.target_id])
        for flow in architecture.flows
    }
    assert flows == {
        "F1": ("Public API edge", "Core API"),
        "F2": ("Clinical document store", "Document ingestion"),
        "F3": ("Core API", "Workflow bus"),
    }
    assert not any(component.id.startswith("ext_") for component in architecture.components)
