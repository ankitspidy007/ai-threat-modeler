"""Unresolved coverage must leave the report as questions, not as a number.

Most STRIDE cells in a design review are unresolved because the description
does not state the control. Reporting that as a count discards the most useful
output the tool produces, and listing every cell buries it.
"""

import pytest

from app.engine.evidence_requests import CONTROL_FAMILIES, build_evidence_requests


def _cell(element_id, name, category, controls, kind="component", element_type="Service", status="unknown"):
    return {
        "element_id": element_id,
        "element_name": name,
        "element_kind": kind,
        "element_type": element_type,
        "category": category,
        "status": status,
        "rationale": f"The architecture does not specify: {', '.join(controls)}.",
        "finding_ids": [],
        "controls": controls,
    }


def _coverage(cells, elements=None):
    return {"cells": cells, "elements": elements or []}


def _element(element_id, trust_level="internal", properties=None):
    return {
        "id": element_id,
        "name": element_id,
        "kind": "component",
        "type": "Service",
        "trust_level": trust_level,
        "properties": properties or {},
    }


def test_many_unresolved_cells_collapse_into_few_questions():
    cells = [
        _cell(f"service_{index}", f"Service {index}", "Repudiation", ["audit_logging", "logging_enabled"])
        for index in range(20)
    ]

    result = build_evidence_requests(_coverage(cells))

    assert len(result["requests"]) == 1, "one control gap should ask one question"
    request = result["requests"][0]
    assert request["resolves_cells"] == 20
    assert len(request["elements"]) == 20
    assert "20" in result["summary"]


def test_every_unresolved_cell_is_accounted_for():
    """A question the analyst never sees is the same as no question at all."""
    cells = [
        _cell("api", "API", "Spoofing", ["auth_type", "mfa_enabled", "mtls_enabled"]),
        _cell("api", "API", "Elevation of Privilege", ["authorization", "rbac_enabled"]),
        _cell("db", "Database", "Information Disclosure", ["encryption_at_rest"], element_type="Database"),
        _cell("api", "API", "Denial of Service", ["rate_limiting", "waf_enabled"]),
        _cell("api", "API", "Tampering", ["integrity_validation", "input_validation"]),
    ]

    result = build_evidence_requests(_coverage(cells))

    assert result["cells_without_request"] == 0
    assert result["cells_addressed"] == result["unresolved_cells"] == 5


def test_a_question_names_every_element_it_would_resolve():
    cells = [
        _cell("api", "API", "Information Disclosure", ["encryption_at_rest"]),
        _cell("db", "Database", "Information Disclosure", ["encryption_at_rest"]),
    ]

    request = build_evidence_requests(_coverage(cells))["requests"][0]

    assert {element["name"] for element in request["elements"]} == {"API", "Database"}
    assert request["accepted_evidence"], "an analyst needs to know what would close the question"
    assert request["question"].endswith("?")


def test_exposure_drives_priority_rather_than_architecture_size():
    """Twenty internal services must not outrank one internet-facing service."""
    internal = [
        _cell(f"internal_{index}", f"Internal {index}", "Spoofing", ["auth_type", "mfa_enabled"])
        for index in range(20)
    ]
    internal_elements = [_element(f"internal_{index}") for index in range(20)]
    exposed = [_cell("edge", "Edge API", "Spoofing", ["auth_type", "mfa_enabled"])]
    exposed_elements = [_element("edge", trust_level="public")]

    internal_request = build_evidence_requests(_coverage(internal, internal_elements))["requests"][0]
    exposed_request = build_evidence_requests(_coverage(exposed, exposed_elements))["requests"][0]

    assert exposed_request["priority_score"] > internal_request["priority_score"]
    assert exposed_request["priority"] == "Critical"
    assert internal_request["priority"] != "Critical"


def test_a_trust_boundary_is_not_asked_to_describe_its_controls():
    """A boundary implements nothing; the question belongs on what crosses it."""
    cells = [
        _cell("boundary:internet", "internet", "Tampering", ["integrity_validation"], kind="boundary", element_type="internet"),
        _cell("api", "API", "Tampering", ["integrity_validation"]),
    ]

    result = build_evidence_requests(_coverage(cells))

    assert result["boundary_cells_excluded"] == 1
    names = [element["name"] for request in result["requests"] for element in request["elements"]]
    assert names == ["API"]


def test_a_component_and_its_data_are_distinguishable():
    cells = [
        _cell("kms", "AWS KMS", "Information Disclosure", ["encryption_at_rest"], element_type="Key Management"),
        _cell("asset:AWS KMS", "AWS KMS", "Information Disclosure", ["encryption_at_rest"], kind="asset", element_type="secrets"),
    ]

    request = build_evidence_requests(_coverage(cells))["requests"][0]

    labels = sorted(element["label"] for element in request["elements"])
    assert labels == ["AWS KMS (Key Management)", "AWS KMS (asset)"]


def test_a_fully_resolved_model_asks_nothing():
    cells = [_cell("api", "API", "Spoofing", ["auth_type"], status="control_present")]

    result = build_evidence_requests(_coverage(cells))

    assert result["requests"] == []
    assert "No further evidence is required" in result["summary"]


def test_requests_are_ranked_and_ordered_by_priority():
    cells = [
        _cell("edge", "Edge API", "Spoofing", ["auth_type", "mfa_enabled"]),
        _cell("worker", "Worker", "Repudiation", ["audit_logging"]),
    ]
    elements = [_element("edge", trust_level="public"), _element("worker")]

    requests = build_evidence_requests(_coverage(cells, elements))["requests"]

    assert [request["rank"] for request in requests] == [1, 2]
    assert requests[0]["title"] == "Authentication strength"
    assert requests[0]["priority_score"] >= requests[1]["priority_score"]


@pytest.mark.parametrize("family", CONTROL_FAMILIES, ids=lambda family: family["id"])
def test_every_family_is_answerable(family):
    """A question without accepted evidence cannot be closed."""
    assert family["question"].endswith("?")
    assert family["accepted_evidence"]
    assert 3 <= family["weight"] <= 5
    assert family["controls"]


def test_control_families_do_not_overlap():
    seen = {}
    for family in CONTROL_FAMILIES:
        for control in family["controls"]:
            assert control not in seen, f"{control} is claimed by {seen.get(control)} and {family['id']}"
            seen[control] = family["id"]
