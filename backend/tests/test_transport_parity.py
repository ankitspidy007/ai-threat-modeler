"""The streamed report and the requested report must be the same report.

The UI streams by default and falls back to REST, so any difference between the
two transports is a difference most users never see. A previous release shipped
a streaming path that raised on every request and produced a report with no
quality gate at all; these tests exist to make that class of drift fail loudly.
"""

import json

import pytest
from fastapi.testclient import TestClient

from app.main import app

DESCRIPTION = (
    "A React web portal and an iOS mobile app call an API gateway over HTTPS. "
    "The API gateway routes to a payments service, which stores transactions in "
    "a PostgreSQL database that is not encrypted at rest. Auth0 issues tokens. "
    "Known issues: the JWT signing secret is committed to the repository."
)

PAYLOAD = {
    "description": DESCRIPTION,
    "project_name": "Transport Parity",
    "analysis_mode": "fast",
    "domain_profile": "general",
}

# Fields that carry the analytical substance of a report. A transport that drops
# any of these is not serving the same pipeline.
REQUIRED_FIELDS = [
    "threats",
    "architecture",
    "score",
    "engine_status",
    "stride_coverage",
    "system_model",
    "coverage",
    "follow_up_questions",
    "evidence_requests",
    "finding_groups",
    "report_markdown",
    "mermaid_diagram",
]


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="module")
def rest_result(client):
    response = client.post("/analyze", json=PAYLOAD)
    assert response.status_code == 200, response.text
    return response.json()


@pytest.fixture(scope="module")
def streamed(client):
    """Return (progress events, result payload) from the WebSocket transport."""
    events = []
    with client.websocket_connect("/ws/analyze") as socket:
        socket.send_text(json.dumps(PAYLOAD))
        while True:
            message = socket.receive_json()
            if message.get("type") == "error":
                pytest.fail(f"streaming analysis failed: {message.get('message')}")
            if message.get("type") == "result":
                return events, message["data"]
            events.append(message)


def test_the_streaming_transport_accepts_everything_the_endpoint_sends(streamed):
    """Signature drift between the endpoint and the analyzer must not be possible."""
    _, result = streamed
    assert result["threats"] is not None


def test_both_transports_return_the_same_report_fields(rest_result, streamed):
    _, streamed_result = streamed
    for field in REQUIRED_FIELDS:
        assert rest_result.get(field) is not None, f"REST is missing {field}"
        assert streamed_result.get(field) is not None, f"streaming is missing {field}"


def test_the_streamed_report_is_gated_like_the_requested_report(rest_result, streamed):
    _, streamed_result = streamed
    rest_gate = rest_result["engine_status"]["quality_gate"]
    streamed_gate = streamed_result["engine_status"]["quality_gate"]
    assert streamed_gate["status"] == rest_gate["status"]
    assert streamed_gate["publication_status"] == rest_gate["publication_status"]
    assert set(streamed_gate) == set(rest_gate)


def test_both_transports_find_the_same_threats(rest_result, streamed):
    _, streamed_result = streamed
    assert sorted(threat["id"] for threat in streamed_result["threats"]) == sorted(
        threat["id"] for threat in rest_result["threats"]
    )
    assert streamed_result["score"] == rest_result["score"]


def test_the_declared_known_issue_survives_both_transports(rest_result, streamed):
    _, streamed_result = streamed
    for name, result in (("REST", rest_result), ("streaming", streamed_result)):
        titles = " ".join(threat["title"].lower() for threat in result["threats"])
        assert "jwt" in titles or "secret" in titles, f"{name} lost the declared known issue"


def test_progress_is_reported_in_order_and_reaches_completion(streamed):
    events, _ = streamed
    assert events, "no progress was streamed"
    percentages = [event["progress"] for event in events]
    assert percentages == sorted(percentages)
    assert percentages[0] == 0
    assert events[-1]["phase"] == "complete"
    assert events[-1]["progress"] == 100
    phases = [event["phase"] for event in events]
    assert "reporting" in phases
    for event in events:
        assert event["label"], "a client needs a human-readable phase label"
