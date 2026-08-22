"""A document the tool could not fully read must not be reported as fully read.

An architecture diagram is usually an image. Extracting nothing from it and then
publishing "ready" presents a model of part of a design as a model of the design.
"""

import io

import pytest
from fastapi.testclient import TestClient

from app.engine.analyzer import ThreatAnalyzer
from app.engine.reporter import ReportGenerator
from app.models import AnalysisResult, Component, SystemArchitecture, Threat


VALID = {"valid": True}
NO_COVERAGE_CONCERN = {"unknown_cells": 0, "applicable_cells": 0}
gate = ThreatAnalyzer._runtime_quality_gate


def _threat():
    return Threat(
        id="T-1",
        category="Tampering",
        stride_category="Tampering",
        title="Finding",
        description="Description",
        severity="High",
        mitigation="Fix it.",
        component="api",
        affected_component="api",
        affected_components=["api"],
        root_cause="Cause",
        tier="Confirmed",
        evidence_details=[{"source_ref": "K1", "statement": "Stated in input"}],
    )


def _architecture(*documents):
    return SystemArchitecture(
        components=[Component(id="api", name="API", type="API")],
        flows=[],
        metadata={"source_documents": list(documents)},
    )


def _pdf(filename="design.pdf", image_only_pages="", quality="text_complete", warning=""):
    return {
        "filename": filename,
        "type": "pdf",
        "role": "source_design",
        "characters": "400",
        "pages": "8",
        "image_only_pages": image_only_pages,
        "extraction_quality": quality,
        "warning": warning,
    }


def test_a_fully_read_document_leaves_the_report_ready():
    result = gate(VALID, [_threat()], NO_COVERAGE_CONCERN, architecture=_architecture(_pdf()))

    assert result["status"] == "ready"
    assert result["unread_document_content"] == []


def test_image_only_pages_mark_the_report_for_review():
    architecture = _architecture(_pdf(
        image_only_pages="3,7", quality="partial",
        warning="Pages 3, 7 contained no extractable text; OCR or diagram review is required.",
    ))

    result = gate(VALID, [_threat()], NO_COVERAGE_CONCERN, architecture=architecture)

    assert result["status"] == "review"
    assert [item["check"] for item in result["completeness_warnings"]] == ["unread_document_content"]
    assert result["unread_document_content"][0]["unread_pages"] == ["3", "7"]


def test_the_warning_names_the_document_and_the_pages():
    architecture = _architecture(_pdf(image_only_pages="3,7", quality="partial"))

    result = gate(VALID, [_threat()], NO_COVERAGE_CONCERN, architecture=architecture)
    detail = result["completeness_warnings"][0]["detail"]

    assert "design.pdf" in detail
    assert "pages 3, 7" in detail


def test_an_embedded_diagram_with_no_page_numbers_is_still_reported():
    architecture = _architecture({
        "filename": "topology.docx", "type": "docx", "role": "source_design",
        "characters": "900", "tables": "2", "embedded_images": "3",
        "extraction_quality": "partial",
        "warning": "Embedded images require separate diagram review.",
    })

    result = gate(VALID, [_threat()], NO_COVERAGE_CONCERN, architecture=architecture)
    detail = result["completeness_warnings"][0]["detail"]

    assert result["status"] == "review"
    assert "topology.docx" in detail
    assert "embedded images require separate diagram review" in detail


def test_the_docx_fallback_parser_counts_as_incomplete_not_as_a_hard_failure():
    # The fallback preserves paragraphs and tables, so the analysis is worth
    # having. Ingestion writes "structured_text_fallback"; a guard in the API
    # used to compare against a string nothing ever produced, so this case
    # passed through entirely unremarked.
    architecture = _architecture({
        "filename": "records.docx", "type": "docx", "role": "source_design",
        "characters": "500", "embedded_images": "unknown",
        "extraction_quality": "structured_text_fallback",
        "warning": "DOCX images require separate review; paragraph and table order was preserved.",
    })

    result = gate(VALID, [_threat()], NO_COVERAGE_CONCERN, architecture=architecture)

    assert result["status"] == "review"
    assert result["unread_document_content"][0]["document"] == "records.docx"


def test_many_unread_documents_are_summarized_rather_than_listed_in_full():
    architecture = _architecture(*[
        _pdf(filename=f"doc-{index}.pdf", image_only_pages="2", quality="partial")
        for index in range(5)
    ])

    result = gate(VALID, [_threat()], NO_COVERAGE_CONCERN, architecture=architecture)
    warning = result["completeness_warnings"][0]

    assert warning["count"] == 5
    assert "and 2 more" in warning["detail"]


def test_a_typed_description_with_no_uploads_is_unaffected():
    result = gate(VALID, [_threat()], NO_COVERAGE_CONCERN, architecture=_architecture())

    assert result["status"] == "ready"
    assert result["unread_document_content"] == []


def test_the_report_states_which_pages_were_not_read():
    architecture = _architecture(_pdf(image_only_pages="4", quality="partial"))
    quality_gate = gate(VALID, [_threat()], NO_COVERAGE_CONCERN, architecture=architecture)
    result = AnalysisResult(
        project_name="Unread",
        summary="Summary",
        score=50,
        threats=[],
        architecture=architecture,
        engine_status={"quality_gate": quality_gate},
    )

    markdown = ReportGenerator.generate_markdown(result)

    assert "Documents not fully read:" in markdown
    assert "design.pdf: pages 4" in markdown


class TestDocumentUpload:
    @pytest.fixture
    def client(self):
        from app.main import app
        with TestClient(app) as test_client:
            yield test_client

    def test_a_readable_document_is_still_analyzed(self, client):
        files = [(
            "files",
            ("design.md", io.BytesIO(b"# Design\nA React portal calls an orders API."), "text/markdown"),
        )]

        response = client.post("/analyze-documents", data={"project_name": "Readable"}, files=files)

        assert response.status_code == 200, response.text
        gate_result = response.json()["engine_status"]["quality_gate"]
        assert gate_result["unread_document_content"] == []
