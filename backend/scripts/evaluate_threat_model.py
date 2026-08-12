"""Run the versioned golden threat-model corpus from the command line."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

BACKEND_ROOT = Path(__file__).parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.evaluation import (
    assert_thresholds, evaluate_corpus, evaluate_retrieval_corpus,
    evaluate_stride_classifier_corpus, load_classifier_corpus, load_corpus, load_retrieval_corpus,
)


DEFAULT_THRESHOLDS = {
    "threat_recall": 1.0,
    "critical_threat_recall": 1.0,
    "architecture_accuracy": 1.0,
    "evidence_rate": 1.0,
    "stride_matrix_completion": 1.0,
    "severity_accuracy": 1.0,
    "component_scope_accuracy": 1.0,
    "evidence_grounding_rate": 1.0,
    "disagreement_surface_rate": 1.0,
    "stride_recall_spoofing": 1.0,
    "stride_recall_tampering": 1.0,
    "stride_recall_repudiation": 1.0,
    "stride_recall_information_disclosure": 1.0,
    "stride_recall_denial_of_service": 1.0,
    "stride_recall_elevation_of_privilege": 1.0,
}

MAXIMUM_THRESHOLDS = {
    "false_positive_rate": 0.0,
    "hallucinated_technology_rate": 0.0,
    "duplicate_finding_rate": 0.0,
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate threat-model quality against the golden corpus.")
    parser.add_argument(
        "--corpus",
        default=str(BACKEND_ROOT / "tests" / "fixtures" / "evaluation_corpus.json"),
    )
    parser.add_argument("--output", help="Optional path for the JSON report.")
    parser.add_argument(
        "--retrieval-corpus",
        default=str(BACKEND_ROOT / "tests" / "fixtures" / "retrieval_corpus.json"),
    )
    parser.add_argument(
        "--classifier-corpus",
        default=str(BACKEND_ROOT / "tests" / "fixtures" / "stride_classifier_corpus.json"),
    )
    parser.add_argument("--no-gate", action="store_true", help="Report metrics without enforcing thresholds.")
    args = parser.parse_args()

    report = evaluate_corpus(load_corpus(args.corpus))
    retrieval_report = evaluate_retrieval_corpus(load_retrieval_corpus(args.retrieval_corpus))
    classifier_report = evaluate_stride_classifier_corpus(load_classifier_corpus(args.classifier_corpus))
    report["retrieval_evaluation"] = retrieval_report
    report["stride_classifier_evaluation"] = classifier_report
    rendered = json.dumps(report, indent=2)
    print(rendered)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    if not args.no_gate:
        assert_thresholds(report, DEFAULT_THRESHOLDS, MAXIMUM_THRESHOLDS)
        retrieval_metrics = retrieval_report["metrics"]
        if (
            retrieval_metrics["recall_at_k"] < 1.0
            or retrieval_metrics["mean_reciprocal_rank"] < 0.5
            or retrieval_metrics["hard_negative_leakage_rate"] > 0.0
        ):
            raise AssertionError(f"Semantic retrieval quality gate failed: {retrieval_metrics}")
        classifier_metrics = classifier_report["metrics"]
        if classifier_metrics["accuracy"] < 0.9 or classifier_metrics["macro_accuracy"] < 0.9:
            raise AssertionError(f"STRIDE classifier quality gate failed: {classifier_metrics}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
