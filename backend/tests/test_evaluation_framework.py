from pathlib import Path

from app.evaluation import (
    assert_thresholds, evaluate_corpus, evaluate_retrieval_corpus,
    evaluate_stride_classifier_corpus, load_classifier_corpus, load_corpus, load_retrieval_corpus,
)


CORPUS = Path(__file__).parent / "fixtures" / "evaluation_corpus.json"
RETRIEVAL_CORPUS = Path(__file__).parent / "fixtures" / "retrieval_corpus.json"
CLASSIFIER_CORPUS = Path(__file__).parent / "fixtures" / "stride_classifier_corpus.json"


def test_evaluation_corpus_meets_release_gate():
    report = evaluate_corpus(load_corpus(CORPUS))

    assert report["metrics"]["scenario_count"] >= 8
    assert_thresholds(report, {
        "threat_recall": 1.0,
        "critical_threat_recall": 1.0,
        "architecture_accuracy": 1.0,
        "evidence_rate": 1.0,
        "stride_matrix_completion": 1.0,
        "severity_accuracy": 1.0,
        "component_scope_accuracy": 1.0,
        "evidence_grounding_rate": 1.0,
        "disagreement_surface_rate": 1.0,
    }, {
        "false_positive_rate": 0.0,
        "hallucinated_technology_rate": 0.0,
        "duplicate_finding_rate": 0.0,
    })


def test_corpus_has_negative_expectations_for_hallucinations():
    corpus = load_corpus(CORPUS)
    assert all(item["expected"].get("forbidden_component_terms") for item in corpus)
    assert all("topology" in item["expected"] for item in corpus)


def test_semantic_retrieval_meets_recall_and_hard_negative_gate():
    report = evaluate_retrieval_corpus(load_retrieval_corpus(RETRIEVAL_CORPUS))

    assert report["metrics"]["recall_at_k"] == 1.0
    assert report["metrics"]["mean_reciprocal_rank"] >= 0.5
    assert report["metrics"]["hard_negative_leakage_rate"] == 0.0
    assert report["passed"] is True


def test_stride_classifier_meets_holdout_accuracy_gate():
    report = evaluate_stride_classifier_corpus(load_classifier_corpus(CLASSIFIER_CORPUS))

    assert report["metrics"]["accuracy"] >= 0.9
    assert report["metrics"]["macro_accuracy"] >= 0.9
    assert report["passed"] is True
