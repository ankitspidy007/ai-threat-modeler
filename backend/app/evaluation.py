"""Golden-corpus evaluation for threat-model quality and regressions."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence

from .engine.analyzer import ThreatAnalyzer
from .engine.stride_coverage_engine import STRIDE_CATEGORIES


@dataclass
class ScenarioScore:
    scenario_id: str
    required_findings: int
    detected_findings: int
    forbidden_findings: int
    architecture_checks: int
    architecture_checks_passed: int
    stride_cells_complete: bool
    grounded_findings: int
    total_findings: int
    critical_severity_checks: int
    critical_severity_passed: int
    component_scope_checks: int
    component_scope_passed: int
    forbidden_technology_checks: int
    hallucinated_technologies: int
    duplicate_findings: int
    stride_checks: Dict[str, int]
    stride_passed: Dict[str, int]
    disagreements: int
    surfaced_disagreements: int
    failures: List[str] = field(default_factory=list)

    @property
    def threat_recall(self) -> float:
        return self.detected_findings / self.required_findings if self.required_findings else 1.0

    @property
    def architecture_accuracy(self) -> float:
        return self.architecture_checks_passed / self.architecture_checks if self.architecture_checks else 1.0

    @property
    def evidence_rate(self) -> float:
        return self.grounded_findings / self.total_findings if self.total_findings else 1.0


def load_corpus(path: str | Path) -> List[Dict[str, Any]]:
    corpus = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(corpus, list) or not corpus:
        raise ValueError("Evaluation corpus must be a non-empty JSON array.")
    required = {"id", "description", "expected"}
    for index, scenario in enumerate(corpus):
        missing = required - set(scenario)
        if missing:
            raise ValueError(f"Scenario {index} is missing: {', '.join(sorted(missing))}")
    return corpus


def load_retrieval_corpus(path: str | Path) -> List[Dict[str, Any]]:
    corpus = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(corpus, list) or not corpus:
        raise ValueError("Retrieval corpus must be a non-empty JSON array.")
    for index, scenario in enumerate(corpus):
        missing = {"id", "query", "expected_ids", "forbidden_ids"} - set(scenario)
        if missing:
            raise ValueError(f"Retrieval scenario {index} is missing: {', '.join(sorted(missing))}")
    return corpus


def load_classifier_corpus(path: str | Path) -> List[Dict[str, Any]]:
    corpus = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(corpus, list) or not corpus:
        raise ValueError("Classifier corpus must be a non-empty JSON array.")
    for index, scenario in enumerate(corpus):
        missing = {"id", "text", "stride_category"} - set(scenario)
        if missing or scenario.get("stride_category") not in STRIDE_CATEGORIES:
            raise ValueError(f"Classifier scenario {index} is invalid.")
    return corpus


def evaluate_stride_classifier_corpus(corpus: Sequence[Dict[str, Any]], classifier=None) -> Dict[str, Any]:
    if classifier is None:
        from .engine.stride_classifier import StrideClassifier
        from .knowledge_base.loader import ThreatKnowledgeBase
        classifier = StrideClassifier()
        classifier.load_or_train(ThreatKnowledgeBase().get_all_threats())
    by_category = {category: {"correct": 0, "total": 0} for category in STRIDE_CATEGORIES}
    scenarios = []
    correct = 0
    for item in corpus:
        predicted, scores = classifier.predict(item["text"])
        expected = item["stride_category"]
        matched = predicted == expected
        correct += int(matched)
        by_category[expected]["total"] += 1
        by_category[expected]["correct"] += int(matched)
        scenarios.append({
            "id": item["id"], "expected": expected, "predicted": predicted,
            "correct": matched, "scores": {key: round(value, 4) for key, value in scores.items()},
        })
    per_stride = {
        category: _ratio(values["correct"], values["total"])
        for category, values in by_category.items()
    }
    return {
        "schema_version": "stride-classifier-eval-1.0",
        "metrics": {
            "accuracy": _ratio(correct, len(corpus)),
            "macro_accuracy": round(sum(per_stride.values()) / len(STRIDE_CATEGORIES), 4),
            "per_stride_accuracy": per_stride,
        },
        "scenarios": scenarios,
        "passed": _ratio(correct, len(corpus)) >= 0.9,
    }


def evaluate_retrieval_corpus(
    corpus: Sequence[Dict[str, Any]],
    matcher=None,
    knowledge_base=None,
) -> Dict[str, Any]:
    """Measure semantic candidate recall, rank, and hard-negative leakage."""
    if matcher is None or knowledge_base is None:
        from .engine.semantic_matcher import SemanticThreatMatcher
        from .knowledge_base.loader import ThreatKnowledgeBase
        knowledge_base = knowledge_base or ThreatKnowledgeBase()
        matcher = matcher or SemanticThreatMatcher()
    matcher.vectorize_knowledge_base(knowledge_base.get_all_threats())
    expected_total = 0
    expected_found = 0
    forbidden_total = 0
    forbidden_found = 0
    reciprocal_rank = 0.0
    scenarios = []
    for item in corpus:
        top_k = int(item.get("top_k", 5))
        results = matcher.find_relevant_threats(
            item["query"], item.get("component_type"), top_k,
            item.get("stride_category"), item.get("cloud_provider"),
            item.get("security_domains"),
        )
        ids = [metadata.get("threat_id") for metadata, _ in results]
        expected = item.get("expected_ids") or []
        forbidden = item.get("forbidden_ids") or []
        found_expected = [threat_id for threat_id in expected if threat_id in ids]
        found_forbidden = [threat_id for threat_id in forbidden if threat_id in ids]
        ranks = [ids.index(threat_id) + 1 for threat_id in expected if threat_id in ids]
        expected_total += len(expected)
        expected_found += len(found_expected)
        forbidden_total += len(forbidden)
        forbidden_found += len(found_forbidden)
        reciprocal_rank += 1.0 / min(ranks) if ranks else 0.0
        scenarios.append({
            "id": item["id"], "result_ids": ids,
            "missing_expected_ids": sorted(set(expected) - set(ids)),
            "leaked_forbidden_ids": found_forbidden,
            "reciprocal_rank": round(1.0 / min(ranks), 4) if ranks else 0.0,
        })
    return {
        "schema_version": "retrieval-eval-1.0",
        "metrics": {
            "recall_at_k": _ratio(expected_found, expected_total),
            "mean_reciprocal_rank": round(reciprocal_rank / len(corpus), 4) if corpus else 1.0,
            "hard_negative_leakage_rate": _ratio(forbidden_found, forbidden_total),
        },
        "scenarios": scenarios,
        "passed": all(not item["missing_expected_ids"] and not item["leaked_forbidden_ids"] for item in scenarios),
    }


def evaluate_corpus(
    corpus: Sequence[Dict[str, Any]],
    analyzer: ThreatAnalyzer | None = None,
    use_local_intelligence: bool = True,
) -> Dict[str, Any]:
    engine = analyzer or ThreatAnalyzer()
    scores = []
    for scenario in corpus:
        result = engine.analyze_from_text(
            scenario["description"],
            scenario["id"],
            use_local_slm=use_local_intelligence,
            domain_profile=scenario.get("domain", "general"),
        )
        scores.append(_evaluate_scenario(scenario, result))

    required = sum(item.required_findings for item in scores)
    detected = sum(item.detected_findings for item in scores)
    total_findings = sum(item.total_findings for item in scores)
    grounded = sum(item.grounded_findings for item in scores)
    architecture_checks = sum(item.architecture_checks for item in scores)
    architecture_passed = sum(item.architecture_checks_passed for item in scores)
    forbidden = sum(item.forbidden_findings for item in scores)
    severity_checks = sum(item.critical_severity_checks for item in scores)
    severity_passed = sum(item.critical_severity_passed for item in scores)
    scope_checks = sum(item.component_scope_checks for item in scores)
    scope_passed = sum(item.component_scope_passed for item in scores)
    technology_checks = sum(item.forbidden_technology_checks for item in scores)
    hallucinated_technologies = sum(item.hallucinated_technologies for item in scores)
    duplicates = sum(item.duplicate_findings for item in scores)
    disagreements = sum(item.disagreements for item in scores)
    surfaced_disagreements = sum(item.surfaced_disagreements for item in scores)
    critical_required = sum(len(item.get("expected", {}).get("critical_finding_ids", [])) for item in corpus)
    critical_detected = 0
    for scenario, score in zip(corpus, scores):
        critical_ids = set(scenario.get("expected", {}).get("critical_finding_ids", []))
        required_ids = set(scenario.get("expected", {}).get("finding_ids", []))
        missing_required = {
            failure.removeprefix("missing finding: ")
            for failure in score.failures if failure.startswith("missing finding: ")
        }
        critical_detected += len((critical_ids & required_ids) - missing_required)

    stride_recall = {
        category: _ratio(
            sum(item.stride_passed.get(category, 0) for item in scores),
            sum(item.stride_checks.get(category, 0) for item in scores),
        )
        for category in STRIDE_CATEGORIES
    }
    metrics = {
        "scenario_count": len(scores),
        "threat_recall": _ratio(detected, required),
        "critical_threat_recall": _ratio(critical_detected, critical_required),
        "precision_proxy": _ratio(detected, detected + forbidden),
        "architecture_accuracy": _ratio(architecture_passed, architecture_checks),
        "evidence_rate": _ratio(grounded, total_findings),
        "evidence_grounding_rate": _ratio(grounded, total_findings),
        "stride_matrix_completion": _ratio(sum(item.stride_cells_complete for item in scores), len(scores)),
        "stride_recall": stride_recall,
        **{f"stride_recall_{_metric_name(category)}": value for category, value in stride_recall.items()},
        "severity_accuracy": _ratio(severity_passed, severity_checks),
        "component_scope_accuracy": _ratio(scope_passed, scope_checks),
        "false_positive_rate": _ratio(forbidden, total_findings),
        "hallucinated_technology_rate": _ratio(hallucinated_technologies, technology_checks),
        "duplicate_finding_rate": _ratio(duplicates, total_findings),
        "disagreement_surface_rate": _ratio(surfaced_disagreements, disagreements),
        "forbidden_findings": forbidden,
    }
    return {
        "schema_version": "threat-eval-2.0",
        "metrics": metrics,
        "scenarios": [{**asdict(item), "threat_recall": round(item.threat_recall, 4),
                       "architecture_accuracy": round(item.architecture_accuracy, 4),
                       "evidence_rate": round(item.evidence_rate, 4)} for item in scores],
        "passed": all(not item.failures for item in scores),
    }


def assert_thresholds(
    report: Dict[str, Any],
    thresholds: Dict[str, float],
    maximums: Dict[str, float] | None = None,
) -> None:
    failures = []
    for metric, minimum in thresholds.items():
        actual = float(report["metrics"].get(metric, 0))
        if actual < minimum:
            failures.append(f"{metric}={actual:.3f} is below {minimum:.3f}")
    for metric, maximum in (maximums or {}).items():
        actual = float(report["metrics"].get(metric, 1))
        if actual > maximum:
            failures.append(f"{metric}={actual:.3f} exceeds {maximum:.3f}")
    if report["metrics"].get("forbidden_findings", 0):
        failures.append(f"forbidden_findings={report['metrics']['forbidden_findings']}")
    scenario_failures = [
        f"{item['scenario_id']}: {', '.join(item['failures'])}"
        for item in report["scenarios"] if item["failures"]
    ]
    if failures or scenario_failures:
        raise AssertionError("Evaluation quality gate failed:\n" + "\n".join(failures + scenario_failures))


def _evaluate_scenario(scenario: Dict[str, Any], result: Any) -> ScenarioScore:
    expected = scenario["expected"]
    findings = result.threats or []
    canonical_ids = {_canonical_finding_id(item.id) for item in findings}
    findings_by_id: Dict[str, List[Any]] = {}
    for item in findings:
        findings_by_id.setdefault(_canonical_finding_id(item.id), []).append(item)
    finding_fingerprints = []
    for item in findings:
        source_refs = tuple(sorted(
            str(detail.get("source_ref") or "") for detail in item.evidence_details or []
        ))
        finding_fingerprints.append((
            _canonical_finding_id(item.id),
            tuple(sorted(item.affected_components or [])),
            tuple(sorted(item.affected_data_flows or [])),
            source_refs,
        ))
    duplicate_findings = len(finding_fingerprints) - len(set(finding_fingerprints))
    required_ids = expected.get("finding_ids", [])
    failures = []
    detected = 0
    for required_id in required_ids:
        if required_id in canonical_ids:
            detected += 1
        else:
            failures.append(f"missing finding: {required_id}")

    forbidden = 0
    for forbidden_id in expected.get("forbidden_finding_ids", []):
        if forbidden_id in canonical_ids:
            forbidden += 1
            failures.append(f"forbidden finding: {forbidden_id}")

    for finding_id in expected.get("confirmed_finding_ids", []):
        if not any(item.tier == "Confirmed" for item in findings_by_id.get(finding_id, [])):
            failures.append(f"finding is not confirmed: {finding_id}")

    component_map = {item.id: item for item in result.architecture.components or []}
    scope_checks = 0
    scope_passed = 0
    for finding_id, expected_terms in expected.get("finding_component_terms", {}).items():
        scope_checks += 1
        scoped = []
        for item in findings_by_id.get(finding_id, []):
            for component_id in item.affected_components or []:
                component = component_map.get(component_id)
                if component:
                    scoped.append(f"{component.id} {component.name} {component.type}".lower())
        if not scoped or not any(term.lower() in " ".join(scoped) for term in expected_terms):
            failures.append(f"incorrect component scope for {finding_id}: expected one of {expected_terms}")
        else:
            scope_passed += 1

    critical_severity_checks = 0
    critical_severity_passed = 0
    for finding_id in expected.get("critical_finding_ids", []):
        critical_severity_checks += 1
        if any(item.severity == "Critical" for item in findings_by_id.get(finding_id, [])):
            critical_severity_passed += 1
        else:
            failures.append(f"critical severity mismatch: {finding_id}")

    expected_known_count = expected.get("known_issue_count")
    if expected_known_count is not None:
        actual_known_count = len((result.architecture.metadata or {}).get("known_issues", []))
        if actual_known_count != expected_known_count:
            failures.append(f"known issue count {actual_known_count} != {expected_known_count}")

    forbidden_ai_types = set(expected.get("forbidden_ai_component_types", []))
    if forbidden_ai_types:
        for item in findings:
            if not (item.id.startswith("KB-AI-") or "Prompt Injection" in item.title or "Inference API" in item.title):
                continue
            component = component_map.get(item.affected_component or item.component or "")
            if component and component.type in forbidden_ai_types:
                failures.append(f"AI finding {item.id} leaked onto {component.type} {component.id}")

    components = result.architecture.components or []
    component_text = " ".join(
        f"{item.id} {item.name} {item.type} {(item.properties or {}).get('technology', '')}"
        for item in components
    ).lower()
    architecture_checks = 0
    architecture_passed = 0
    forbidden_technology_checks = 0
    hallucinated_technologies = 0
    for term in expected.get("component_terms", []):
        architecture_checks += 1
        if _contains_term(component_text, term):
            architecture_passed += 1
        else:
            failures.append(f"missing component term: {term}")
    for term in expected.get("forbidden_component_terms", []):
        architecture_checks += 1
        forbidden_technology_checks += 1
        if not _contains_term(component_text, term):
            architecture_passed += 1
        else:
            hallucinated_technologies += 1
            failures.append(f"invented component term: {term}")

    topology = expected.get("topology", {})
    actual_counts = {
        "components": len(components),
        "flows": len(result.architecture.flows or []),
        "boundaries": len(result.architecture.trust_boundaries or []),
    }
    for key, bounds in topology.items():
        architecture_checks += 1
        minimum = bounds.get("min", bounds) if isinstance(bounds, dict) else bounds
        maximum = bounds.get("max", bounds) if isinstance(bounds, dict) else bounds
        actual = actual_counts[key]
        if minimum <= actual <= maximum:
            architecture_passed += 1
        else:
            failures.append(f"{key} count {actual} outside [{minimum}, {maximum}]")

    categories = {item.stride_category or item.category for item in findings}
    for item in findings:
        categories.update(item.affected_stride_categories or [])
    stride_checks = {category: 0 for category in STRIDE_CATEGORIES}
    stride_passed = {category: 0 for category in STRIDE_CATEGORIES}
    for category in expected.get("stride_categories", []):
        stride_checks[category] += 1
        if category not in categories:
            failures.append(f"missing STRIDE category: {category}")
        else:
            stride_passed[category] += 1

    coverage = result.stride_coverage or {}
    elements = coverage.get("elements", [])
    cells = coverage.get("cells", [])
    matrix_complete = (
        len(cells) == len(elements) * len(STRIDE_CATEGORIES)
        and all(cell.get("status") in {"finding", "control_present", "unknown", "not_applicable"} for cell in cells)
    )
    if not matrix_complete:
        failures.append("STRIDE matrix is incomplete")

    grounded = sum(
        1 for item in findings
        if item.evidence_details and all(detail.get("statement") for detail in item.evidence_details)
    )
    if grounded != len(findings):
        failures.append("one or more findings lack structured evidence")

    disagreement_items = (((result.engine_status or {}).get("disagreements") or {}).get("items") or [])
    surfaced_disagreements = sum(bool(item.get("question") and item.get("resolution")) for item in disagreement_items)

    return ScenarioScore(
        scenario_id=scenario["id"],
        required_findings=len(required_ids),
        detected_findings=detected,
        forbidden_findings=forbidden,
        architecture_checks=architecture_checks,
        architecture_checks_passed=architecture_passed,
        stride_cells_complete=matrix_complete,
        grounded_findings=grounded,
        total_findings=len(findings),
        critical_severity_checks=critical_severity_checks,
        critical_severity_passed=critical_severity_passed,
        component_scope_checks=scope_checks,
        component_scope_passed=scope_passed,
        forbidden_technology_checks=forbidden_technology_checks,
        hallucinated_technologies=hallucinated_technologies,
        duplicate_findings=duplicate_findings,
        stride_checks=stride_checks,
        stride_passed=stride_passed,
        disagreements=len(disagreement_items),
        surfaced_disagreements=surfaced_disagreements,
        failures=failures,
    )


def _canonical_finding_id(value: str) -> str:
    normalized = re.sub(r"^KB-", "", str(value or ""))
    normalized = re.sub(r"-(?:K\d+|\d{2}|[a-z][a-z0-9_]*)$", "", normalized, flags=re.IGNORECASE)
    return normalized


def _contains_term(text: str, term: str) -> bool:
    return bool(re.search(r"(?<![a-z0-9])" + re.escape(term.lower()) + r"(?![a-z0-9])", text.lower()))


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 1.0


def _metric_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
