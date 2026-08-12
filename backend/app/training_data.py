"""Build versioned, reviewable security SLM instruction-tuning records."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List

from .engine.stride_coverage_engine import STRIDE_CATEGORIES


TRAINING_SCHEMA_VERSION = "security-slm-training-1.0"


def build_training_records(
    corpus: Iterable[Dict[str, Any]],
    analyzer,
    approved_by: str,
) -> List[Dict[str, Any]]:
    if not approved_by.strip():
        raise ValueError("approved_by is required; unreviewed data cannot be exported for fine-tuning")
    records = []
    for scenario in corpus:
        result = analyzer.analyze_from_text(
            scenario["description"], scenario["id"], use_local_slm=False,
            domain_profile=scenario.get("domain", "general"),
        )
        expected = scenario["expected"]
        findings = {_canonical_finding_id(item.id): item for item in result.threats or []}
        architecture = result.architecture.model_dump(mode="json")
        common = {
            "schema_version": TRAINING_SCHEMA_VERSION,
            "scenario_id": scenario["id"],
            "domain": scenario.get("domain", "general"),
            "source": scenario["description"],
            "approval": {
                "status": "approved",
                "approved_by": approved_by,
                "approved_at": datetime.now(timezone.utc).isoformat(),
                "basis": "versioned golden-corpus expectation",
            },
        }
        records.append(_record(common, "architecture_extraction", {
            "architecture": architecture,
            "instruction": "Extract only explicitly supported components, flows, boundaries, and assets.",
        }))

        for finding_id in expected.get("finding_ids", []):
            finding = findings.get(finding_id)
            if finding is None:
                continue
            records.append(_record(common, "applicable_threat", {
                "finding": _finding_label(finding),
                "instruction": "Return this threat only when its architecture evidence and applicability predicates hold.",
            }))

        for finding_id in expected.get("forbidden_finding_ids", []):
            records.append(_record(common, "non_applicable_threat", {
                "candidate_finding_id": finding_id,
                "decision": "reject",
                "reason": "The reviewed scenario does not contain the required technology or applicability evidence.",
                "instruction": "Reject this hard-negative threat and do not invent supporting components.",
            }))

        for term in expected.get("forbidden_component_terms", []):
            records.append(_record(common, "hallucination_rejection", {
                "candidate_component": term,
                "decision": "reject",
                "reason": "The component is absent from the reviewed source architecture.",
                "instruction": "Do not add this technology to the architecture model.",
            }))
    validate_training_records(records)
    return records


def validate_training_records(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not records:
        raise ValueError("training dataset must contain at least one record")
    required_tasks = {"architecture_extraction", "applicable_threat", "non_applicable_threat", "hallucination_rejection"}
    tasks = {item.get("task") for item in records}
    missing_tasks = required_tasks - tasks
    if missing_tasks:
        raise ValueError(f"training dataset is missing tasks: {', '.join(sorted(missing_tasks))}")
    categories = set()
    for index, item in enumerate(records):
        if item.get("schema_version") != TRAINING_SCHEMA_VERSION:
            raise ValueError(f"record {index} has an invalid schema version")
        approval = item.get("approval") or {}
        if approval.get("status") != "approved" or not approval.get("approved_by"):
            raise ValueError(f"record {index} is not expert approved")
        finding = (item.get("output") or {}).get("finding") or {}
        categories.update(finding.get("affected_stride_categories") or [])
        if finding.get("stride_category"):
            categories.add(finding["stride_category"])
    missing_categories = set(STRIDE_CATEGORIES) - categories
    return {
        "schema_version": TRAINING_SCHEMA_VERSION,
        "record_count": len(records),
        "tasks": sorted(tasks),
        "stride_categories": sorted(categories),
        "missing_stride_categories": sorted(missing_categories),
        "complete_stride_coverage": not missing_categories,
    }


def write_jsonl(records: List[Dict[str, Any]], output: str | Path) -> Dict[str, Any]:
    validation = validate_training_records(records)
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    rendered = "\n".join(json.dumps(item, ensure_ascii=True, sort_keys=True) for item in records) + "\n"
    path.write_text(rendered, encoding="utf-8")
    validation["sha256"] = hashlib.sha256(rendered.encode("utf-8")).hexdigest()
    validation["output"] = str(path)
    manifest_path = path.with_suffix(path.suffix + ".manifest.json")
    manifest_path.write_text(json.dumps(validation, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    validation["manifest"] = str(manifest_path)
    return validation


def _record(common: Dict[str, Any], task: str, output: Dict[str, Any]) -> Dict[str, Any]:
    return {
        **common,
        "task": task,
        "messages": [
            {"role": "system", "content": "You are a constrained technical threat-model reviewer. Use only supplied evidence."},
            {"role": "user", "content": common["source"]},
            {"role": "assistant", "content": json.dumps(output, ensure_ascii=True, sort_keys=True)},
        ],
        "output": output,
    }


def _finding_label(finding) -> Dict[str, Any]:
    return {
        "id": _canonical_finding_id(finding.id),
        "title": finding.title,
        "stride_category": finding.stride_category or finding.category,
        "affected_stride_categories": finding.affected_stride_categories or [finding.stride_category or finding.category],
        "severity": finding.severity,
        "tier": finding.tier,
        "affected_components": finding.affected_components,
        "affected_data_flows": finding.affected_data_flows,
        "affected_assets": finding.affected_assets,
        "evidence": finding.evidence_details,
        "preconditions": finding.preconditions,
        "mitigation": finding.mitigation,
        "negating_controls": (finding.explanation or {}).get("negating_controls", []),
    }


def _canonical_finding_id(value: str) -> str:
    normalized = re.sub(r"^KB-", "", str(value or ""))
    return re.sub(r"-(?:K\d+|\d{2}|[a-z][a-z0-9_]*)$", "", normalized, flags=re.IGNORECASE)
