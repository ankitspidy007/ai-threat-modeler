"""
Shared prompt and parsing contract for LLM threat-model findings.
"""
import json
from typing import Dict, List

from ..models import Threat


STRIDE_CATEGORIES = (
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
)


def build_system_prompt() -> str:
    """Return the canonical JSON-only threat-modeling system prompt."""
    categories = "|".join(STRIDE_CATEGORIES)
    return f"""You are a senior security architect performing structured threat modeling.

Your job is to return machine-readable threat findings only.
Do not write prose outside JSON.
Do not include markdown fences.
Do not include commentary, reasoning steps, or explanation of the format.

Return exactly one JSON object with this top-level shape:
{{
  "threats": [
    {{
      "id": "LLM-001",
      "category": "{categories}",
      "stride_category": "{categories}",
      "title": "Short threat title",
      "description": "Concrete architecture-specific threat description",
      "severity": "Critical|High|Medium|Low",
      "likelihood": "High|Medium|Low",
      "impact": "High|Medium|Low",
      "risk_score": 75,
      "mitigation": "Specific mitigation steps",
      "evidence": ["direct architecture evidence 1", "direct architecture evidence 2"],
      "affected_components": ["component name"],
      "affected_data_flows": ["source -> target"],
      "affected_assets": ["asset name"],
      "component": "primary affected component",
      "data_flow": "primary affected data flow",
      "asset": "primary affected asset",
      "root_cause": "Why the architecture enables the threat",
      "realistic_attack_scenario": "One realistic attack path in plain language",
      "attack_scenario": "Same value as realistic_attack_scenario unless a shorter variant is needed",
      "business_impact": "Operational or business impact",
      "specific_control": "Named control to implement",
      "implementation_detail": "Concrete implementation guidance",
      "optional_config_example": "Short optional config or policy example",
      "owasp_top_10": ["A01:2021 - Broken Access Control"],
      "cwe": ["CWE-200"],
      "cwe_id": ["CWE-200"],
      "mitre_attack": ["T1190"],
      "mitre_atlas": [],
      "nist_800_53": ["AC-3"]
    }}
  ]
}}

Rules:
- Use this exact threat template for every finding.
- Only return threats supported by the provided architecture.
- Every threat must include concrete evidence strings from the architecture text.
- Prefer 3 to 12 high-signal threats rather than broad speculative coverage.
- Use STRIDE categories exactly as listed above.
- If a field is unknown, use an empty array for arrays or an empty string for strings.
- Keep IDs stable within the response using LLM-001, LLM-002, and so on.
"""


def build_user_prompt(description: str, project_name: str) -> str:
    """Build the canonical user prompt for structured LLM analysis."""
    return f"""TASK
Analyze the following architecture and produce threat findings that can be merged into the existing threat-model report template.

PROJECT
{project_name}

ANALYSIS OBJECTIVE
- Find architecture-specific threats using STRIDE.
- Focus on realistic, evidence-based findings.
- Output only the JSON object defined in the system instructions.
- Populate every threat field in the template when the architecture provides enough evidence.

PRIORITY AREAS
- Authentication and authorization
- Sensitive data exposure and storage
- API and external integration risk
- Trust-boundary crossing
- Injection and prompt-manipulation risk
- Session and token handling
- Logging, auditability, and repudiation
- Availability and denial-of-service exposure
- Privilege escalation and lateral movement

ARCHITECTURE DESCRIPTION
{description}
"""


def parse_response_json(content: str) -> Dict:
    """Extract and parse the JSON object from a model response."""
    normalized = content.strip()
    if "```json" in normalized:
        normalized = normalized.split("```json", 1)[1].split("```", 1)[0].strip()
    elif "```" in normalized:
        normalized = normalized.split("```", 1)[1].split("```", 1)[0].strip()

    try:
        return json.loads(normalized)
    except json.JSONDecodeError:
        start = normalized.find("{")
        end = normalized.rfind("}")
        if start != -1 and end != -1 and end > start:
            return json.loads(normalized[start:end + 1])
        raise RuntimeError("LLM did not return valid JSON")


def parse_threats(threats_data: Dict) -> List[Threat]:
    """Parse canonical LLM JSON into backend Threat objects."""
    threats = []

    for index, threat_dict in enumerate(threats_data.get("threats", []), 1):
        try:
            category = _normalize_category(threat_dict.get("category"))
            title = str(threat_dict.get("title") or "Unknown Threat").strip()
            if not title.startswith("[AI]"):
                title = f"[AI] {title}"

            realistic_attack_scenario = _string_or_empty(
                threat_dict.get("realistic_attack_scenario") or threat_dict.get("attack_scenario")
            )
            affected_components = _as_list(threat_dict.get("affected_components"))
            affected_data_flows = _as_list(threat_dict.get("affected_data_flows"))
            affected_assets = _as_list(threat_dict.get("affected_assets"))

            severity = _normalize_level(threat_dict.get("severity"), "Medium", allow_critical=True)
            likelihood = _normalize_level(threat_dict.get("likelihood"), "Medium")

            threat = Threat(
                id=_string_or_empty(threat_dict.get("id")) or f"LLM-{index:03d}",
                category=category,
                stride_category=_normalize_category(threat_dict.get("stride_category") or category),
                title=title,
                description=_string_or_empty(threat_dict.get("description")),
                severity=severity,
                likelihood=likelihood,
                impact=_normalize_level(threat_dict.get("impact"), "Medium"),
                risk_score=_coerce_risk_score(threat_dict.get("risk_score"), severity, likelihood),
                mitigation=_string_or_empty(threat_dict.get("mitigation")),
                confidence="High",
                evidence=_as_list(threat_dict.get("evidence")),
                status="Identified",
                tier="Confirmed",
                component=_string_or_none(threat_dict.get("component")),
                data_flow=_string_or_none(threat_dict.get("data_flow")),
                asset=_string_or_none(threat_dict.get("asset")),
                affected_component=_string_or_none(threat_dict.get("affected_component")) or _first_or_none(affected_components),
                related_data_flow=_string_or_none(threat_dict.get("related_data_flow")) or _first_or_none(affected_data_flows),
                root_cause=_string_or_none(threat_dict.get("root_cause")),
                realistic_attack_scenario=realistic_attack_scenario or None,
                attack_scenario=_string_or_empty(threat_dict.get("attack_scenario")) or realistic_attack_scenario or None,
                business_impact=_string_or_none(threat_dict.get("business_impact")),
                specific_control=_string_or_none(threat_dict.get("specific_control")),
                implementation_detail=_string_or_none(threat_dict.get("implementation_detail")),
                optional_config_example=_string_or_none(threat_dict.get("optional_config_example")),
                owasp_top_10=_as_list(threat_dict.get("owasp_top_10")),
                cwe=_as_list(threat_dict.get("cwe") or threat_dict.get("cwe_id")),
                mitre_attack=_as_list(threat_dict.get("mitre_attack")),
                mitre_atlas=_as_list(threat_dict.get("mitre_atlas")),
                nist_800_53=_as_list(threat_dict.get("nist_800_53")),
                affected_components=affected_components,
                affected_data_flows=affected_data_flows,
                affected_assets=affected_assets,
            )
            threats.append(threat)
        except Exception as exc:
            print(f"Failed to parse LLM threat: {exc} | Data: {threat_dict}")
            continue

    return threats


def calculate_risk_score(severity: str, likelihood: str) -> int:
    severity_scores = {"Critical": 100, "High": 75, "Medium": 50, "Low": 25}
    likelihood_scores = {"High": 1.0, "Medium": 0.7, "Low": 0.4}
    return int(severity_scores.get(severity, 50) * likelihood_scores.get(likelihood, 0.7))


def _as_list(value) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, tuple):
        return [str(item).strip() for item in value if str(item).strip()]
    text = str(value).strip()
    return [text] if text else []


def _coerce_risk_score(value, severity: str, likelihood: str) -> int:
    try:
        score = int(value)
        return max(0, min(100, score))
    except (TypeError, ValueError):
        return calculate_risk_score(severity, likelihood)


def _first_or_none(values: List[str]):
    return values[0] if values else None


def _normalize_category(value) -> str:
    text = _string_or_empty(value)
    for category in STRIDE_CATEGORIES:
        if text.lower() == category.lower():
            return category
    return "Unknown"


def _normalize_level(value, default: str, allow_critical: bool = False) -> str:
    allowed = {"High", "Medium", "Low"}
    if allow_critical:
        allowed.add("Critical")
    text = _string_or_empty(value).title()
    return text if text in allowed else default


def _string_or_empty(value) -> str:
    return str(value).strip() if value is not None else ""


def _string_or_none(value):
    text = _string_or_empty(value)
    return text or None
