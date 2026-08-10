from app.services.claude_service import ClaudeService
from app.services.gemini_service import GeminiService
from app.services.llm_threat_contract import build_system_prompt, parse_response_json, parse_threats
from app.services.openai_service import OpenAIService


def test_llm_contract_prompt_contains_required_template_fields():
    prompt = build_system_prompt()

    for field in (
        "root_cause",
        "realistic_attack_scenario",
        "business_impact",
        "affected_components",
        "affected_data_flows",
        "specific_control",
        "implementation_detail",
    ):
        assert field in prompt


def test_parse_threats_preserves_report_template_fields():
    threats = parse_threats({
        "threats": [
            {
                "id": "LLM-001",
                "category": "Information Disclosure",
                "title": "Token leakage through logs",
                "description": "JWTs are logged by the API.",
                "severity": "High",
                "likelihood": "Medium",
                "impact": "High",
                "mitigation": "Redact authorization headers and tokens before writing logs.",
                "evidence": "centralized logging receives API request metadata",
                "affected_components": ["FastAPI API", "Central logging"],
                "affected_data_flows": ["FastAPI API -> Central logging"],
                "affected_assets": ["JWT access tokens"],
                "root_cause": "Sensitive request metadata is sent to logs without a redaction boundary.",
                "realistic_attack_scenario": "An operator account reads logs and reuses captured bearer tokens.",
                "business_impact": "Account takeover and customer data exposure.",
                "specific_control": "Token redaction",
                "implementation_detail": "Filter Authorization and Cookie headers at middleware.",
                "optional_config_example": "redact_headers=['authorization','cookie']",
                "owasp_top_10": "A02:2021 - Cryptographic Failures",
                "cwe_id": "CWE-532",
                "mitre_attack": ["T1552"],
                "nist_800_53": ["AU-9"],
            }
        ]
    })

    assert len(threats) == 1
    threat = threats[0]
    assert threat.title == "[AI] Token leakage through logs"
    assert threat.stride_category == "Information Disclosure"
    assert threat.evidence == ["centralized logging receives API request metadata"]
    assert threat.affected_components == ["FastAPI API", "Central logging"]
    assert threat.affected_data_flows == ["FastAPI API -> Central logging"]
    assert threat.affected_assets == ["JWT access tokens"]
    assert threat.root_cause.startswith("Sensitive request metadata")
    assert threat.realistic_attack_scenario.startswith("An operator account")
    assert threat.business_impact == "Account takeover and customer data exposure."
    assert threat.specific_control == "Token redaction"
    assert threat.implementation_detail.startswith("Filter Authorization")
    assert threat.optional_config_example == "redact_headers=['authorization','cookie']"
    assert threat.owasp_top_10 == ["A02:2021 - Cryptographic Failures"]
    assert threat.cwe == ["CWE-532"]
    assert threat.mitre_attack == ["T1552"]
    assert threat.nist_800_53 == ["AU-9"]


def test_parse_response_json_accepts_wrapped_json():
    payload = parse_response_json('Here is JSON:\n```json\n{"threats": []}\n```')
    assert payload == {"threats": []}


def test_providers_use_the_same_template_prompt():
    services = [
        OpenAIService("test-key"),
        ClaudeService("test-key"),
        GeminiService("test-key"),
    ]

    prompts = [service._get_system_prompt() for service in services]
    assert prompts[0] == prompts[1] == prompts[2]
