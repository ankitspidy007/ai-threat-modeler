"""Add the missing-MFA predicate to the knowledge base, if it is not there yet.

Written as a script so the edit to a large generated JSON file is reviewable and
repeatable rather than hand-applied.
"""

import json
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent / "app" / "knowledge_base" / "threats.json"

RULE = {
    "id": "S-009",
    "category": "Spoofing",
    "cwe": ["CWE-308"],
    "owasp_top_10": ["A07:2021 Identification and Authentication Failures"],
    "resource_type": ["IdentityProvider", "WebClient", "APIGateway"],
    "detection": {
        "logic": {
            "operator": "AND",
            "conditions": [
                {"field": "mfa_enabled", "op": "==", "value": False},
            ],
        },
        "auto_detectable": True,
        "confidence": "high",
    },
    "threat": {
        "title": "Sign-in Without a Second Factor",
        "description": (
            "The sign-in path accepts a single factor, so a phished, reused or guessed "
            "password is enough to take over an account."
        ),
        "attack_vector": (
            "An attacker replays credentials obtained from a phishing page or an unrelated "
            "breach and reaches the account directly, with no second factor to stop them."
        ),
    },
    "risk": {
        "severity": "High",
        "likelihood": "High",
        "impact": "High",
        "risk_score": 78.0,
        "affected_assets": ["Accounts", "Data"],
        "business_impact": ["Account Takeover", "Data Breach"],
    },
    "mitigation": {
        "primary": (
            "Require phishing-resistant multi-factor authentication on this sign-in path, "
            "starting with administrative and remote access."
        ),
        "defense_in_depth": [
            "Step-up authentication for sensitive operations",
            "Impossible-travel and credential-stuffing detection",
        ],
        "verification": "Attempt a password-only sign-in and confirm it is refused.",
    },
    "metadata": {
        "version": "1.0",
        "last_reviewed": "2026-08-16",
        "created": "2026-08-16",
        "last_updated": "2026-08-16",
        "author": "AI Threat Modeler Intelligence Team",
        "reviewed_by": "Security Architect",
    },
    "evidence": {
        "derived_from": ["mfa_enabled"],
        "reasoning": "The description states that multi-factor authentication is absent.",
    },
    "signal_source": ["configuration", "architecture"],
    "negating_controls": ["mfa_enabled", "passwordless_authentication"],
    "mapped_controls": {
        "owasp_top_10": ["A07:2021"],
        "nist_800_53": ["IA-2"],
    },
    "maturity_level": "baseline",
}


def main() -> int:
    rules = json.loads(BASE.read_text(encoding="utf-8"))
    if any(rule["id"] == RULE["id"] for rule in rules):
        print(f"{RULE['id']} already present")
        return 0
    rules.append(RULE)
    BASE.write_text(json.dumps(rules, indent=4) + "\n", encoding="utf-8")
    print(f"added {RULE['id']} ({len(rules)} rules)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
