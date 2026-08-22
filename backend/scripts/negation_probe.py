"""Does a stated weakness survive as a weakness, or become its opposite?"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.engine.parser import ArchitectureParser

CASES = (
    "The clinician portal has no MFA.",
    "There is no MFA on the clinician portal.",
    "MFA is not enforced on the clinician portal.",
    "The clinician portal does not require MFA.",
    "MFA is enforced on the clinician portal.",
    "The admin console lacks multi-factor authentication.",
    "Data in the ledger database is not encrypted at rest.",
    "The receipts bucket is not encrypted at rest.",
    "The API has no rate limiting.",
    "There is no WAF in front of the public API edge.",
)

BASE = "A clinician portal calls a records service backed by a ledger database and a receipts bucket. "

WATCH = (
    "mfa_enabled", "encryption_at_rest", "rate_limiting", "waf_enabled",
    "auth_type", "public_access",
)


def main() -> None:
    parser = ArchitectureParser()
    for sentence in CASES:
        architecture = parser.parse(BASE + sentence)
        print(f"\n{sentence}")
        for component in architecture.components:
            stated = {
                key: value for key, value in (component.properties or {}).items()
                if key in WATCH and value not in (None, "unknown")
            }
            if stated:
                print(f"   {component.name:<24} {stated}")
        issues = architecture.metadata.get("known_issues") or []
        print(f"   known_issues={len(issues)}")


if __name__ == "__main__":
    main()
