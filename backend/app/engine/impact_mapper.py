from typing import Dict


def map_business_impact(threat: Dict) -> str:
    title = (threat.get("title") or "").lower()
    root_cause = (threat.get("root_cause") or "").lower()
    asset = (threat.get("asset") or "").lower()
    asset_sensitivity = (threat.get("asset_sensitivity") or threat.get("data_sensitivity") or "").lower()

    if "prompt injection" in title or "retrieval" in root_cause or "tool" in root_cause:
        return "Model decision manipulation, unsafe tool execution, or incorrect automated outcomes that can drive financial or operational loss."
    if "auth" in title or "authorization" in root_cause or "object-level" in root_cause:
        return "Unauthorized access to business functions or customer records, creating fraud exposure and regulatory breach risk."
    if "encryption" in title or "disclosure" in title or asset_sensitivity in {"pii", "phi", "financial", "credentials", "secrets"}:
        return "Sensitive data exposure leading to compliance penalties, incident response cost, and customer trust damage."
    if "supply chain" in title:
        return "Compromised build or runtime artifacts can disrupt service delivery and create widespread platform compromise."
    if "permission" in title or "iam" in root_cause:
        return "Privilege expansion into adjacent systems can lead to broad data tampering, service outage, or regulatory impact."
    if asset:
        return f"Compromise of {asset} can disrupt core business operations and weaken assurance over protected data and workflows."
    return "Business process disruption, increased operational risk, and potential compliance impact."
