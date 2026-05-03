from typing import Dict


def calculate_risk(threat: Dict) -> Dict[str, str | int]:
    exposure = (threat.get("exposure") or "internal").lower()
    asset_sensitivity = (threat.get("asset_sensitivity") or threat.get("data_sensitivity") or "internal").lower()
    exploit_complexity = (threat.get("exploit_complexity") or "medium").lower()
    privilege_required = (threat.get("privilege_required") or "low").lower()

    likelihood_points = 0
    likelihood_points += {"public": 3, "external": 3, "internal": 1}.get(exposure, 1)
    likelihood_points += {"low": 3, "medium": 2, "high": 1}.get(exploit_complexity, 2)
    likelihood_points += {"none": 3, "low": 2, "medium": 1, "high": 0}.get(privilege_required, 1)

    impact_points = 0
    impact_points += {
        "credentials": 3,
        "secrets": 3,
        "financial": 3,
        "phi": 3,
        "pii": 2,
        "sensitive": 2,
        "proprietary": 2,
        "internal": 1,
        "application_data": 1,
    }.get(asset_sensitivity, 1)
    impact_points += 2 if threat.get("category") in {"Information Disclosure", "Elevation of Privilege"} else 1

    if likelihood_points >= 8:
        likelihood = "High"
    elif likelihood_points >= 5:
        likelihood = "Medium"
    else:
        likelihood = "Low"

    if impact_points >= 5:
        impact = "High"
    elif impact_points >= 3:
        impact = "Medium"
    else:
        impact = "Low"

    severity_matrix = {
        ("High", "High"): "Critical",
        ("High", "Medium"): "High",
        ("High", "Low"): "Medium",
        ("Medium", "High"): "High",
        ("Medium", "Medium"): "Medium",
        ("Medium", "Low"): "Low",
        ("Low", "High"): "Medium",
        ("Low", "Medium"): "Low",
        ("Low", "Low"): "Low",
    }
    severity = severity_matrix[(likelihood, impact)]

    base_score = {
        "Critical": 88,
        "High": 68,
        "Medium": 45,
        "Low": 22,
    }[severity]
    adjustment = min(10, max(0, likelihood_points + impact_points - 5))

    return {
        "likelihood": likelihood,
        "impact": impact,
        "severity": severity,
        "risk_score": min(95, base_score + adjustment),
    }
