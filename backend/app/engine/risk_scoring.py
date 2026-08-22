from typing import Any, Dict

#: Exposure and required privilege are not independent observations. Every
#: producer derives both from the same trust level, so scoring each at full
#: weight let one architectural fact - whether the component faces the internet -
#: move likelihood by six points and decide the severity band by itself. Capping
#: their sum keeps the weaker signal meaningful, so a public component that still
#: demands high privilege scores below one that demands none, without letting the
#: same fact count twice.
REACHABILITY_CAP = 4

EXPOSURE_POINTS = {"public": 3, "external": 3, "internal": 1}
PRIVILEGE_POINTS = {"none": 3, "low": 2, "medium": 1, "high": 0}

#: Whether the control a finding concerns is missing, present, or simply not
#: stated. This replaced exploit complexity in the likelihood term. Complexity
#: read "medium" on 97% of findings because an architecture description carries
#: no evidence of how hard a weakness is to exploit, so it contributed a constant
#: and separated nothing. Control state is what this tool genuinely establishes,
#: and it is a fact about the system rather than a measure of our certainty: an
#: attacker who meets no multi-factor prompt meets no prompt regardless of how
#: well the rest of the design is documented. An unresolved control is a question,
#: and a question should not score like a confirmed gap.
CONTROL_STATE_POINTS = {"absent": 3, "unknown": 1, "present": 0}

#: Mirrors graph.SENSITIVITY_RANK. "public" has to appear here: while the rank
#: table scored it lowest, this table had no entry for it, so genuinely public
#: data fell to the default and carried the impact of internal data.
SENSITIVITY_POINTS = {
    "public": 0,
    "internal": 1,
    "application_data": 1,
    "proprietary": 2,
    "sensitive": 2,
    "pii": 2,
    "phi": 3,
    "financial": 3,
    "credentials": 3,
    "secrets": 3,
}

BASE_SCORE = {"Critical": 88, "High": 68, "Medium": 45, "Low": 22}

#: Calibrated so the bands carry a plain meaning rather than an even spread:
#: a confirmed gap on a reachable component reaches High likelihood, while an
#: unresolved question stays Medium, and ordinary internal data with no sensitive
#: classification stays below Medium impact. Before this, an unanswered STRIDE
#: question about an internal component scored Medium severity, which put it
#: alongside real confirmed weaknesses and left nothing in the Low band at all.
HIGH_LIKELIHOOD = 6
MEDIUM_LIKELIHOOD = 4
HIGH_IMPACT = 5
MEDIUM_IMPACT = 4


def score_for(severity: str, risk_factors: Dict[str, Any]) -> int:
    """The score matching a severity band, for when a floor overrides the calculation.

    Direct code and IaC evidence can hold a finding at the severity its rule
    reported. Without rebasing the score onto that band, severity and score
    disagreed: a finding held at High carried a score from the middle of the
    Medium range.
    """
    adjustment = min(10, max(0, (risk_factors.get("likelihood_points") or 0)
                             + (risk_factors.get("impact_points") or 0) - 5))
    return min(95, BASE_SCORE.get(severity, BASE_SCORE["Low"]) + adjustment)


def calculate_risk(threat: Dict[str, Any]) -> Dict[str, Any]:
    exposure = (threat.get("exposure") or "internal").lower()
    asset_sensitivity = (threat.get("asset_sensitivity") or threat.get("data_sensitivity") or "internal").lower()
    exploit_complexity = (threat.get("exploit_complexity") or "medium").lower()
    privilege_required = (threat.get("privilege_required") or "low").lower()
    control_state = (threat.get("control_state") or "unknown").lower()
    evidence_confidence = (threat.get("evidence_confidence") or threat.get("confidence") or "medium").lower()
    compensating_controls = min(2, int(threat.get("compensating_controls") or 0))
    crosses_trust_boundary = bool(threat.get("crosses_trust_boundary"))
    blast_radius = int(threat.get("blast_radius") or 0)
    architecture_size = int(threat.get("architecture_size") or 0)
    # Reaching three components meant something when blast radius counted the
    # components a finding happened to name. Measured over the graph it holds for
    # almost anything that is not a leaf, so a fixed threshold adds the same point
    # to nearly every finding and stops separating them. What matters is reaching
    # a large share of the system, which scales with the system.
    broad_reach = blast_radius >= max(3, (architecture_size + 1) // 2)

    reachability = min(
        REACHABILITY_CAP,
        EXPOSURE_POINTS.get(exposure, 1) + PRIVILEGE_POINTS.get(privilege_required, 1),
    )
    # Evidence confidence is deliberately absent. It measures how sure we are that
    # a finding is real, not how likely an attacker is to succeed, and folding it
    # in here both mixed those axes and double-counted the Confirmed/Potential
    # tier that already carries certainty. It stays in risk_factors as context.
    likelihood_points = reachability
    likelihood_points += CONTROL_STATE_POINTS.get(control_state, 1)
    likelihood_points += int(crosses_trust_boundary)
    likelihood_points -= compensating_controls

    impact_points = SENSITIVITY_POINTS.get(asset_sensitivity, 1)
    impact_points += 2 if threat.get("category") in {"Information Disclosure", "Elevation of Privilege"} else 1
    impact_points += int(broad_reach)

    if likelihood_points >= HIGH_LIKELIHOOD:
        likelihood = "High"
    elif likelihood_points >= MEDIUM_LIKELIHOOD:
        likelihood = "Medium"
    else:
        likelihood = "Low"

    if impact_points >= HIGH_IMPACT:
        impact = "High"
    elif impact_points >= MEDIUM_IMPACT:
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

    adjustment = min(10, max(0, likelihood_points + impact_points - 5))

    return {
        "likelihood": likelihood,
        "impact": impact,
        "severity": severity,
        "risk_score": min(95, BASE_SCORE[severity] + adjustment),
        "risk_factors": {
            "exposure": exposure,
            "asset_sensitivity": asset_sensitivity,
            "exploit_complexity": exploit_complexity,
            "privilege_required": privilege_required,
            "control_state": control_state,
            "evidence_confidence": evidence_confidence.title(),
            "compensating_controls": compensating_controls,
            "crosses_trust_boundary": crosses_trust_boundary,
            "blast_radius": blast_radius,
            "broad_reach": broad_reach,
            "reachability": reachability,
            "likelihood_points": likelihood_points,
            "impact_points": impact_points,
        },
    }
