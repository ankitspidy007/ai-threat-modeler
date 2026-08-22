"""What the risk model is allowed to conclude, and from what.

These cover the properties that were quietly violated rather than the arithmetic:
one architectural fact counting once, a recalculation being free to fall, and an
unresolved question ranking below a confirmed gap.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.engine.risk_scoring import calculate_risk, score_for  # noqa: E402
from app.engine.analyzer import ThreatAnalyzer  # noqa: E402
from app.models import Threat  # noqa: E402


def _risk(**overrides):
    base = {
        "category": "Information Disclosure",
        "exposure": "internal",
        "data_sensitivity": "internal",
        "control_state": "unknown",
        "architecture_size": 6,
    }
    base.update(overrides)
    return calculate_risk(base)


def _threat(**overrides):
    base = {
        "id": "T-1",
        "category": "Information Disclosure",
        "title": "t",
        "description": "d",
        "severity": "Medium",
        "mitigation": "m",
    }
    base.update(overrides)
    return Threat(**base)


class TestExposureCountsOnce:
    def test_privilege_cannot_stack_freely_onto_exposure(self):
        # Both are derived from the same trust level by every producer, so their
        # combined contribution is capped rather than summed.
        public_open = _risk(exposure="public", privilege_required="none")
        assert public_open["risk_factors"]["reachability"] == 4

    def test_a_public_component_still_outranks_an_internal_one(self):
        public = _risk(exposure="public", privilege_required="none")
        internal = _risk(exposure="internal", privilege_required="low")
        assert public["risk_factors"]["likelihood_points"] > internal["risk_factors"]["likelihood_points"]

    def test_demanding_high_privilege_lowers_a_public_finding(self):
        open_access = _risk(exposure="public", privilege_required="none")
        needs_admin = _risk(exposure="public", privilege_required="high")
        assert needs_admin["risk_factors"]["likelihood_points"] < open_access["risk_factors"]["likelihood_points"]


class TestControlStateDrivesLikelihood:
    def test_a_confirmed_gap_outranks_an_open_question(self):
        confirmed = _risk(control_state="absent")
        question = _risk(control_state="unknown")
        assert confirmed["risk_factors"]["likelihood_points"] > question["risk_factors"]["likelihood_points"]

    def test_a_control_known_present_ranks_lowest(self):
        present = _risk(control_state="present")
        question = _risk(control_state="unknown")
        assert present["risk_factors"]["likelihood_points"] < question["risk_factors"]["likelihood_points"]

    def test_an_unresolved_question_on_ordinary_data_is_not_high(self):
        # Half of every report was High before this, which left the band meaning
        # nothing. An unanswered question about internal data is not a High risk.
        assert _risk(control_state="unknown")["severity"] in {"Low", "Medium"}


class TestEvidenceConfidenceStaysOutOfLikelihood:
    def test_confidence_does_not_move_the_score(self):
        sure = _risk(evidence_confidence="high")
        unsure = _risk(evidence_confidence="low")
        assert sure["risk_score"] == unsure["risk_score"]

    def test_confidence_is_still_reported(self):
        assert _risk(evidence_confidence="high")["risk_factors"]["evidence_confidence"] == "High"


class TestSensitivityIsGraded:
    def test_public_data_is_not_treated_as_internal(self):
        # graph.SENSITIVITY_RANK ranks public below internal, but this table had no
        # entry for it, so public data fell to the default and scored as internal.
        assert _risk(data_sensitivity="public")["risk_factors"]["impact_points"] < \
            _risk(data_sensitivity="internal")["risk_factors"]["impact_points"]

    def test_regulated_data_outranks_ordinary_data(self):
        assert _risk(data_sensitivity="phi")["risk_factors"]["impact_points"] > \
            _risk(data_sensitivity="internal")["risk_factors"]["impact_points"]


class TestCompensatingControls:
    def test_controls_lower_the_result(self):
        bare = _risk(exposure="public", privilege_required="none", control_state="absent")
        defended = _risk(exposure="public", privilege_required="none", control_state="absent",
                         compensating_controls=2)
        assert defended["risk_score"] < bare["risk_score"]


class TestRecalculationIsNotARatchet:
    def test_a_second_pass_may_lower_a_computed_severity(self):
        # The model runs once per refinement of the architecture. Keeping the
        # greater of old and new made every pass a ratchet, so a control found
        # later could never bring a severity back down.
        analyzer = ThreatAnalyzer()
        threat = _threat(severity="Critical", risk_score=95, severity_source="model")
        analyzer._apply_risk_model([threat], None)
        first, first_score = threat.severity, threat.risk_score
        analyzer._apply_risk_model([threat], None)
        assert (threat.severity, threat.risk_score) == (first, first_score)
        assert threat.severity != "Critical"

    def test_repeated_passes_are_stable(self):
        analyzer = ThreatAnalyzer()
        threat = _threat(severity_source="model")
        seen = set()
        for _ in range(4):
            analyzer._apply_risk_model([threat], None)
            seen.add((threat.severity, threat.risk_score))
        assert len(seen) == 1


class TestAuthoredSeverityIsAFloor:
    def test_a_curated_rule_severity_is_not_talked_down(self):
        # A formula cannot rederive that some named weaknesses are critical, so an
        # authored severity holds.
        analyzer = ThreatAnalyzer()
        threat = _threat(severity="Critical", severity_source="rule")
        analyzer._apply_risk_model([threat], None)
        assert threat.severity == "Critical"

    def test_a_computed_severity_carries_no_such_authority(self):
        analyzer = ThreatAnalyzer()
        threat = _threat(severity="Critical", severity_source="model")
        analyzer._apply_risk_model([threat], None)
        assert threat.severity != "Critical"

    def test_a_floored_severity_gets_a_matching_score(self):
        # Severity and score disagreed here: a finding held at Critical kept a
        # score from the middle of the Medium range.
        analyzer = ThreatAnalyzer()
        threat = _threat(severity="Critical", severity_source="rule")
        analyzer._apply_risk_model([threat], None)
        assert threat.risk_score >= score_for("Critical", {"likelihood_points": 0, "impact_points": 0})

    def test_the_original_claim_survives_recalculation(self):
        analyzer = ThreatAnalyzer()
        threat = _threat(severity="High", severity_source="rule")
        analyzer._apply_risk_model([threat], None)
        analyzer._apply_risk_model([threat], None)
        assert threat.reported_severity == "High"
        assert threat.severity == "High"


class TestControlStateResolution:
    def test_a_stated_absence_is_read_from_the_component(self):
        component = type("C", (), {"properties": {"control_assertions": {"encryption_at_rest": "absent"}}})()
        threat = _threat(explanation={"matched_controls": ["encryption_at_rest"]})
        assert ThreatAnalyzer._control_state(threat, component) == "absent"

    def test_a_present_control_is_recognised(self):
        component = type("C", (), {"properties": {"control_assertions": {"encryption_at_rest": "present"}}})()
        threat = _threat(explanation={"matched_controls": ["encryption_at_rest"]})
        assert ThreatAnalyzer._control_state(threat, component) == "present"

    def test_an_unnamed_control_on_a_potential_finding_is_unknown(self):
        threat = _threat(tier="Potential")
        assert ThreatAnalyzer._control_state(threat, None) == "unknown"

    def test_a_confirmed_finding_establishes_the_gap(self):
        # Tier says the weakness exists; confidence grades how good the evidence
        # is. Only the former belongs in likelihood.
        threat = _threat(tier="Confirmed")
        assert ThreatAnalyzer._control_state(threat, None) == "absent"
