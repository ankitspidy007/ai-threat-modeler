from app.engine.analyzer import ThreatAnalyzer
from app.engine.iac_parser import IaCParser


def test_iac_analysis_emits_a_technical_threat_model_contract():
    terraform = '''
resource "aws_db_instance" "primary" {
  publicly_accessible = true
  storage_encrypted = false
}
'''
    architecture = IaCParser().parse(terraform, format_hint="terraform")
    result = ThreatAnalyzer().analyze(architecture, "Technical Output")

    assert set(result.system_model) >= {
        "components", "assets", "data_flows", "trust_boundaries",
        "public_entry_points", "identities", "cloud_resources", "boundary_crossings",
    }
    # v3 caps exposure and required privilege together, drops evidence confidence
    # from likelihood and scores control state instead of exploit complexity, so
    # reports from either side of that change are not comparable by severity alone.
    assert result.risk_methodology["version"] == "technical-v3"
    assert result.finding_groups["iac"]

    finding = result.finding_groups["iac"][0]
    assert finding.tier == "Confirmed"
    assert finding.evidence_details[0]["source_type"] == "iac"
    assert finding.risk_factors["evidence_confidence"] == "High"
    assert finding.preconditions

    path = result.attack_chains["paths"][0]
    assert path["related_threat_id"] == finding.id
    assert path["evidence"]

    assert "## 5. Technical Findings" in result.report_markdown
    assert "## 6. Evidence-Backed Attack Paths" in result.report_markdown
    assert "## 7. Risk Calculation" in result.report_markdown
