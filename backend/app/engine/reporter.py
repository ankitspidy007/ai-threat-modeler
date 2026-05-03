from datetime import datetime
from typing import List

from ..models import AnalysisResult, Threat


class ReportGenerator:
    @staticmethod
    def generate_markdown(result: AnalysisResult) -> str:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines: List[str] = [
            f"# Threat Model Report: {result.project_name}",
            f"Generated: {now}",
            "",
        ]

        lines.extend(ReportGenerator._executive_summary(result))
        lines.extend(ReportGenerator._architecture_model(result))
        lines.extend(ReportGenerator._assets_section(result))
        lines.extend(ReportGenerator._data_flows_section(result))
        lines.extend(ReportGenerator._threat_analysis(result))
        lines.extend(ReportGenerator._risk_table(result))
        lines.extend(ReportGenerator._mitigations(result))
        lines.extend(ReportGenerator._missing_information(result))
        return "\n".join(lines)

    @staticmethod
    def _executive_summary(result: AnalysisResult) -> List[str]:
        confirmed = len([threat for threat in result.threats if threat.tier == "Confirmed"])
        critical = len([threat for threat in result.threats if threat.severity == "Critical"])
        high = len([threat for threat in result.threats if threat.severity == "High"])
        return [
            "## 1. Executive Summary",
            result.summary,
            f"- Security score: {result.score}/100",
            f"- Confirmed threats: {confirmed}",
            f"- Critical threats: {critical}",
            f"- High threats: {high}",
            "",
        ]

    @staticmethod
    def _architecture_model(result: AnalysisResult) -> List[str]:
        lines = ["## 2. Architecture Overview", "### Components"]
        for component in result.architecture.components:
            lines.append(f"- {component.name} ({component.type}) trust={component.trust_level}")
        lines.append("")
        lines.append("### Trust Boundaries")
        for boundary in result.architecture.trust_boundaries:
            lines.append(f"- {boundary.name} ({boundary.boundary_type}): {', '.join(boundary.components)}")
        lines.append("")
        return lines

    @staticmethod
    def _assets_section(result: AnalysisResult) -> List[str]:
        lines = ["## 3. Assets"]
        for asset in result.architecture.assets:
            lines.append(f"- {asset.name}: sensitivity={asset.sensitivity}, location={asset.location}")
        lines.append("")
        return lines

    @staticmethod
    def _data_flows_section(result: AnalysisResult) -> List[str]:
        lines = ["## 4. Data Flows"]
        for flow in result.architecture.flows:
            suffix = "assumed" if flow.assumed else "explicit"
            lines.append(f"- {flow.source_id} -> {flow.target_id} [{flow.protocol}] data={flow.data_type} ({suffix})")
        lines.append("")
        return lines

    @staticmethod
    def _threat_analysis(result: AnalysisResult) -> List[str]:
        lines = ["## 5. Deduplicated Threats"]
        for threat in sorted(result.threats, key=lambda item: item.risk_score or 0, reverse=True):
            lines.extend(ReportGenerator._format_threat(threat))
        lines.append("")
        return lines

    @staticmethod
    def _format_threat(threat: Threat) -> List[str]:
        lines = [
            f"### {threat.title}",
            f"- STRIDE: {threat.stride_category or threat.category}",
            f"- Severity: {threat.severity}",
            f"- Likelihood: {threat.likelihood}",
            f"- Impact: {threat.impact}",
            f"- Components: {', '.join(threat.affected_components or ([threat.component] if threat.component else [])) or 'n/a'}",
            f"- Data flows: {', '.join(threat.affected_data_flows or ([threat.data_flow] if threat.data_flow else [])) or 'n/a'}",
            f"- Assets: {', '.join(threat.affected_assets or ([threat.asset] if threat.asset else [])) or 'n/a'}",
            f"- Root cause: {threat.root_cause or 'n/a'}",
            f"- Attack scenario: {threat.attack_scenario or threat.realistic_attack_scenario or threat.description}",
            f"- Business impact: {threat.business_impact or 'n/a'}",
            f"- Mappings: CWE={', '.join(threat.cwe or []) or 'n/a'} | MITRE={', '.join(threat.mitre_attack or []) or 'n/a'} | OWASP={', '.join(threat.owasp_top_10 or []) or 'n/a'}",
        ]
        if threat.attack_path:
            lines.append("- Attack path:")
            for step in threat.attack_path.get("steps", []):
                lines.append(f"  - {step}")
        return lines

    @staticmethod
    def _risk_table(result: AnalysisResult) -> List[str]:
        lines = [
            "## 6. Risk Table",
            "| Threat | Exposure | Data Sensitivity | Exploit Complexity | Privilege Required | Likelihood | Impact | Severity |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for threat in sorted(result.threats, key=lambda item: item.risk_score or 0, reverse=True):
            lines.append(
                f"| {threat.id} | {threat.exposure or 'n/a'} | {threat.data_sensitivity or 'n/a'} | "
                f"{threat.exploit_complexity or 'n/a'} | {threat.privilege_required or 'n/a'} | "
                f"{threat.likelihood} | {threat.impact} | {threat.severity} |"
            )
        lines.append("")
        return lines

    @staticmethod
    def _mitigations(result: AnalysisResult) -> List[str]:
        lines = ["## 7. Mitigations"]
        for threat in sorted(result.threats, key=lambda item: item.risk_score or 0, reverse=True):
            lines.append(f"### {threat.title}")
            lines.append(f"- Specific control: {threat.specific_control or threat.mitigation}")
            lines.append(f"- Implementation detail: {threat.implementation_detail or threat.mitigation}")
            if threat.optional_config_example:
                lines.append(f"- Example: {threat.optional_config_example}")
        lines.append("")
        return lines

    @staticmethod
    def _missing_information(result: AnalysisResult) -> List[str]:
        lines = ["## 8. Missing Information"]
        for item in (result.coverage or {}).get("missing_information", []):
            lines.append(f"- {item.get('message', 'Missing context identified.')}")
        assumptions = (result.coverage or {}).get("assumptions", [])
        for assumption in assumptions:
            lines.append(f"- Assumption: {assumption.get('message', 'Context was inferred.')}")
        lines.append("")
        return lines
