from datetime import datetime
from typing import List, Dict, Any
from ..models import AnalysisResult, Threat, SystemArchitecture
import json
import os
from collections import Counter

class ReportGenerator:
    """Enhanced report generator with comprehensive threat modeling sections."""
    
    # Load framework and compliance mappings
    @staticmethod
    def _load_json_data(filename: str) -> Dict:
        """Load JSON data file from app/data directory."""
        try:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            file_path = os.path.join(base_dir, 'data', filename)
            with open(file_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load {filename}: {e}")
            return {}
    
    @staticmethod
    def generate_markdown(result: AnalysisResult) -> str:
        """
        Generates a comprehensive, enterprise-grade markdown report with 15 sections.
        Maintains backward compatibility while adding enhanced sections.
        """
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Separate threats by tier
        confirmed = [t for t in result.threats if t.tier == "Confirmed"]
        potential = [t for t in result.threats if t.tier == "Potential"]
        
        # Load reference data
        framework_data = ReportGenerator._load_json_data('framework_mappings.json')
        compliance_data = ReportGenerator._load_json_data('compliance_mappings.json')
        stride_colors = ReportGenerator._load_json_data('stride_colors.json')
        
        md = []
        
        # ========================================
        # HEADER
        # ========================================
        md.append(f"# Threat Model Report: {result.project_name}")
        md.append(f"**Generated:** {now}")
        md.append(f"**Report Version:** 2.0")
        md.append(f"**Classification:** Internal Use")
        md.append("---\n")
        
        # ========================================
        # SECTION 1: EXECUTIVE SUMMARY
        # ========================================
        md.extend(ReportGenerator._generate_executive_summary(result, confirmed, potential))
        
        # ========================================
        # SECTION 2: SCOPE AND METHODOLOGY
        # ========================================
        md.extend(ReportGenerator._generate_scope_and_methodology(result))
        
        # ========================================
        # SECTION 3: ARCHITECTURE OVERVIEW
        # ========================================
        md.extend(ReportGenerator._generate_architecture_overview(result))
        
        # ========================================
        # SECTION 4: ASSET INVENTORY
        # ========================================
        md.extend(ReportGenerator._generate_asset_inventory(result))
        
        # ========================================
        # SECTION 5: THREAT ANALYSIS (CONFIRMED)
        # ========================================
        md.append("## 5. Threat Analysis - Confirmed Risks")
        if not confirmed:
            md.append("*No confirmed risks detected.*\n")
        else:
            md.append(f"The following **{len(confirmed)} confirmed risks** are backed by verified evidence:\n")
            for t in confirmed:
                md.append(ReportGenerator._format_enhanced_threat(t, framework_data))
        
        # ========================================
        # SECTION 6: THREAT ANALYSIS (POTENTIAL)
        # ========================================
        md.append("## 6. Potential Risks (Assumption-Based)")
        if not potential:
            md.append("*No potential risks detected.*\n")
        else:
            md.append(f"The following **{len(potential)} potential risks** are based on missing or unclear information:\n")
            for t in potential:
                md.append(ReportGenerator._format_enhanced_threat(t, framework_data))
        
        # ========================================
        
        # ========================================
        # SECTION 8: RISK HEAT MAP
        # ========================================
        md.extend(ReportGenerator._generate_risk_matrix(result.threats))
        
        # ========================================
        # SECTION 9: COMPLIANCE MAPPING
        # ========================================
        md.extend(ReportGenerator._generate_compliance_mapping(result.threats, compliance_data))
        
        # ========================================
        # SECTION 10: METRICS AND STATISTICS
        # ========================================
        md.extend(ReportGenerator._generate_metrics(result))
        
        # ========================================
        # SECTION 11: RISK TREATMENT DECISIONS
        # ========================================
        md.extend(ReportGenerator._generate_risk_treatment(result.threats))
        
        # ========================================
        # SECTION 12: TESTING AND VALIDATION PLAN
        # ========================================
        md.extend(ReportGenerator._generate_testing_plan(result.threats))
        
        # ========================================
        # SECTION 13: APPENDICES
        # ========================================
        md.extend(ReportGenerator._generate_appendices(stride_colors))
        
        # ========================================
        # FOOTER
        # ========================================
        md.append("\n---\n")
        md.append("*Generated by AI Threat Modeler v2.0*")
        md.append(f"*Next Review Date: {ReportGenerator._get_next_review_date()}*")
        
        return "\n".join(md)
    
    @staticmethod
    def _generate_executive_summary(result: AnalysisResult, confirmed: List[Threat], potential: List[Threat]) -> List[str]:
        """Generate executive summary section."""
        md = []
        md.append("## 1. Executive Summary\n")
        
        # Count by severity
        critical = len([t for t in confirmed if t.severity == "Critical"])
        high = len([t for t in confirmed if t.severity == "High"])
        medium = len([t for t in confirmed if t.severity == "Medium"])
        low = len([t for t in confirmed if t.severity == "Low"])
        
        # Overall assessment
        md.append("### Security Posture Assessment\n")
        
        if result.score >= 80:
            posture = "**STRONG** ✅"
            summary = "The system demonstrates a strong security posture with minimal critical risks."
        elif result.score >= 60:
            posture = "**MODERATE** ⚠️"
            summary = "The system has a moderate security posture with some areas requiring attention."
        elif result.score >= 40:
            posture = "**WEAK** ⚠️"
            summary = "The system has significant security gaps that require immediate remediation."
        else:
            posture = "**CRITICAL** 🔴"
            summary = "The system has critical security vulnerabilities requiring urgent action."
        
        md.append(f"**Overall Rating:** {posture}")
        md.append(f"**Security Score:** {result.score}/100")
        md.append(f"\n{summary}\n")
        
        # Risk summary
        md.append("### Risk Summary\n")
        md.append(f"- 🔴 **Critical:** {critical}")
        md.append(f"- 🟠 **High:** {high}")
        md.append(f"- 🟡 **Medium:** {medium}")
        md.append(f"- 🟢 **Low:** {low}")
        md.append(f"- 📊 **Total Confirmed:** {len(confirmed)}")
        md.append(f"- ⚠️ **Potential Risks:** {len(potential)}\n")
        
        # Top threats
        if confirmed:
            md.append("### Top Critical Findings\n")
            top_threats = sorted(confirmed, key=lambda t: (
                {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}.get(t.severity, 0),
                t.risk_score
            ), reverse=True)[:5]
            
            for i, threat in enumerate(top_threats, 1):
                md.append(f"{i}. **{threat.title}** ({threat.severity}) - {threat.category}")
        
        # Immediate actions
        md.append("\n### Recommended Immediate Actions\n")
        if critical > 0:
            md.append(f"1. **Address {critical} Critical threat(s)** - These pose immediate risk to the system")
        if high > 0:
            md.append(f"2. **Remediate {high} High severity threat(s)** - Should be addressed within 30 days")
        md.append("3. **Review and implement recommended mitigations** - See Section 7")
        md.append("4. **Establish continuous monitoring** - Implement detection for identified threats")
        md.append("5. **Schedule follow-up assessment** - Re-assess after implementing mitigations\n")
        
        return md
    
    @staticmethod
    def _generate_scope_and_methodology(result: AnalysisResult) -> List[str]:
        """Generate scope and methodology section."""
        md = []
        md.append("## 2. Scope and Methodology\n")
        
        md.append("### System Under Analysis\n")
        md.append(f"**Project Name:** {result.project_name}")
        md.append(f"**Components in Scope:** {len(result.architecture.components)}")
        md.append(f"**Data Flows Analyzed:** {len(result.architecture.flows)}\n")
        
        # Detect architecture type
        component_types = [c.type for c in result.architecture.components]
        if 'Serverless' in component_types or 'Lambda' in str(component_types):
            arch_type = "Serverless Architecture"
        elif 'Service' in component_types or 'Microservice' in str(component_types):
            arch_type = "Microservices Architecture"
        elif 'Container' in str(component_types):
            arch_type = "Containerized Architecture"
        else:
            arch_type = "Traditional Architecture"
        
        md.append(f"**Architecture Type:** {arch_type}\n")
        
        md.append("### Threat Modeling Methodology\n")
        md.append("**Primary Framework:** STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)")
        md.append("**Analysis Approach:** Component-based and data flow analysis")
        md.append("**Confidence Levels:** High (verified evidence), Medium (inferred), Low (assumed)\n")
        
        md.append("### Assumptions and Constraints\n")
        md.append("- Analysis based on architecture description provided")
        md.append("- Security controls assumed absent unless explicitly mentioned")
        md.append("- Network boundaries and trust zones inferred from component types")
        md.append("- Compliance requirements based on common industry standards\n")
        
        return md
    
    @staticmethod
    def _generate_architecture_overview(result: AnalysisResult) -> List[str]:
        """Generate architecture overview section."""
        md = []
        md.append("## 3. Architecture Overview\n")
        
        md.append("### System Components\n")
        for comp in result.architecture.components:
            md.append(f"- **{comp.name}** ({comp.type})")
            if comp.description:
                md.append(f"  - {comp.description}")
        
        md.append("\n### Data Flows\n")
        if result.architecture.flows:
            for flow in result.architecture.flows:
                protocol = f" [{flow.protocol}]" if flow.protocol else ""
                md.append(f"- {flow.source_id} → {flow.target_id}{protocol}")
        else:
            md.append("*No explicit data flows defined - inferred from component relationships*\n")
        
        # Trust boundaries
        md.append("### Trust Boundaries\n")
        md.append("- **Internet/Public Zone** (Untrusted): Web clients, public-facing APIs")
        md.append("- **DMZ** (Semi-trusted): API gateways, load balancers")
        md.append("- **Internal Network** (Trusted): Databases, internal services")
        md.append("- **Sensitive Data Zone** (Highly trusted): Credential stores, encryption keys\n")
        
        # Architecture diagram
        if result.mermaid_diagram:
            md.append("### Architecture Diagram\n")
            md.append("```mermaid")
            md.append(result.mermaid_diagram)
            md.append("```\n")
        
        return md
    
    @staticmethod
    def _generate_asset_inventory(result: AnalysisResult) -> List[str]:
        """Generate asset inventory section."""
        md = []
        md.append("## 4. Asset Inventory\n")
        
        md.append("| Asset Name | Type | Criticality | Data Classification | Dependencies |")
        md.append("|------------|------|-------------|---------------------|--------------|")
        
        for comp in result.architecture.components:
            # Determine criticality based on type
            if comp.type in ['Database', 'Secrets Manager']:
                criticality = "Critical"
                classification = "Confidential"
            elif comp.type in ['API', 'Service']:
                criticality = "High"
                classification = "Internal"
            elif comp.type in ['WebClient', 'CDN']:
                criticality = "Medium"
                classification = "Public"
            else:
                criticality = "Medium"
                classification = "Internal"
            
            # Find dependencies
            deps = [f.target_id for f in result.architecture.flows if f.source_id == comp.id]
            dep_str = ", ".join(deps[:3]) if deps else "None"
            if len(deps) > 3:
                dep_str += f" (+{len(deps)-3} more)"
            
            md.append(f"| {comp.name} | {comp.type} | {criticality} | {classification} | {dep_str} |")
        
        md.append("")
        return md
    
    @staticmethod
    def _format_enhanced_threat(t: Threat, framework_data: Dict) -> str:
        """Format a single threat with enhanced details including MITRE ATT&CK, CWE, etc."""
        lines = []
        
        # Header with severity icon
        severity_icons = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}
        icon = severity_icons.get(t.severity, "⚪")
        
        stride_label = f" ({t.stride_category})" if t.stride_category and t.stride_category != t.category else ""
        lines.append(f"### {icon} [{t.severity.upper()}] {t.title}{stride_label}")
        lines.append(f"**ID:** {t.id} | **Category:** {t.category} | **Confidence:** {t.confidence}")
        lines.append("")
        
        # Description
        lines.append(f"**Description:** {t.description}\n")
        
        # Attack scenario (if we can infer it)
        lines.append("**Attack Scenario:**")
        lines.append(f"1. Attacker identifies vulnerable component: {', '.join(t.affected_components) if t.affected_components else 'System component'}")
        lines.append(f"2. Exploits weakness described above")
        lines.append(f"3. Potential impact: {t.severity} severity to system security\n")
        
        # Impact analysis
        lines.append("**Impact Analysis:**")
        lines.append(f"- **Severity:** {t.severity}")
        lines.append(f"- **Likelihood:** {t.likelihood}")
        lines.append(f"- **Risk Score:** {t.risk_score}/12")
        
        # CIA Triad impact
        if "Information Disclosure" in t.category or "Information Disclosure" in str(t.stride_category):
            lines.append(f"- **Confidentiality:** HIGH")
        if "Tampering" in t.category or "Tampering" in str(t.stride_category):
            lines.append(f"- **Integrity:** HIGH")
        if "Denial of Service" in t.category or "Denial of Service" in str(t.stride_category):
            lines.append(f"- **Availability:** HIGH")
        lines.append("")
        
        # Affected components
        if t.affected_components:
            lines.append(f"**Affected Components:** {', '.join(t.affected_components)}")
        if t.affected_data_flows:
            lines.append(f"**Affected Data Flows:** {', '.join(t.affected_data_flows)}")
        lines.append("")
        
        # Framework references (MITRE ATT&CK, CWE, etc.)
        threat_mappings = framework_data.get('threat_mappings', {})
        
        # Try to find matching framework data
        mapping_key = None
        if 'SQL' in t.id or 'SQL' in t.title:
            mapping_key = 'SQL_INJECTION'
        elif 'Access Control' in t.title or 'Access' in t.title:
            mapping_key = 'BROKEN_ACCESS_CONTROL'
        elif 'Crypto' in t.title or 'Encryption' in t.title:
            mapping_key = 'CRYPTOGRAPHIC_FAILURES'
        elif 'SSRF' in t.title or 'SSRF' in t.id:
            mapping_key = 'SSRF'
        elif 'JWT' in t.title or 'JWT' in t.id:
            mapping_key = 'JWT_ISSUES'
        elif 'NoSQL' in t.title or 'MongoDB' in str(t.affected_components):
            mapping_key = 'NOSQL_INJECTION'
        elif 'Container' in t.title or 'Container' in str(t.affected_components):
            mapping_key = 'CONTAINER_ESCAPE'
        elif 'Credential' in t.title or 'Key' in t.title:
            mapping_key = 'EXPOSED_CREDENTIALS'
        
        if mapping_key and mapping_key in threat_mappings:
            mapping = threat_mappings[mapping_key]
            lines.append("**Framework References:**")
            
            if 'mitre_attack' in mapping:
                mitre_ids = ', '.join(mapping['mitre_attack'])
                lines.append(f"- **MITRE ATT&CK:** {mitre_ids}")
            
            if 'cwe' in mapping:
                cwe_ids = ', '.join(mapping['cwe'])
                lines.append(f"- **CWE:** {cwe_ids}")
            
            if 'capec' in mapping:
                capec_ids = ', '.join(mapping['capec'])
                lines.append(f"- **CAPEC:** {capec_ids}")
            
            if 'owasp' in mapping:
                owasp_ids = ', '.join(mapping['owasp'])
                lines.append(f"- **OWASP:** {owasp_ids}")
            
            # Real-world examples
            if 'real_world_examples' in mapping:
                lines.append("\n**Real-World Examples:**")
                for example in mapping['real_world_examples']:
                    lines.append(f"- **{example['incident']}** ({example['year']}): {example['impact']}")
            
            lines.append("")
        
        # Evidence
        if t.evidence:
            lines.append("**Evidence:**")
            for ev in t.evidence:
                lines.append(f"- {ev}")
            lines.append("")
        
        # Current controls
        lines.append("**Current Security Controls:** None explicitly defined")
        lines.append("**Control Effectiveness:** N/A")
        lines.append(f"**Residual Risk:** {t.severity}\n")
        
        # Mitigation
        lines.append(f"**Recommended Mitigation:** {t.mitigation}")
        lines.append("")
        
        return "\n".join(lines)
    
    @staticmethod
    def _generate_recommendations(threats: List[Threat]) -> List[str]:
        """Generate recommendations and mitigations section."""
        md = []
        md.append("## 7. Recommendations & Mitigations\n")
        
        md.append("### Prioritized Mitigation Plan\n")
        
        # Sort by severity and risk score
        sorted_threats = sorted(threats, key=lambda t: (
            {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}.get(t.severity, 0),
            t.risk_score
        ), reverse=True)
        
        priority_map = {"Critical": "P0", "High": "P1", "Medium": "P2", "Low": "P3"}
        effort_map = {"Critical": "High", "High": "Medium", "Medium": "Medium", "Low": "Low"}
        timeline_map = {"Critical": "Immediate (0-7 days)", "High": "Short-term (1-30 days)", 
                       "Medium": "Medium-term (1-3 months)", "Low": "Long-term (3-6 months)"}
        
        md.append("| Priority | Threat ID | Mitigation | Effort | Timeline | Control Type |")
        md.append("|----------|-----------|------------|--------|----------|--------------|")
        
        for threat in sorted_threats[:15]:  # Top 15 threats
            priority = priority_map.get(threat.severity, "P3")
            effort = effort_map.get(threat.severity, "Medium")
            timeline = timeline_map.get(threat.severity, "Medium-term")
            control_type = "Preventive"
            
            # Truncate mitigation for table
            mitigation_short = threat.mitigation[:50] + "..." if len(threat.mitigation) > 50 else threat.mitigation
            
            md.append(f"| {priority} | {threat.id} | {mitigation_short} | {effort} | {timeline} | {control_type} |")
        
        md.append("\n### Implementation Guidance\n")
        md.append("**P0 (Critical):** Immediate action required. Allocate resources and implement within 7 days.")
        md.append("**P1 (High):** High priority. Should be addressed within 30 days.")
        md.append("**P2 (Medium):** Medium priority. Plan for implementation within 1-3 months.")
        md.append("**P3 (Low):** Low priority. Can be addressed in regular security improvements cycle.\n")
        
        return md
    
    @staticmethod
    def _generate_risk_matrix(threats: List[Threat]) -> List[str]:
        """Generate risk heat map / risk matrix."""
        md = []
        md.append("## 8. Risk Heat Map\n")
        
        md.append("### Risk Matrix (Likelihood vs Impact)\n")
        md.append("```")
        md.append("         │ Low    │ Medium │ High   │ Critical")
        md.append("─────────┼────────┼────────┼────────┼─────────")
        
        # Count threats in each cell
        matrix = {
            'High': {'Low': [], 'Medium': [], 'High': [], 'Critical': []},
            'Medium': {'Low': [], 'Medium': [], 'High': [], 'Critical': []},
            'Low': {'Low': [], 'Medium': [], 'High': [], 'Critical': []}
        }
        
        for threat in threats:
            likelihood = threat.likelihood if threat.likelihood in ['High', 'Medium', 'Low'] else 'Medium'
            impact = threat.severity if threat.severity in ['Critical', 'High', 'Medium', 'Low'] else 'Medium'
            if likelihood in matrix and impact in matrix[likelihood]:
                matrix[likelihood][impact].append(threat.id)
        
        for likelihood in ['High', 'Medium', 'Low']:
            row = f" {likelihood:8} │"
            for impact in ['Low', 'Medium', 'High', 'Critical']:
                count = len(matrix[likelihood][impact])
                cell = f" {count:2}    " if count > 0 else "       "
                row += f"{cell}│"
            md.append(row)
        
        md.append("```\n")
        
        # Risk distribution
        critical_count = len([t for t in threats if t.severity == "Critical"])
        high_count = len([t for t in threats if t.severity == "High"])
        medium_count = len([t for t in threats if t.severity == "Medium"])
        low_count = len([t for t in threats if t.severity == "Low"])
        
        md.append("### Risk Distribution\n")
        md.append(f"- 🔴 **Critical Risk:** {critical_count} threats")
        md.append(f"- 🟠 **High Risk:** {high_count} threats")
        md.append(f"- 🟡 **Medium Risk:** {medium_count} threats")
        md.append(f"- 🟢 **Low Risk:** {low_count} threats\n")
        
        return md
    
    @staticmethod
    def _generate_compliance_mapping(threats: List[Threat], compliance_data: Dict) -> List[str]:
        """Generate compliance framework mapping."""
        md = []
        md.append("## 9. Compliance Mapping\n")
        
        md.append("### Applicable Compliance Frameworks\n")
        
        # PCI-DSS
        md.append("#### PCI-DSS v4.0\n")
        md.append("| Requirement | Description | Relevant Threats |")
        md.append("|-------------|-------------|------------------|")
        
        pci_reqs = compliance_data.get('PCI_DSS', {}).get('requirements', {})
        for req_id, req_data in list(pci_reqs.items())[:5]:
            threat_types = req_data.get('threats', [])
            relevant = len([t for t in threats if any(tt in t.id or tt in t.title for tt in threat_types)])
            md.append(f"| {req_id} | {req_data.get('title', '')} | {relevant} |")
        
        # GDPR
        md.append("\n#### GDPR\n")
        md.append("| Article | Description | Relevant Threats |")
        md.append("|---------|-------------|------------------|")
        
        gdpr_articles = compliance_data.get('GDPR', {}).get('articles', {})
        for art_id, art_data in list(gdpr_articles.items())[:3]:
            threat_types = art_data.get('threats', [])
            relevant = len([t for t in threats if any(tt in t.id or tt in t.title for tt in threat_types)])
            md.append(f"| {art_id} | {art_data.get('title', '')} | {relevant} |")
        
        # SOC 2
        md.append("\n#### SOC 2 Trust Service Criteria\n")
        md.append("| Criteria | Description | Relevant Threats |")
        md.append("|----------|-------------|------------------|")
        
        soc2_criteria = compliance_data.get('SOC2', {}).get('trust_criteria', {})
        for crit_id, crit_data in list(soc2_criteria.items())[:4]:
            threat_types = crit_data.get('threats', [])
            relevant = len([t for t in threats if any(tt in t.id or tt in t.title for tt in threat_types)])
            md.append(f"| {crit_id} | {crit_data.get('title', '')} | {relevant} |")
        
        md.append("")
        return md
    
    @staticmethod
    def _generate_metrics(result: AnalysisResult) -> List[str]:
        """Generate metrics and statistics section."""
        md = []
        md.append("## 10. Metrics and Statistics\n")
        
        threats = result.threats
        
        # Threats by STRIDE category
        stride_counts = Counter([t.stride_category or t.category for t in threats])
        md.append("### Threats by STRIDE Category\n")
        for category, count in stride_counts.most_common():
            percentage = (count / len(threats) * 100) if threats else 0
            bar = "█" * int(percentage / 5)
            md.append(f"- **{category}:** {count} ({percentage:.1f}%) {bar}")
        
        # Threats by severity
        severity_counts = Counter([t.severity for t in threats])
        md.append("\n### Threats by Severity\n")
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            count = severity_counts.get(severity, 0)
            percentage = (count / len(threats) * 100) if threats else 0
            bar = "█" * int(percentage / 5)
            icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(severity, "⚪")
            md.append(f"- {icon} **{severity}:** {count} ({percentage:.1f}%) {bar}")
        
        # Threats by component
        component_counts = Counter()
        for t in threats:
            for comp in t.affected_components:
                component_counts[comp] += 1
        
        md.append("\n### Threats by Component\n")
        for component, count in component_counts.most_common(10):
            md.append(f"- **{component}:** {count} threats")
        
        # Summary statistics
        md.append("\n### Summary Statistics\n")
        md.append(f"- **Total Threats Identified:** {len(threats)}")
        md.append(f"- **Confirmed Threats:** {len([t for t in threats if t.tier == 'Confirmed'])}")
        md.append(f"- **Potential Threats:** {len([t for t in threats if t.tier == 'Potential'])}")
        md.append(f"- **Average Risk Score:** {sum(t.risk_score for t in threats) / len(threats):.1f}/12" if threats else "- **Average Risk Score:** N/A")
        md.append(f"- **Security Score:** {result.score}/100")
        md.append(f"- **Components Analyzed:** {len(result.architecture.components)}")
        md.append(f"- **Data Flows Analyzed:** {len(result.architecture.flows)}\n")
        
        return md
    
    @staticmethod
    def _generate_risk_treatment(threats: List[Threat]) -> List[str]:
        """Generate risk treatment decisions section."""
        md = []
        md.append("## 11. Risk Treatment Decisions\n")
        
        md.append("### Risk Treatment Plan\n")
        md.append("| Threat ID | Threat Title | Treatment | Justification | Review Date |")
        md.append("|-----------|--------------|-----------|---------------|-------------|")
        
        for threat in threats[:10]:  # Top 10 threats
            # Default treatment based on severity
            if threat.severity in ['Critical', 'High']:
                treatment = "Mitigate"
                justification = "High risk requires immediate mitigation"
            else:
                treatment = "Mitigate"
                justification = "Plan mitigation in security roadmap"
            
            review_date = ReportGenerator._get_next_review_date()
            title_short = threat.title[:40] + "..." if len(threat.title) > 40 else threat.title
            
            md.append(f"| {threat.id} | {title_short} | {treatment} | {justification} | {review_date} |")
        
        md.append("\n**Treatment Options:**")
        md.append("- **Mitigate:** Implement controls to reduce risk")
        md.append("- **Accept:** Acknowledge risk and accept consequences")
        md.append("- **Transfer:** Transfer risk to third party (insurance, vendor)")
        md.append("- **Avoid:** Eliminate the risk by removing the feature/component\n")
        
        return md
    
    @staticmethod
    def _generate_testing_plan(threats: List[Threat]) -> List[str]:
        """Generate testing and validation plan."""
        md = []
        md.append("## 12. Testing and Validation Plan\n")
        
        md.append("### Recommended Security Testing\n")
        
        # Group threats by category for testing recommendations
        has_injection = any('Injection' in t.title or 'SQL' in t.title for t in threats)
        has_auth = any('Auth' in t.title or 'JWT' in t.title or 'OAuth' in t.title for t in threats)
        has_access = any('Access' in t.title for t in threats)
        has_crypto = any('Crypto' in t.title or 'Encryption' in t.title for t in threats)
        
        if has_injection:
            md.append("#### Injection Testing")
            md.append("- **SAST:** Use static analysis to detect SQL/NoSQL injection vulnerabilities")
            md.append("- **DAST:** Automated injection testing with tools like SQLMap, Burp Suite")
            md.append("- **Manual Testing:** Penetration testing with crafted payloads")
            md.append("- **Validation:** Verify input sanitization and parameterized queries\n")
        
        if has_auth:
            md.append("#### Authentication Testing")
            md.append("- **Token Analysis:** Verify JWT expiration, signature validation")
            md.append("- **Session Testing:** Test session timeout, token refresh mechanisms")
            md.append("- **Credential Testing:** Verify secure credential storage and transmission")
            md.append("- **MFA Testing:** Validate multi-factor authentication implementation\n")
        
        if has_access:
            md.append("#### Authorization Testing")
            md.append("- **RBAC Testing:** Verify role-based access controls")
            md.append("- **Privilege Escalation:** Test for horizontal and vertical privilege escalation")
            md.append("- **API Authorization:** Verify API endpoint access controls")
            md.append("- **Resource Access:** Test unauthorized resource access attempts\n")
        
        if has_crypto:
            md.append("#### Cryptography Testing")
            md.append("- **TLS/SSL Testing:** Verify strong cipher suites, certificate validation")
            md.append("- **Encryption Testing:** Verify data encryption at rest and in transit")
            md.append("- **Key Management:** Test key rotation, secure key storage")
            md.append("- **Protocol Testing:** Verify secure protocol usage (TLS 1.2+)\n")
        
        md.append("### Recommended Tools\n")
        md.append("- **SAST:** SonarQube, Checkmarx, Veracode")
        md.append("- **DAST:** OWASP ZAP, Burp Suite Professional, Acunetix")
        md.append("- **Dependency Scanning:** Snyk, Dependabot, npm audit")
        md.append("- **Container Scanning:** Trivy, Clair, Anchore")
        md.append("- **Cloud Security:** Prowler (AWS), ScoutSuite (Multi-cloud)\n")
        
        return md
    
    @staticmethod
    def _generate_appendices(stride_colors: Dict) -> List[str]:
        """Generate appendices section."""
        md = []
        md.append("## 13. Appendices\n")
        
        md.append("### Appendix A: STRIDE Methodology\n")
        md.append("STRIDE is a threat modeling framework developed by Microsoft:\n")
        
        stride_data = stride_colors.get('STRIDE_COLORS', {})
        for category, data in stride_data.items():
            icon = data.get('icon', '')
            desc = data.get('description', '')
            md.append(f"- **{icon} {category}:** {desc}")
        
        md.append("\n### Appendix B: Severity Definitions\n")
        md.append("- **Critical:** Immediate threat to system security, data breach likely")
        md.append("- **High:** Significant security risk, exploitation probable")
        md.append("- **Medium:** Moderate security risk, requires attention")
        md.append("- **Low:** Minor security concern, low exploitation probability\n")
        
        md.append("### Appendix C: Glossary\n")
        md.append("- **STRIDE:** Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege")
        md.append("- **MITRE ATT&CK:** Knowledge base of adversary tactics and techniques")
        md.append("- **CWE:** Common Weakness Enumeration")
        md.append("- **CAPEC:** Common Attack Pattern Enumeration and Classification")
        md.append("- **CIA Triad:** Confidentiality, Integrity, Availability")
        md.append("- **SAST:** Static Application Security Testing")
        md.append("- **DAST:** Dynamic Application Security Testing\n")
        
        md.append("### Appendix D: References\n")
        md.append("- OWASP Top 10: https://owasp.org/www-project-top-ten/")
        md.append("- MITRE ATT&CK: https://attack.mitre.org/")
        md.append("- CWE: https://cwe.mitre.org/")
        md.append("- NIST Cybersecurity Framework: https://www.nist.gov/cyberframework")
        md.append("- Microsoft Threat Modeling: https://www.microsoft.com/en-us/securityengineering/sdl/threatmodeling\n")
        
        return md
    
    @staticmethod
    def _get_next_review_date() -> str:
        """Get next review date (90 days from now)."""
        from datetime import timedelta
        next_review = datetime.now() + timedelta(days=90)
        return next_review.strftime("%Y-%m-%d")
