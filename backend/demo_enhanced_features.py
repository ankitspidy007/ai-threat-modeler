import requests
import json

print("=" * 80)
print("🚀 ENHANCED THREAT MODELER - LIVE DEMONSTRATION")
print("=" * 80)
print()

# Test the enhanced system
url = "http://127.0.0.1:8000/analyze"
data = {
    "project_name": "E-Commerce Platform",
    "description": "A Node.js API connected to MongoDB with React frontend, hosted on AWS using Cognito for auth"
}

print("📝 Analyzing architecture...")
print(f"   Input: {data['description']}")
print()

response = requests.post(url, json=data)

if response.status_code == 200:
    result = response.json()
    
    print("✅ Analysis Complete!")
    print("=" * 80)
    print()
    
    # Show key metrics
    print("📊 SECURITY METRICS")
    print("-" * 80)
    print(f"   Security Score: {result.get('score', 'N/A')}/100")
    print(f"   Total Threats: {len(result.get('threats', []))}")
    
    confirmed = [t for t in result.get('threats', []) if t.get('tier') == 'Confirmed']
    potential = [t for t in result.get('threats', []) if t.get('tier') == 'Potential']
    
    print(f"   Confirmed Risks: {len(confirmed)}")
    print(f"   Potential Risks: {len(potential)}")
    print()
    
    # Show severity breakdown
    critical = len([t for t in confirmed if t.get('severity') == 'Critical'])
    high = len([t for t in confirmed if t.get('severity') == 'High'])
    medium = len([t for t in confirmed if t.get('severity') == 'Medium'])
    low = len([t for t in confirmed if t.get('severity') == 'Low'])
    
    print("🎯 THREAT SEVERITY BREAKDOWN")
    print("-" * 80)
    print(f"   🔴 Critical: {critical}")
    print(f"   🟠 High: {high}")
    print(f"   🟡 Medium: {medium}")
    print(f"   🟢 Low: {low}")
    print()
    
    # Show detected threats
    print("🔍 DETECTED THREATS")
    print("-" * 80)
    for i, threat in enumerate(confirmed[:5], 1):
        severity_icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(threat.get('severity'), "⚪")
        print(f"   {i}. {severity_icon} [{threat.get('severity')}] {threat.get('title')}")
        print(f"      Category: {threat.get('stride_category', threat.get('category'))}")
        print(f"      Component: {', '.join(threat.get('affected_components', ['N/A']))}")
        print()
    
    # Show architecture diagram info
    if 'mermaid_diagram' in result:
        diagram = result['mermaid_diagram']
        has_flows = '-->' in diagram or '==>' in diagram
        has_dfd = '[E' in diagram or '[D' in diagram or '.0]' in diagram
        has_legend = 'Legend' in diagram
        
        print("🎨 ARCHITECTURE DIAGRAM")
        print("-" * 80)
        print(f"   ✅ Components: {len(result.get('architecture', {}).get('components', []))}")
        print(f"   {'✅' if has_flows else '❌'} Data Flows: {'Present' if has_flows else 'Missing'}")
        print(f"   {'✅' if has_dfd else '❌'} DFD Numbering: {'Present' if has_dfd else 'Missing'}")
        print(f"   {'✅' if has_legend else '❌'} Legend: {'Present' if has_legend else 'Missing'}")
        print()
    
    # Show report sections
    if 'report_markdown' in result:
        report = result['report_markdown']
        sections = [
            "Executive Summary",
            "Scope and Methodology",
            "Architecture Overview",
            "Asset Inventory",
            "Threat Analysis",
            "Recommendations & Mitigations",
            "Risk Heat Map",
            "Compliance Mapping",
            "Metrics and Statistics",
            "Risk Treatment",
            "Testing and Validation",
            "Appendices"
        ]
        
        print("📋 ENHANCED REPORT SECTIONS")
        print("-" * 80)
        for section in sections:
            present = section in report
            icon = "✅" if present else "❌"
            print(f"   {icon} {section}")
        print()
        
        # Show report stats
        lines = len(report.split('\n'))
        chars = len(report)
        has_mitre = 'MITRE ATT&CK' in report
        has_cwe = 'CWE' in report
        has_compliance = 'PCI-DSS' in report or 'GDPR' in report
        
        print("📈 REPORT STATISTICS")
        print("-" * 80)
        print(f"   Total Lines: {lines}")
        print(f"   Total Characters: {chars:,}")
        print(f"   {'✅' if has_mitre else '❌'} MITRE ATT&CK References")
        print(f"   {'✅' if has_cwe else '❌'} CWE References")
        print(f"   {'✅' if has_compliance else '❌'} Compliance Mappings")
        print()
    
    print("=" * 80)
    print("✅ ENHANCED THREAT MODELING COMPLETE!")
    print("=" * 80)
    print()
    print("📁 Files Generated:")
    print("   - enhanced_threat_report.md (Comprehensive report)")
    print("   - enhanced_architecture_diagram.mmd (Mermaid diagram)")
    print("   - enhanced_report_result.json (Full API response)")
    print()
    print("🌐 Open http://localhost:5173 to use the web interface!")
    print()
    
else:
    print(f"❌ Error: {response.status_code}")
    print(response.text)
