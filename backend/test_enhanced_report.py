import requests
import json

# Test the enhanced threat detection and report generation
url = "http://127.0.0.1:8000/analyze"
data = {
    "project_name": "E-Commerce Platform",
    "description": "A Node.js API connected to MongoDB with React frontend, hosted on AWS using Cognito for auth"
}

print("Sending request to analyze architecture...")
response = requests.post(url, json=data)

print(f"Status Code: {response.status_code}\n")

if response.status_code == 200:
    result = response.json()
    
    # Save full result
    with open('enhanced_report_result.json', 'w') as f:
        json.dump(result, f, indent=2)
    print("✅ Full result saved to: enhanced_report_result.json\n")
    
    # Save enhanced markdown report
    if 'report_markdown' in result:
        with open('enhanced_threat_report.md', 'w', encoding='utf-8') as f:
            f.write(result['report_markdown'])
        print("✅ Enhanced report saved to: enhanced_threat_report.md\n")
        
        # Show report statistics
        report = result['report_markdown']
        print("=" * 80)
        print("ENHANCED REPORT STATISTICS")
        print("=" * 80)
        print(f"Total lines: {len(report.split(chr(10)))}")
        print(f"Total characters: {len(report)}")
        print(f"\nSections included:")
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
            "Risk Treatment Decisions",
            "Testing and Validation Plan",
            "Appendices"
        ]
        for section in sections:
            if section in report:
                print(f"  ✅ {section}")
            else:
                print(f"  ❌ {section}")
        
        print(f"\n📊 Security Score: {result.get('score', 'N/A')}/100")
        print(f"🔍 Total Threats: {len(result.get('threats', []))}")
        print(f"✅ Confirmed: {len([t for t in result.get('threats', []) if t.get('tier') == 'Confirmed'])}")
        print(f"⚠️  Potential: {len([t for t in result.get('threats', []) if t.get('tier') == 'Potential'])}")
        
    # Save enhanced diagram
    if 'mermaid_diagram' in result:
        with open('enhanced_architecture_diagram.mmd', 'w', encoding='utf-8') as f:
            f.write(result['mermaid_diagram'])
        print(f"\n✅ Enhanced diagram saved to: enhanced_architecture_diagram.mmd")
        
        diagram = result['mermaid_diagram']
        print(f"\nDiagram features:")
        if 'DFD' in diagram or '[E' in diagram or '[D' in diagram:
            print("  ✅ DFD element numbering ([E1], [D1], [1.0])")
        if 'Trust' in diagram or 'Untrusted' in diagram:
            print("  ✅ Trust boundary visualization")
        if 'STRIDE' in diagram:
            print("  ✅ STRIDE legend included")
        if 'fill:#' in diagram:
            print("  ✅ Color coding applied")
    
    print("\n" + "=" * 80)
    print("✅ ENHANCED REPORT GENERATION SUCCESSFUL!")
    print("=" * 80)
    print("\nView the enhanced report at: enhanced_threat_report.md")
    print("View the diagram at: enhanced_architecture_diagram.mmd")
    
else:
    print(f"❌ Error: {response.status_code}")
    print(response.text)
