"""Quick test: Check if mapped_controls flow through to Threat objects."""
import sys
sys.path.insert(0, '.')
from app.engine.rules import RuleEngine

re = RuleEngine()

with open('test_output.txt', 'w') as f:
    # Count rules with mapped_controls
    rules_with_mc = [r for r in re.rules if r.get('mapped_controls')]
    f.write(f"Total rules: {len(re.rules)}\n")
    f.write(f"Rules with mapped_controls: {len(rules_with_mc)}\n\n")

    # Show first 10
    for r in rules_with_mc[:10]:
        mc = r['mapped_controls']
        f.write(f"  {r['id']}: owasp={mc.get('owasp_top_10',[])} cwe={mc.get('cwe',[])} mitre={mc.get('mitre_attack', mc.get('mitre',[]))} nist={mc.get('nist_800_53',[])}\n")

    # Now test the full analyze pipeline
    f.write("\n--- Full Analysis Test ---\n")
    from app.engine.analyzer import ThreatAnalyzer
    analyzer = ThreatAnalyzer()
    result = analyzer.analyze_from_text("A web app with React frontend and Node.js API and PostgreSQL database", "Test")

    for t in result.threats:
        f.write(f"  {t.id} | {t.title[:50]} | owasp={t.owasp_top_10} cwe={t.cwe} mitre={t.mitre_attack} nist={t.nist_800_53}\n")

print("Output written to test_output.txt")
