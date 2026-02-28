import json

with open('threat_analysis_result.json') as f:
    data = json.load(f)

print(f"Total threats detected: {len(data['threats'])}")
print(f"Security score: {data['score']}/100\n")
print("="*80)
print("DETECTED THREATS:")
print("="*80)

for i, threat in enumerate(data['threats'], 1):
    print(f"\n{i}. [{threat['id']}] {threat['title']}")
    print(f"   Severity: {threat['severity']}")
    print(f"   Component: {threat.get('affected_components', ['N/A'])[0]}")
