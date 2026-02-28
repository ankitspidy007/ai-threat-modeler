import requests
import json

# Test the threat detection with user's input
url = "http://127.0.0.1:8000/analyze"
data = {
    "project_name": "Test Project",
    "description": "A Node.js API connected to MongoDB with React frontend, hosted on AWS using Cognito for auth"
}

response = requests.post(url, json=data)
result = response.json()

print(f"Status Code: {response.status_code}")
print(f"\nTotal Threats Detected: {len(result.get('threats', []))}")
print(f"Security Score: {result.get('security_score', 'N/A')}")

print("\n" + "="*80)
print("DETECTED THREATS:")
print("="*80)

for i, threat in enumerate(result.get('threats', []), 1):
    print(f"\n{i}. [{threat.get('id')}] {threat.get('title')}")
    print(f"   Category: {threat.get('category')}")
    print(f"   Severity: {threat.get('severity')}")
    print(f"   Confidence: {threat.get('confidence', 'N/A')}")
    print(f"   Component: {threat.get('component_id', 'N/A')}")
    if threat.get('evidence'):
        print(f"   Evidence: {threat.get('evidence')}")

# Save full response for analysis
with open('threat_analysis_result.json', 'w') as f:
    json.dump(result, f, indent=2)

print(f"\n\nFull results saved to threat_analysis_result.json")
