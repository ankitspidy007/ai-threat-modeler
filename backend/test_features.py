"""Quick verification test for all 3 new features."""
import sys
sys.path.insert(0, '.')
import logging
logging.basicConfig(level=logging.WARNING)

from app.engine.analyzer import ThreatAnalyzer

desc = (
    "Web app with React frontend connects to Node.js API server. "
    "API server uses PostgreSQL database for user data. "
    "Redis cache between API and DB. External payment service Stripe connected via HTTPS. "
    "JWT authentication. No WAF or logging."
)

a = ThreatAnalyzer()
r = a.analyze_from_text(desc, "Test Project")

print(f"Score: {r.score}")
print(f"Threats: {len(r.threats)}")

ml = r.ml_enhanced or {}
print(f"Semantic: {ml.get('semantic_matching', False)}")
print(f"STRIDE Classifier: {ml.get('stride_classifier', False)}")
print(f"STRIDE Accuracy: {ml.get('stride_classifier_accuracy', 0)}")
print(f"Severity: {ml.get('severity_classifier', False)}")
print(f"Attack Chains: {ml.get('attack_chains', False)}")

insights = r.architecture_insights or []
print(f"Insights: {len(insights)}")
for i in insights:
    print(f"  [{i['severity']}] {i['title']}")
print("DONE")
