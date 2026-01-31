import sys
import os

# Ensure app is in path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.engine.analyzer import ThreatAnalyzer

def test_engine():
    print("Initializing Analyzer...")
    analyzer = ThreatAnalyzer()
    
    input_text = "The system has a public API that talks to a Database using basic auth. There is no logging."
    print(f"\nAnalyzing Text: '{input_text}'")
    
    result = analyzer.analyze_from_text(input_text)
    
    print(f"\n--- Analysis Result (Score: {result.score}) ---")
    print(f"Components Found: {[c.name for c in result.architecture.components]}")
    print(f"Threats Detected: {len(result.threats)}")
    
    for t in result.threats:
        print(f"[{t.severity}] {t.title}: {t.description}")

if __name__ == "__main__":
    test_engine()
