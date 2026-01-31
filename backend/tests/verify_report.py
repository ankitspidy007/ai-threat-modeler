import sys
import os

# Add backend to path
sys.path.append(os.path.join(os.getcwd(), 'backend'))

from app.engine.analyzer import ThreatAnalyzer
from app.models import AnalysisResult

def test_report_generation():
    analyzer = ThreatAnalyzer()
    description = "A web app with an API connecting to a Database."
    project_name = "Test Project Alpha"
    
    result = analyzer.analyze_from_text(description, project_name)
    
    print(f"Project Name: {result.project_name}")
    print(f"Report Generated: {result.report_markdown is not None}")
    
    if result.report_markdown:
        print("\n--- Report Preview ---\n")
        print(result.report_markdown[:200] + "...")
        
        if project_name in result.report_markdown:
            print("\n[PASS] Project Name found in report.")
        else:
            print("\n[FAIL] Project Name NOT found in report.")
            
        if "System Architecture" in result.report_markdown:
             print("[PASS] Architecture section found.")
        else:
             print("[FAIL] Architecture section missing.")
             
        if "Identified Threats" in result.report_markdown:
             print("[PASS] Threats section found.")
        else:
             print("[FAIL] Threats section missing.")

if __name__ == "__main__":
    test_report_generation()
