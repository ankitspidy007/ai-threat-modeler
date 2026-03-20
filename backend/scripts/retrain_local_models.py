"""
Rebuild local knowledge-driven intelligence for AI Threat Modeler.

This refreshes:
- knowledge base loading
- semantic vector index
- local STRIDE classifier
- analyzer caches
"""

from pathlib import Path
import json
import sys


def main():
    backend_dir = Path(__file__).resolve().parent.parent
    if str(backend_dir) not in sys.path:
        sys.path.insert(0, str(backend_dir))

    from app.engine.analyzer import ThreatAnalyzer

    analyzer = ThreatAnalyzer()
    stats = analyzer.reload_local_intelligence()
    print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
