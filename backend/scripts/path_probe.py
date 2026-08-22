"""Per-finding view of why an attack path was or was not built."""
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.engine.analyzer import ThreatAnalyzer  # noqa: E402
from scripts.flow_probe import SCENARIOS  # noqa: E402


def main() -> None:
    analyzer = ThreatAnalyzer()
    for label in ("healthcare", "fintech"):
        result = analyzer.analyze_from_text(SCENARIOS[label], project_name=label)
        print(f"\n=== {label} ===")
        for threat in result.threats:
            path = threat.attack_path or {}
            print(
                f"  {threat.id:26} tier={threat.tier or '-':10} "
                f"comp={threat.component or '-':20} exposure={threat.exposure or '-':9} "
                f"path={path.get('path_status', 'none'):22} hops={len(path.get('hops') or [])}"
            )


if __name__ == "__main__":
    main()
