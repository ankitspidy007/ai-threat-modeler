"""Export expert-approved golden scenarios as versioned SLM training JSONL."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

BACKEND_ROOT = Path(__file__).parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.engine.analyzer import ThreatAnalyzer
from app.evaluation import load_corpus
from app.training_data import build_training_records, write_jsonl


def main() -> int:
    parser = argparse.ArgumentParser(description="Build reviewed security SLM instruction-tuning data.")
    parser.add_argument("--corpus", default=str(BACKEND_ROOT / "tests" / "fixtures" / "evaluation_corpus.json"))
    parser.add_argument("--output", default=str(BACKEND_ROOT / "training" / "security_threat_training_v1.jsonl"))
    parser.add_argument("--approved-by", required=True, help="Named reviewer or review group approving the labels.")
    args = parser.parse_args()
    records = build_training_records(load_corpus(args.corpus), ThreatAnalyzer(), args.approved_by)
    print(json.dumps(write_jsonl(records, args.output), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
