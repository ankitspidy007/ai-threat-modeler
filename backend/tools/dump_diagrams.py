"""Write a diagram for every golden scenario so their syntax can be checked.

Pair with scripts/check-diagram-syntax.mjs, which parses the output with the
same Mermaid build the browser uses.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.engine.analyzer import ThreatAnalyzer

HERE = os.path.dirname(__file__)
OUT = os.path.abspath(os.path.join(HERE, '..', 'diagram_check'))
CORPORA = (
    os.path.join(HERE, '..', 'tests', 'fixtures', 'golden_scenarios.json'),
    os.path.join(HERE, '..', 'tests', 'fixtures', 'evaluation_corpus.json'),
)


def scenarios():
    for path in CORPORA:
        if not os.path.exists(path):
            continue
        with open(path, encoding='utf-8') as handle:
            payload = json.load(handle)
        records = payload if isinstance(payload, list) else payload.get('scenarios', [])
        for record in records:
            description = record.get('description') or record.get('input') or ''
            if description:
                yield record.get('id', 'scenario'), description


def main() -> None:
    os.makedirs(OUT, exist_ok=True)
    analyzer = ThreatAnalyzer()
    for name, description in scenarios():
        result = analyzer.analyze_from_text(description, name, use_local_slm=False)
        target = os.path.join(OUT, f'{name}.mmd')
        with open(target, 'w', encoding='utf-8') as handle:
            handle.write(result.mermaid_diagram)
        print(f'wrote {target}')


if __name__ == '__main__':
    main()
