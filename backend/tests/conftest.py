import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# An analysis that reaches the network is not the analysis the product ships, so
# the tests run under the same offline policy a deployment does. Set before the
# engine is imported, because model loaders read it at construction.
os.environ.setdefault("AEGIS_THREAT_ALLOW_MODEL_DOWNLOAD", "0")


@pytest.fixture(scope="session")
def analyzer():
    """One analyzer for the whole session.

    Constructing one is cheap only after the first, which loads the knowledge
    base, the embedding index and the STRIDE classifier. Sharing it also means a
    test that mutates global engine state fails here rather than in whichever
    test happens to run next.
    """
    from app.engine.analyzer import ThreatAnalyzer

    return ThreatAnalyzer()


@pytest.fixture(scope="session")
def analyze(analyzer):
    """Analyze a description once per session, however many tests ask for it.

    Several suites assert different things about the same architecture. Caching
    on the arguments keeps each of those a separate, readable test without
    paying for the analysis again.
    """
    cache = {}

    def run(description, project_name="Test Project", **kwargs):
        # The local challenger is off unless a test is about the challenger, so
        # a shared result stays deterministic.
        kwargs.setdefault("use_local_slm", False)
        key = (description, project_name, tuple(sorted(kwargs.items())))
        if key not in cache:
            cache[key] = analyzer.analyze_from_text(description, project_name, **kwargs)
        return cache[key]

    return run
