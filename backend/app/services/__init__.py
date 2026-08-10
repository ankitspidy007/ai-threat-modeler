"""Services package.

LLM SDKs are optional at import time, so service classes are loaded lazily.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .claude_service import ClaudeService
    from .llm_analyzer import LLMAnalyzer
    from .openai_service import OpenAIService


def __getattr__(name):
    if name == "OpenAIService":
        from .openai_service import OpenAIService

        return OpenAIService
    if name == "ClaudeService":
        from .claude_service import ClaudeService

        return ClaudeService
    if name == "LLMAnalyzer":
        from .llm_analyzer import LLMAnalyzer

        return LLMAnalyzer
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["OpenAIService", "ClaudeService", "LLMAnalyzer"]
