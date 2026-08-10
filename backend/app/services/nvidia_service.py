"""
NVIDIA NIM Service for OpenAI-compatible LLM threat detection.
"""
from typing import List
import logging

from .openai_service import OpenAIService

logger = logging.getLogger(__name__)


class NvidiaService(OpenAIService):
    """Service for analyzing architecture using NVIDIA NIM OpenAI-compatible models."""

    DEFAULT_BASE_URL = "https://integrate.api.nvidia.com/v1"
    PREFERRED_MODELS = [
        "meta/llama-3.1-70b-instruct",
        "meta/llama-3.1-8b-instruct",
        "minimaxai/minimax-m3",
        "minimaxai/minimax-m2.7",
        "mistralai/mixtral-8x7b-instruct-v0.1",
        "meta/llama-3.3-70b-instruct",
        "google/gemma-3-12b-it",
        "google/gemma-3-4b-it",
        "mistralai/mistral-7b-instruct-v0.3",
        "deepseek-ai/deepseek-v4-flash",
        "deepseek-ai/deepseek-v4-pro",
    ]
    EXCLUDED_TOKENS = (
        "embed",
        "embedding",
        "rerank",
        "diffusion",
        "vision",
        "audio",
        "asr",
        "deplot",
    )

    def __init__(
        self,
        api_key: str,
        model: str = "meta/llama-3.1-70b-instruct",
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 8.0,
    ):
        super().__init__(
            api_key=api_key,
            model=model,
            base_url=base_url,
            supports_response_format=False,
            timeout=timeout,
        )

    def validate_api_key(self) -> bool:
        try:
            candidate_models = self._compatible_models()
            model = candidate_models[0] if candidate_models else self.model
            self.client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": "Return OK"}],
                max_tokens=1,
                temperature=0,
            )
            return True
        except Exception as exc:
            print(f"NVIDIA API key validation failed: {exc}")
            return False

    def list_models(self) -> List[str]:
        model_ids = super().list_models()
        preferred = [model_id for model_id in self.PREFERRED_MODELS if model_id in model_ids]
        remaining = [model_id for model_id in model_ids if model_id not in preferred]
        return preferred + remaining

    def analyze_architecture(self, description: str, project_name: str = "System"):
        candidates = [self.model, *self._fallback_candidates()]
        attempted = []

        for candidate in candidates:
            if candidate in attempted:
                continue
            attempted.append(candidate)
            self.model = candidate
            try:
                return super().analyze_architecture(description, project_name)
            except RuntimeError as exc:
                logger.warning("NVIDIA analysis failed for model %s: %s", candidate, exc)
                continue

        raise RuntimeError(
            "NVIDIA API call failed for all compatible models. "
            f"Tried: {', '.join(attempted[:6])}"
        )

    @classmethod
    def _is_text_generation_model(cls, model_id: str) -> bool:
        lowered = model_id.lower()
        if any(token in lowered for token in cls.EXCLUDED_TOKENS):
            return False

        if lowered.startswith("minimaxai/"):
            return True

        return any(token in lowered for token in ("instruct", "chat", "-it", "-flash", "-pro"))

    def _fallback_candidates(self) -> List[str]:
        available = self._compatible_models()
        prioritized = []

        if self.model == "minimaxai/minimax-m3":
            prioritized.extend([
                "minimaxai/minimax-m2.7",
                "meta/llama-3.1-70b-instruct",
                "meta/llama-3.1-8b-instruct",
            ])

        prioritized.extend(self.PREFERRED_MODELS)
        prioritized.extend(available)
        return [model_id for model_id in prioritized if model_id != self.model]

    def _compatible_models(self) -> List[str]:
        all_models = self.list_models()
        return [model_id for model_id in all_models if self._is_text_generation_model(model_id)]
