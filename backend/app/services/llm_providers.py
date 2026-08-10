"""
LLM provider registry and model discovery helpers.
"""
from dataclasses import dataclass
from typing import Dict, List, Optional

from .claude_service import ClaudeService
from .gemini_service import GeminiService
from .nvidia_service import NvidiaService
from .openai_service import OpenAIService


@dataclass(frozen=True)
class ModelOption:
    id: str
    label: str
    recommended: bool = False
    tier: str = "balanced"


@dataclass(frozen=True)
class ProviderConfig:
    id: str
    label: str
    description: str
    key_hint: str
    default_model: str
    fallback_models: List[ModelOption]


PROVIDERS: Dict[str, ProviderConfig] = {
    "openai": ProviderConfig(
        id="openai",
        label="OpenAI",
        description="GPT models for strong structured security analysis",
        key_hint="sk-...",
        default_model="gpt-4o-mini",
        fallback_models=[
            ModelOption("gpt-4o-mini", "GPT-4o Mini", True, "fast"),
            ModelOption("gpt-4o", "GPT-4o", False, "quality"),
        ],
    ),
    "claude": ProviderConfig(
        id="claude",
        label="Claude",
        description="Anthropic Claude models for long-context threat reasoning",
        key_hint="sk-ant-...",
        default_model="claude-sonnet-4-20250514",
        fallback_models=[
            ModelOption("claude-sonnet-4-20250514", "Claude Sonnet 4", True, "quality"),
            ModelOption("claude-3-5-sonnet-20241022", "Claude 3.5 Sonnet", False, "balanced"),
            ModelOption("claude-3-5-haiku-20241022", "Claude 3.5 Haiku", False, "fast"),
        ],
    ),
    "gemini": ProviderConfig(
        id="gemini",
        label="Gemini",
        description="Google Gemini models for fast JSON threat extraction",
        key_hint="AIza...",
        default_model="gemini-2.0-flash",
        fallback_models=[
            ModelOption("gemini-2.0-flash", "Gemini 2.0 Flash", True, "fast"),
            ModelOption("gemini-1.5-pro", "Gemini 1.5 Pro", False, "quality"),
            ModelOption("gemini-1.5-flash", "Gemini 1.5 Flash", False, "balanced"),
        ],
    ),
    "nvidia": ProviderConfig(
        id="nvidia",
        label="NVIDIA",
        description="NVIDIA NIM OpenAI-compatible inference endpoint",
        key_hint="nvapi-...",
        default_model="meta/llama-3.1-70b-instruct",
        fallback_models=[
            ModelOption("meta/llama-3.1-70b-instruct", "Llama 3.1 70B Instruct", True, "quality"),
            ModelOption("meta/llama-3.1-8b-instruct", "Llama 3.1 8B Instruct", False, "fast"),
            ModelOption("mistralai/mixtral-8x7b-instruct-v0.1", "Mixtral 8x7B Instruct", False, "balanced"),
        ],
    ),
}


def supported_provider_ids() -> List[str]:
    return list(PROVIDERS)


def provider_public_info() -> List[dict]:
    return [
        {
            "id": provider.id,
            "label": provider.label,
            "description": provider.description,
            "key_hint": provider.key_hint,
            "default_model": provider.default_model,
            "fallback_models": [model.__dict__ for model in provider.fallback_models],
        }
        for provider in PROVIDERS.values()
    ]


def get_provider(provider: str) -> ProviderConfig:
    normalized = (provider or "").lower()
    if normalized not in PROVIDERS:
        raise ValueError(f"Unsupported LLM provider: {provider}")
    return PROVIDERS[normalized]


def create_service(provider: str, api_key: str, model: Optional[str] = None):
    config = get_provider(provider)
    selected_model = model or config.default_model
    if config.id == "openai":
        return OpenAIService(api_key, selected_model)
    if config.id == "claude":
        return ClaudeService(api_key, selected_model)
    if config.id == "gemini":
        return GeminiService(api_key, selected_model)
    if config.id == "nvidia":
        return NvidiaService(api_key, selected_model)
    raise ValueError(f"Unsupported LLM provider: {provider}")


def _label_from_model_id(model_id: str) -> str:
    label = model_id.split("/")[-1]
    label = label.replace("-", " ").replace("_", " ")
    return label.title()


def normalize_models(provider: str, model_ids: List[str]) -> List[dict]:
    config = get_provider(provider)
    seen = set()
    models = []
    for model_id in model_ids:
        if not model_id or model_id in seen:
            continue
        seen.add(model_id)
        models.append({
            "id": model_id,
            "label": _label_from_model_id(model_id),
            "recommended": model_id == config.default_model,
            "tier": "dynamic",
        })
    if models:
        if not any(model["recommended"] for model in models):
            models[0]["recommended"] = True
        return models
    return [model.__dict__ for model in config.fallback_models]


def list_provider_models(provider: str, api_key: str) -> List[dict]:
    service = create_service(provider, api_key)
    if not hasattr(service, "list_models"):
        return [model.__dict__ for model in get_provider(provider).fallback_models]
    try:
        return normalize_models(provider, service.list_models())
    except Exception:
        return [model.__dict__ for model in get_provider(provider).fallback_models]


def validate_provider_key(provider: str, api_key: str) -> bool:
    service = create_service(provider, api_key)
    return service.validate_api_key()
