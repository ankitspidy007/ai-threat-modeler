"""
OpenAI-compatible service for LLM-enhanced threat detection.
"""
from typing import Any, Dict, List, Optional

from openai import OpenAI

from ..models import Threat
from .llm_threat_contract import (
    build_system_prompt,
    build_user_prompt,
    calculate_risk_score,
    parse_response_json,
    parse_threats,
)


class OpenAIService:
    """Service for analyzing architecture using OpenAI-compatible chat models."""

    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4o-mini",
        base_url: Optional[str] = None,
        supports_response_format: bool = True,
        timeout: float = 15.0,
    ):
        client_kwargs = {
            "api_key": api_key,
            "timeout": timeout,
            "max_retries": 0,
        }
        if base_url:
            client_kwargs["base_url"] = base_url
        self.client = OpenAI(**client_kwargs)
        self.model = model
        self.supports_response_format = supports_response_format

    def validate_api_key(self) -> bool:
        try:
            self.client.models.list()
            return True
        except Exception as exc:
            print(f"API key validation failed: {exc}")
            return False

    def list_models(self) -> List[str]:
        """Return model IDs available to the API key."""
        models = self.client.models.list()
        return sorted([model.id for model in models.data if getattr(model, "id", None)])

    def analyze_architecture(self, description: str, project_name: str = "System") -> List[Threat]:
        prompt = self._build_prompt(description, project_name)

        try:
            request = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": self._get_system_prompt()},
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.3,
                "max_tokens": 3200,
            }
            if self.supports_response_format:
                request["response_format"] = {"type": "json_object"}

            response = self.client.chat.completions.create(**request)
            content = self._extract_response_content(response)
            threats_data = self._parse_response_json(content)
            return self._parse_threats(threats_data)
        except Exception as exc:
            print(f"OpenAI analysis failed: {exc}")
            raise RuntimeError(f"OpenAI API call failed: {exc}") from exc

    def _extract_response_content(self, response: Any) -> str:
        """Normalize OpenAI-compatible chat completion output into plain text."""
        choices = getattr(response, "choices", None) or []
        if not choices:
            raise RuntimeError("LLM returned no completion choices")

        message = getattr(choices[0], "message", None)
        if message is None:
            raise RuntimeError("LLM returned a choice without a message")

        content = getattr(message, "content", None)
        if isinstance(content, str) and content.strip():
            return content.strip()

        if isinstance(content, list):
            text_parts = []
            for part in content:
                if isinstance(part, str) and part.strip():
                    text_parts.append(part.strip())
                    continue
                if isinstance(part, dict):
                    if isinstance(part.get("text"), str) and part["text"].strip():
                        text_parts.append(part["text"].strip())
                        continue
                    if part.get("type") == "text":
                        nested = part.get("text")
                        if isinstance(nested, str) and nested.strip():
                            text_parts.append(nested.strip())
                        elif isinstance(nested, dict) and isinstance(nested.get("value"), str) and nested["value"].strip():
                            text_parts.append(nested["value"].strip())
            if text_parts:
                return "\n".join(text_parts)

        fallback_text = getattr(choices[0], "text", None)
        if isinstance(fallback_text, str) and fallback_text.strip():
            return fallback_text.strip()

        raise RuntimeError("LLM returned an empty completion payload")

    def _parse_response_json(self, content: str) -> Dict:
        """Extract and parse the JSON object from a model response."""
        return parse_response_json(content)

    def _get_system_prompt(self) -> str:
        """Get the system prompt for threat analysis."""
        return build_system_prompt()

    def _build_prompt(self, description: str, project_name: str) -> str:
        """Build the analysis prompt."""
        return build_user_prompt(description, project_name)

    def _parse_threats(self, threats_data: Dict) -> List[Threat]:
        """Parse threats from LLM response."""
        return parse_threats(threats_data)

    def _calculate_risk_score(self, severity: str, likelihood: str) -> int:
        """Calculate risk score from severity and likelihood."""
        return calculate_risk_score(severity, likelihood)
