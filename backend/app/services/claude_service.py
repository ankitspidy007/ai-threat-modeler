"""
Claude (Anthropic) service for LLM-enhanced threat detection.
"""
from typing import Dict, List

from anthropic import Anthropic

from ..models import Threat
from .llm_threat_contract import (
    build_system_prompt,
    build_user_prompt,
    calculate_risk_score,
    parse_response_json,
    parse_threats,
)


class ClaudeService:
    """Service for analyzing architecture using Claude models."""

    def __init__(self, api_key: str, model: str = "claude-sonnet-4-20250514"):
        self.client = Anthropic(api_key=api_key)
        self.model = model

    def validate_api_key(self) -> bool:
        try:
            self.client.messages.create(
                model=self.model,
                max_tokens=10,
                messages=[{"role": "user", "content": "test"}],
            )
            return True
        except Exception as exc:
            print(f"API key validation failed: {exc}")
            return False

    def list_models(self) -> List[str]:
        """Return model IDs available to the API key when the SDK exposes model listing."""
        if hasattr(self.client, "models") and hasattr(self.client.models, "list"):
            response = self.client.models.list()
            data = getattr(response, "data", response)
            return sorted([model.id for model in data if getattr(model, "id", None)])
        return []

    def analyze_architecture(self, description: str, project_name: str = "System") -> List[Threat]:
        prompt = self._build_prompt(description, project_name)

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=4096,
                temperature=0.3,
                system=self._get_system_prompt(),
                messages=[{"role": "user", "content": prompt}],
            )
            content = response.content[0].text
            threats_data = parse_response_json(content)
            return self._parse_threats(threats_data)
        except Exception as exc:
            print(f"Claude analysis failed: {exc}")
            raise RuntimeError(f"Claude API call failed: {exc}") from exc

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
