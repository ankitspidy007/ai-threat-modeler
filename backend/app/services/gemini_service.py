"""
Google Gemini service for LLM-enhanced threat detection.
"""
from typing import Dict, List

import requests

from ..models import Threat
from .llm_threat_contract import (
    build_system_prompt,
    build_user_prompt,
    calculate_risk_score,
    parse_response_json,
    parse_threats,
)


class GeminiService:
    """Service for analyzing architecture using Google Gemini models."""

    def __init__(self, api_key: str, model: str = "gemini-2.0-flash"):
        self.api_key = api_key
        self.model = model
        self.base_url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}"

    def validate_api_key(self) -> bool:
        try:
            url = f"{self.base_url}:generateContent?key={self.api_key}"
            response = requests.post(
                url,
                json={
                    "contents": [{"parts": [{"text": "test"}]}],
                    "generationConfig": {"maxOutputTokens": 10},
                },
                timeout=15,
            )
            return response.status_code == 200
        except Exception as exc:
            print(f"API key validation failed: {exc}")
            return False

    def list_models(self) -> List[str]:
        """Return Gemini models that support content generation."""
        response = requests.get(
            f"https://generativelanguage.googleapis.com/v1beta/models?key={self.api_key}",
            timeout=15,
        )
        response.raise_for_status()
        models = []
        for model in response.json().get("models", []):
            methods = model.get("supportedGenerationMethods", [])
            name = model.get("name", "")
            if "generateContent" in methods and name.startswith("models/"):
                models.append(name.replace("models/", "", 1))
        return sorted(models)

    def analyze_architecture(self, description: str, project_name: str = "System") -> List[Threat]:
        prompt = self._build_prompt(description, project_name)

        try:
            url = f"{self.base_url}:generateContent?key={self.api_key}"
            response = requests.post(
                url,
                json={
                    "contents": [{"parts": [{"text": prompt}]}],
                    "systemInstruction": {"parts": [{"text": self._get_system_prompt()}]},
                    "generationConfig": {
                        "temperature": 0.3,
                        "maxOutputTokens": 4096,
                        "responseMimeType": "application/json",
                    },
                },
                timeout=60,
            )

            if response.status_code != 200:
                print(f"Gemini API error: {response.status_code} - {response.text}")
                return []

            result = response.json()
            content = result["candidates"][0]["content"]["parts"][0]["text"]
            threats_data = parse_response_json(content)
            return self._parse_threats(threats_data)
        except Exception as exc:
            print(f"Gemini analysis failed: {exc}")
            raise RuntimeError(f"Gemini API call failed: {exc}") from exc

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
