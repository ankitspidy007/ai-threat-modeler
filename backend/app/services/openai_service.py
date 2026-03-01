"""
OpenAI Service for LLM-enhanced threat detection.
"""
from typing import List, Dict, Optional
from openai import OpenAI
from ..models import Threat
import json

class OpenAIService:
    """Service for analyzing architecture using OpenAI GPT models."""
    
    def __init__(self, api_key: str, model: str = "gpt-4o-mini"):
        """
        Initialize OpenAI service.
        
        Args:
            api_key: OpenAI API key
            model: Model to use (default: gpt-4)
        """
        self.client = OpenAI(api_key=api_key)
        self.model = model
    
    def validate_api_key(self) -> bool:
        """
        Validate if the API key is valid.
        
        Returns:
            True if valid, False otherwise
        """
        try:
            # Make a minimal API call to test the key
            self.client.models.list()
            return True
        except Exception as e:
            print(f"API key validation failed: {e}")
            return False
    
    def analyze_architecture(self, description: str, project_name: str = "System") -> List[Threat]:
        """
        Analyze architecture description using OpenAI.
        
        Args:
            description: Architecture description text
            project_name: Name of the project
            
        Returns:
            List of detected threats
        """
        prompt = self._build_prompt(description, project_name)
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": self._get_system_prompt()},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,  # Lower temperature for more consistent results
                response_format={"type": "json_object"}
            )
            
            # Parse response
            content = response.choices[0].message.content
            threats_data = json.loads(content)
            
            # Convert to Threat objects
            threats = self._parse_threats(threats_data)
            return threats
            
        except Exception as e:
            print(f"OpenAI analysis failed: {e}")
            raise RuntimeError(f"OpenAI API call failed: {e}") from e
    
    def _get_system_prompt(self) -> str:
        """Get the system prompt for threat analysis."""
        return """You are an expert security architect specializing in threat modeling using the STRIDE framework.

Your task is to analyze system architecture descriptions and identify security threats.

For each threat you identify, provide:
1. id: A unique identifier (e.g., "LLM-001")
2. category: STRIDE category (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
3. title: Brief, clear title
4. description: Detailed explanation of the threat
5. severity: Critical, High, Medium, or Low
6. likelihood: High, Medium, or Low
7. impact: High, Medium, or Low
8. mitigation: Specific steps to mitigate the threat
9. evidence: Specific quotes or references from the architecture description
10. owasp_top_10: Relevant OWASP Top 10 category (if applicable)
11. cwe_id: Relevant CWE ID (if applicable)

Return your analysis as a JSON object with a "threats" array.

Example format:
{
  "threats": [
    {
      "id": "LLM-001",
      "category": "Information Disclosure",
      "title": "Sensitive Data Exposure in Logs",
      "description": "...",
      "severity": "High",
      "likelihood": "Medium",
      "impact": "High",
      "mitigation": "...",
      "evidence": ["..."],
      "owasp_top_10": "A01:2021 - Broken Access Control",
      "cwe_id": "CWE-200"
    }
  ]
}"""
    
    def _build_prompt(self, description: str, project_name: str) -> str:
        """Build the analysis prompt."""
        return f"""Analyze the following system architecture for security threats using the STRIDE framework.

Project: {project_name}

Architecture Description:
{description}

Identify all potential security threats, focusing on:
- Authentication and authorization issues
- Data protection and encryption
- API security
- Input validation
- Third-party integrations
- Network security
- Session management
- Error handling
- Access control

Provide detailed, actionable findings with specific evidence from the description."""
    
    def _parse_threats(self, threats_data: Dict) -> List[Threat]:
        """
        Parse threats from LLM response.
        
        Args:
            threats_data: Parsed JSON response from LLM
            
        Returns:
            List of Threat objects
        """
        threats = []
        
        for threat_dict in threats_data.get("threats", []):
            try:
                # Normalize compliance fields — LLM may return strings or lists
                owasp_raw = threat_dict.get("owasp_top_10", [])
                cwe_raw = threat_dict.get("cwe_id") or threat_dict.get("cwe", [])
                mitre_raw = threat_dict.get("mitre_attack", [])
                
                # Ensure they are lists
                owasp = [owasp_raw] if isinstance(owasp_raw, str) else (owasp_raw or [])
                cwe = [cwe_raw] if isinstance(cwe_raw, str) else (cwe_raw or [])
                mitre = [mitre_raw] if isinstance(mitre_raw, str) else (mitre_raw or [])
                
                # Ensure evidence is a list
                evidence = threat_dict.get("evidence", [])
                if isinstance(evidence, str):
                    evidence = [evidence]
                
                threat = Threat(
                    id=threat_dict.get("id", "LLM-UNKNOWN"),
                    category=threat_dict.get("category", "Unknown"),
                    title=f"[AI] {threat_dict.get('title', 'Unknown Threat')}",
                    description=threat_dict.get("description", ""),
                    severity=threat_dict.get("severity", "Medium"),
                    likelihood=threat_dict.get("likelihood", "Medium"),
                    impact=threat_dict.get("impact", "Medium"),
                    risk_score=self._calculate_risk_score(
                        threat_dict.get("severity", "Medium"),
                        threat_dict.get("likelihood", "Medium")
                    ),
                    mitigation=threat_dict.get("mitigation", ""),
                    confidence="High",
                    evidence=evidence,
                    status="Identified",
                    tier="Confirmed",
                    owasp_top_10=owasp,
                    cwe=cwe,
                    mitre_attack=mitre,
                )
                threats.append(threat)
            except Exception as e:
                print(f"Failed to parse LLM threat: {e} | Data: {threat_dict}")
                continue
        
        return threats
    
    def _calculate_risk_score(self, severity: str, likelihood: str) -> int:
        """Calculate risk score from severity and likelihood."""
        severity_scores = {"Critical": 100, "High": 75, "Medium": 50, "Low": 25}
        likelihood_scores = {"High": 1.0, "Medium": 0.7, "Low": 0.4}
        
        base_score = severity_scores.get(severity, 50)
        multiplier = likelihood_scores.get(likelihood, 0.7)
        
        return int(base_score * multiplier)
