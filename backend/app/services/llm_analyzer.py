"""
LLM Analyzer - Orchestrates LLM-based threat detection.
"""
from typing import List, Optional
from ..models import Threat
from .openai_service import OpenAIService
from .claude_service import ClaudeService

class LLMAnalyzer:
    """Orchestrates LLM-based threat analysis and merges with rule-based threats."""
    
    @staticmethod
    def analyze_with_llm(
        architecture_description: str,
        project_name: str,
        provider: str,
        api_key: str,
        model: Optional[str] = None
    ) -> List[Threat]:
        """
        Analyze architecture using specified LLM provider.
        
        Args:
            architecture_description: System architecture description
            project_name: Name of the project
            provider: LLM provider ("openai" or "claude")
            api_key: API key for the provider
            model: Optional specific model to use
            
        Returns:
            List of threats detected by LLM
        """
        if provider.lower() == "openai":
            service = OpenAIService(api_key, model or "gpt-4")
        elif provider.lower() == "claude":
            service = ClaudeService(api_key, model or "claude-3-5-sonnet-20241022")
        else:
            raise ValueError(f"Unsupported LLM provider: {provider}")
        
        return service.analyze_architecture(architecture_description, project_name)
    
    @staticmethod
    def validate_api_key(provider: str, api_key: str) -> bool:
        """
        Validate API key for specified provider.
        
        Args:
            provider: LLM provider ("openai" or "claude")
            api_key: API key to validate
            
        Returns:
            True if valid, False otherwise
        """
        try:
            if provider.lower() == "openai":
                service = OpenAIService(api_key)
            elif provider.lower() == "claude":
                service = ClaudeService(api_key)
            else:
                return False
            
            return service.validate_api_key()
        except Exception as e:
            print(f"API key validation error: {e}")
            return False
    
    @staticmethod
    def merge_threats(
        rule_based_threats: List[Threat],
        llm_threats: List[Threat]
    ) -> List[Threat]:
        """
        Merge rule-based and LLM-detected threats, removing duplicates.
        
        Args:
            rule_based_threats: Threats from rule engine
            llm_threats: Threats from LLM
            
        Returns:
            Merged list of threats
        """
        # Start with all rule-based threats
        merged = list(rule_based_threats)
        
        # Add LLM threats that don't duplicate rule-based ones
        for llm_threat in llm_threats:
            # Check if similar threat already exists
            is_duplicate = False
            for existing_threat in merged:
                if LLMAnalyzer._is_similar_threat(existing_threat, llm_threat):
                    # Enrich existing threat with LLM insights
                    existing_threat.description += f"\n\n**AI Insight:** {llm_threat.description}"
                    if llm_threat.mitigation and llm_threat.mitigation not in existing_threat.mitigation:
                        existing_threat.mitigation += f"\n\n**AI Recommendation:** {llm_threat.mitigation}"
                    is_duplicate = True
                    break
            
            if not is_duplicate:
                merged.append(llm_threat)
        
        return merged
    
    @staticmethod
    def _is_similar_threat(threat1: Threat, threat2: Threat) -> bool:
        """
        Check if two threats are similar (potential duplicates).
        
        Args:
            threat1: First threat
            threat2: Second threat
            
        Returns:
            True if threats are similar
        """
        # Check if categories match
        if threat1.category != threat2.category:
            return False
        
        # Check if titles are very similar (simple keyword matching)
        title1_words = set(threat1.title.lower().split())
        title2_words = set(threat2.title.lower().split())
        
        # Remove common words
        common_words = {"the", "a", "an", "in", "on", "at", "to", "for", "of", "and", "or", "ai", "potential"}
        title1_words -= common_words
        title2_words -= common_words
        
        # Calculate overlap
        if not title1_words or not title2_words:
            return False
        
        overlap = len(title1_words & title2_words) / max(len(title1_words), len(title2_words))
        
        # If more than 50% overlap, consider similar
        return overlap > 0.5
