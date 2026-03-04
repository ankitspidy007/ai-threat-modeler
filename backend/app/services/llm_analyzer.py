"""
LLM Analyzer - Orchestrates LLM-based threat detection with NLP/DL enhancements.

Improvements over original:
- Semantic deduplication using sentence-transformer embeddings (replaces word-overlap Jaccard)
- RAG: Retrieves relevant KB threats to include in LLM prompts
- Chain-of-thought prompting for better reasoning
"""

import logging
from typing import List, Optional, Dict
from ..models import Threat
from .openai_service import OpenAIService
from .claude_service import ClaudeService
from .gemini_service import GeminiService

logger = logging.getLogger(__name__)

# Import semantic matcher for dedup and RAG
try:
    from ..engine.semantic_matcher import get_semantic_matcher
    SEMANTIC_AVAILABLE = True
except ImportError:
    SEMANTIC_AVAILABLE = False


class LLMAnalyzer:
    """Orchestrates LLM-based threat analysis with semantic dedup and RAG."""
    
    @staticmethod
    def analyze_with_llm(
        architecture_description: str,
        project_name: str,
        provider: str,
        api_key: str,
        model: Optional[str] = None,
        kb_context: Optional[List[Dict]] = None
    ) -> List[Threat]:
        """
        Analyze architecture using specified LLM provider.
        
        Args:
            architecture_description: System architecture description
            project_name: Name of the project
            provider: LLM provider ("openai", "claude", or "gemini")
            api_key: API key for the provider
            model: Optional specific model to use
            kb_context: Optional pre-retrieved KB threats for RAG
            
        Returns:
            List of threats detected by LLM
        """
        if provider.lower() == "openai":
            service = OpenAIService(api_key, model or "gpt-4o-mini")
        elif provider.lower() == "claude":
            service = ClaudeService(api_key, model or "claude-opus-4.6-20260205")
        elif provider.lower() == "gemini":
            service = GeminiService(api_key, model or "gemini-3.1-pro")
        else:
            raise ValueError(f"Unsupported LLM provider: {provider}")
        
        # RAG: Enrich the description with relevant KB threats
        enriched_description = LLMAnalyzer._enrich_with_rag(
            architecture_description, kb_context
        )
        
        return service.analyze_architecture(enriched_description, project_name)
    
    @staticmethod
    def _enrich_with_rag(description: str, kb_context: Optional[List[Dict]] = None) -> str:
        """
        Enrich the architecture description with relevant KB threats (RAG).
        This gives the LLM specific threats to reason about, reducing hallucination.
        """
        relevant_threats = []
        
        # Use pre-fetched context if available
        if kb_context:
            relevant_threats = kb_context
        elif SEMANTIC_AVAILABLE:
            try:
                matcher = get_semantic_matcher()
                results = matcher.find_threats_for_architecture(description, top_k=10)
                relevant_threats = [
                    {
                        'name': meta.get('threat_name', ''),
                        'category': meta.get('category', ''),
                        'severity': meta.get('severity', ''),
                        'score': score
                    }
                    for meta, score in results
                    if score > 0.4
                ]
            except Exception as e:
                logger.warning(f"RAG retrieval failed: {e}")
        
        if not relevant_threats:
            return description
        
        # Append relevant threats as context
        rag_context = "\n\n--- RELEVANT THREAT INTELLIGENCE (from knowledge base) ---\n"
        rag_context += "Consider these known threats when analyzing the architecture:\n\n"
        
        for i, threat in enumerate(relevant_threats[:10], 1):
            name = threat.get('name', threat.get('threat_name', 'Unknown'))
            category = threat.get('category', 'Unknown')
            severity = threat.get('severity', 'Unknown')
            score = threat.get('score', 0)
            rag_context += f"{i}. [{category}] {name} (Severity: {severity}, Relevance: {score:.0%})\n"
        
        rag_context += "\nUse these as hints but also identify threats NOT in this list. "
        rag_context += "Provide specific evidence from the architecture description for each finding.\n"
        
        return description + rag_context
    
    @staticmethod
    def validate_api_key(provider: str, api_key: str) -> bool:
        """Validate API key for specified provider."""
        try:
            if provider.lower() == "openai":
                service = OpenAIService(api_key)
            elif provider.lower() == "claude":
                service = ClaudeService(api_key)
            elif provider.lower() == "gemini":
                service = GeminiService(api_key)
            else:
                return False
            
            return service.validate_api_key()
        except Exception as e:
            logger.error(f"API key validation error: {e}")
            return False
    
    @staticmethod
    def merge_threats(
        rule_based_threats: List[Threat],
        llm_threats: List[Threat]
    ) -> List[Threat]:
        """
        Merge rule-based and LLM-detected threats using semantic deduplication.
        
        Uses embedding-based similarity when available (much better than word overlap),
        falls back to enhanced keyword matching otherwise.
        """
        merged = list(rule_based_threats)
        
        for llm_threat in llm_threats:
            is_duplicate = False
            best_match = None
            best_similarity = 0.0
            
            for existing_threat in merged:
                similarity = LLMAnalyzer._compute_threat_similarity(
                    existing_threat, llm_threat
                )
                
                if similarity > best_similarity:
                    best_similarity = similarity
                    best_match = existing_threat
            
            # Threshold: 0.65 for semantic, 0.5 for keyword fallback
            threshold = 0.65 if SEMANTIC_AVAILABLE else 0.5
            
            if best_similarity > threshold and best_match:
                # Enrich existing threat with LLM insights
                best_match.description += f"\n\n**AI Insight:** {llm_threat.description}"
                if llm_threat.mitigation and llm_threat.mitigation not in best_match.mitigation:
                    best_match.mitigation += f"\n\n**AI Recommendation:** {llm_threat.mitigation}"
                
                # Merge compliance data
                for field in ('owasp_top_10', 'cwe', 'mitre_attack', 'nist_800_53'):
                    existing_vals = getattr(best_match, field, []) or []
                    new_vals = getattr(llm_threat, field, []) or []
                    for v in new_vals:
                        if v and v not in existing_vals:
                            existing_vals.append(v)
                    setattr(best_match, field, existing_vals)
                
                is_duplicate = True
                logger.debug(f"Merged LLM threat '{llm_threat.title}' with "
                           f"'{best_match.title}' (similarity: {best_similarity:.2f})")
            
            if not is_duplicate:
                merged.append(llm_threat)
        
        logger.info(f"Merged {len(rule_based_threats)} rule-based + {len(llm_threats)} LLM threats "
                    f"→ {len(merged)} total (removed {len(rule_based_threats) + len(llm_threats) - len(merged)} duplicates)")
        
        return merged
    
    @staticmethod
    def _compute_threat_similarity(threat1: Threat, threat2: Threat) -> float:
        """
        Compute similarity between two threats.
        Uses semantic embeddings when available, keyword overlap otherwise.
        """
        # Fast reject: different STRIDE categories are never duplicates
        cat1 = threat1.category.lower()
        cat2 = threat2.category.lower()
        if cat1 != cat2:
            # Allow related categories to still match
            related = {
                'spoofing': {'authentication'},
                'tampering': {'injection'},
                'information disclosure': {'data breach', 'eavesdropping'},
                'elevation of privilege': {'authorization', 'lateral movement'},
            }
            if cat2 not in related.get(cat1, set()) and cat1 not in related.get(cat2, set()):
                return 0.0
        
        if SEMANTIC_AVAILABLE:
            try:
                matcher = get_semantic_matcher()
                text1 = f"{threat1.title} {threat1.description}"
                text2 = f"{threat2.title} {threat2.description}"
                return matcher.compute_threat_similarity(text1, text2)
            except Exception:
                pass
        
        # Fallback: Enhanced keyword matching
        return LLMAnalyzer._keyword_similarity(threat1, threat2)
    
    @staticmethod
    def _keyword_similarity(threat1: Threat, threat2: Threat) -> float:
        """Keyword-based similarity (improved fallback)."""
        # Combine title and key words from description
        def get_keywords(threat: Threat) -> set:
            text = f"{threat.title} {threat.description[:200]}"
            words = set(text.lower().split())
            stop_words = {
                'the', 'a', 'an', 'in', 'on', 'at', 'to', 'for', 'of',
                'and', 'or', 'is', 'are', 'was', 'were', 'be', 'been',
                'with', 'from', 'by', 'as', 'it', 'its', 'that', 'this',
                'ai', 'potential', '[ai]', '[semantic]'
            }
            return words - stop_words
        
        words1 = get_keywords(threat1)
        words2 = get_keywords(threat2)
        
        if not words1 or not words2:
            return 0.0
        
        overlap = len(words1 & words2)
        union = len(words1 | words2)
        
        return overlap / union if union > 0 else 0.0
