"""
Semantic Threat Matcher — Uses embeddings + vector search to match
architecture components against the threat knowledge base.

Replaces brute-force rule iteration with:
1. Embedding-based retrieval (top-K relevant threats per component)
2. Zero-shot STRIDE classification
3. Semantic deduplication for LLM merge
"""

import logging
from typing import List, Dict, Tuple, Optional, Any

logger = logging.getLogger(__name__)

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False


class SemanticThreatMatcher:
    """
    Matches architecture components against threats using semantic similarity.
    Works alongside the existing rule engine — provides candidate threats
    that the rule engine might miss through keyword matching alone.
    """
    
    def __init__(self):
        self._kb_vectorized = False
        self._vector_store = None
        self._embedding_service = None
        self._initialize()
    
    def _initialize(self):
        """Initialize embedding service and vector store."""
        try:
            from .embedding_service import get_embedding_service, get_or_create_vector_store
            self._embedding_service = get_embedding_service()
            self._vector_store = get_or_create_vector_store(self._embedding_service.dimension)
            logger.info("Semantic threat matcher initialized")
        except Exception as e:
            logger.warning(f"Failed to initialize semantic threat matcher: {e}")
    
    def vectorize_knowledge_base(self, threats: List[Dict]):
        """
        Vectorize all threats in the knowledge base for semantic search.
        Should be called once at startup.
        """
        if self._kb_vectorized or not self._embedding_service or not self._vector_store:
            return
        
        if not threats:
            logger.warning("No threats to vectorize")
            return
        
        logger.info(f"Vectorizing {len(threats)} threats...")
        
        # Create rich text representations for each threat
        texts = []
        metadata = []
        
        for threat in threats:
            # Build a comprehensive text representation
            parts = [
                threat.get('threat_name', threat.get('threat', {}).get('title', '')),
                threat.get('description', threat.get('attack_vector', '')),
                threat.get('threat', {}).get('description', ''),
                f"Component: {threat.get('component', '')}",
                f"Category: {threat.get('stride_category', threat.get('category', ''))}",
                f"Severity: {threat.get('impact', threat.get('risk', {}).get('severity', ''))}",
            ]
            
            # Add tags if available
            tags = threat.get('tags', [])
            if tags:
                parts.append(f"Tags: {', '.join(tags)}")
            
            # Add mitigation info
            mitigations = threat.get('mitigations', [])
            if mitigations and isinstance(mitigations, list):
                for m in mitigations[:2]:  # Only first 2 to keep text manageable
                    if isinstance(m, dict):
                        parts.append(m.get('description', ''))
            
            text = ' '.join(filter(None, parts))
            texts.append(text)
            
            metadata.append({
                'threat_id': threat.get('threat_id', threat.get('id', '')),
                'threat_name': threat.get('threat_name', threat.get('threat', {}).get('title', '')),
                'component': threat.get('component', ''),
                'category': threat.get('stride_category', threat.get('category', '')),
                'severity': threat.get('impact', threat.get('risk', {}).get('severity', 'Medium')),
                'original': threat  # Keep reference to original
            })
        
        # Batch embed
        try:
            embeddings = self._embedding_service.embed_batch(texts)
            self._vector_store.add(embeddings, metadata)
            self._kb_vectorized = True
            logger.info(f"Vectorized {len(threats)} threats. Vector store size: {self._vector_store.size}")
        except Exception as e:
            logger.error(f"Failed to vectorize knowledge base: {e}")
    
    def find_relevant_threats(
        self, 
        component_description: str, 
        component_type: str = None,
        top_k: int = 15
    ) -> List[Tuple[Dict, float]]:
        """
        Find the most relevant threats for a component using semantic search.
        
        Args:
            component_description: Text describing the component and its context
            component_type: Optional component type filter
            top_k: Number of results to return
            
        Returns:
            List of (threat_metadata, similarity_score) tuples
        """
        if not self._embedding_service or not self._vector_store or self._vector_store.size == 0:
            return []
        
        # Build query text
        query_parts = [component_description]
        if component_type:
            query_parts.insert(0, f"Component type: {component_type}")
        query = ' '.join(query_parts)
        
        # Search
        try:
            query_embedding = self._embedding_service.embed(query)
            results = self._vector_store.search(query_embedding, top_k=top_k)
            
            # Filter by component type if specified
            if component_type:
                filtered = []
                for meta, score in results:
                    threat_component = meta.get('component', 'Any')
                    # Always include 'Any' type threats and matching types
                    if threat_component in ('Any', component_type) or score > 0.7:
                        filtered.append((meta, score))
                return filtered[:top_k]
            
            return results
        except Exception as e:
            logger.error(f"Semantic search failed: {e}")
            return []
    
    def find_threats_for_architecture(
        self,
        architecture_text: str,
        top_k: int = 20
    ) -> List[Tuple[Dict, float]]:
        """
        Find relevant threats for an entire architecture description.
        Useful for RAG — retrieving context for LLM prompts.
        """
        if not self._embedding_service or not self._vector_store or self._vector_store.size == 0:
            return []
        
        try:
            query_embedding = self._embedding_service.embed(architecture_text[:2000])  # Truncate long texts
            return self._vector_store.search(query_embedding, top_k=top_k)
        except Exception as e:
            logger.error(f"Architecture threat search failed: {e}")
            return []
    
    def compute_threat_similarity(self, threat1_text: str, threat2_text: str) -> float:
        """
        Compute semantic similarity between two threat descriptions.
        Used for deduplication.
        
        Returns:
            Similarity score between 0 and 1
        """
        if not self._embedding_service:
            return self._fallback_similarity(threat1_text, threat2_text)
        
        try:
            return self._embedding_service.similarity(threat1_text, threat2_text)
        except Exception as e:
            logger.error(f"Similarity computation failed: {e}")
            return self._fallback_similarity(threat1_text, threat2_text)
    
    def deduplicate_threats(
        self,
        threats: List[Dict],
        similarity_threshold: float = 0.75
    ) -> List[Dict]:
        """
        Remove duplicate/near-duplicate threats using semantic similarity.
        
        Args:
            threats: List of threat dicts with 'title' and 'description' keys
            similarity_threshold: Minimum similarity to consider as duplicate (0-1)
            
        Returns:
            Deduplicated list of threats with duplicates merged
        """
        if not threats:
            return []
        
        if len(threats) == 1:
            return threats
        
        # Create text representations
        texts = [
            f"{t.get('title', '')} {t.get('description', '')}" 
            for t in threats
        ]
        
        # Compute all pairwise similarities
        if self._embedding_service:
            try:
                embeddings = self._embedding_service.embed_batch(texts)
                # Pairwise cosine similarity matrix
                sim_matrix = embeddings @ embeddings.T
            except Exception:
                sim_matrix = self._fallback_similarity_matrix(texts)
        else:
            sim_matrix = self._fallback_similarity_matrix(texts)
        
        # Greedy deduplication — keep first occurrence, merge duplicates
        kept = []
        merged_indices = set()
        
        for i in range(len(threats)):
            if i in merged_indices:
                continue
            
            current = dict(threats[i])  # Copy
            
            # Find duplicates of current threat
            for j in range(i + 1, len(threats)):
                if j in merged_indices:
                    continue
                
                if NUMPY_AVAILABLE:
                    sim = float(sim_matrix[i][j])
                else:
                    sim = self._fallback_similarity(texts[i], texts[j])
                
                if sim >= similarity_threshold:
                    # Merge: keep higher severity, combine evidence
                    merged_indices.add(j)
                    duplicate = threats[j]
                    
                    # Keep higher severity
                    severity_order = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}
                    if severity_order.get(duplicate.get('severity', 'Low'), 0) > \
                       severity_order.get(current.get('severity', 'Low'), 0):
                        current['severity'] = duplicate.get('severity')
                    
                    # Combine evidence
                    existing_evidence = current.get('evidence', [])
                    new_evidence = duplicate.get('evidence', [])
                    if isinstance(existing_evidence, str):
                        existing_evidence = [existing_evidence]
                    if isinstance(new_evidence, str):
                        new_evidence = [new_evidence]
                    current['evidence'] = list(set(existing_evidence + new_evidence))
                    
                    # Note the merge
                    if 'merged_from' not in current:
                        current['merged_from'] = []
                    current['merged_from'].append(duplicate.get('id', duplicate.get('title', 'unknown')))
            
            kept.append(current)
        
        logger.info(f"Deduplication: {len(threats)} → {len(kept)} threats "
                    f"(removed {len(threats) - len(kept)} duplicates)")
        return kept
    
    def classify_stride(self, text: str) -> Dict[str, float]:
        """
        STRIDE classification using trained classifier (primary) or 
        zero-shot embedding similarity (fallback).
        
        Returns:
            Dict mapping STRIDE category to confidence score
        """
        # Try trained classifier first
        try:
            from .stride_classifier import get_stride_classifier
            classifier = get_stride_classifier()
            if classifier.is_trained:
                category, scores = classifier.predict(text)
                if scores:
                    return scores
        except Exception as e:
            logger.debug(f"Trained classifier not available: {e}")
        
        # Fallback to zero-shot embedding similarity
        return self._classify_stride_zero_shot(text)
    
    # Keep old name as alias for backward compat
    classify_stride_zero_shot = classify_stride
    
    def _classify_stride_zero_shot(self, text: str) -> Dict[str, float]:
        """Zero-shot STRIDE classification using embedding similarity (fallback)."""
        stride_descriptions = {
            'Spoofing': 'Identity spoofing, authentication bypass, credential theft, impersonation, unauthorized access through fake identity',
            'Tampering': 'Data tampering, code injection, parameter manipulation, unauthorized data modification, integrity violation',
            'Repudiation': 'Missing audit logs, untracked actions, no accountability, repudiable transactions, missing evidence',
            'Information Disclosure': 'Data leak, sensitive data exposure, information unauthorized access, privacy breach, credential exposure',
            'Denial of Service': 'Service unavailability, resource exhaustion, DDoS, flooding, crash, performance degradation',
            'Elevation of Privilege': 'Privilege escalation, unauthorized admin access, role bypass, permission elevation, root access'
        }
        
        if not self._embedding_service:
            return {cat: 0.0 for cat in stride_descriptions}
        
        try:
            text_emb = self._embedding_service.embed(text)
            
            scores = {}
            for category, desc in stride_descriptions.items():
                cat_emb = self._embedding_service.embed(desc)
                if NUMPY_AVAILABLE:
                    import numpy as np
                    scores[category] = float(np.dot(text_emb, cat_emb))
                else:
                    scores[category] = 0.0
            
            return scores
        except Exception as e:
            logger.error(f"Zero-shot classification failed: {e}")
            return {cat: 0.0 for cat in stride_descriptions}
    
    def _fallback_similarity(self, text1: str, text2: str) -> float:
        """Fallback similarity using Jaccard on word sets."""
        words1 = set(text1.lower().split())
        words2 = set(text2.lower().split())
        
        # Remove common stop words
        stop_words = {'the', 'a', 'an', 'in', 'on', 'at', 'to', 'for', 'of', 
                      'and', 'or', 'is', 'are', 'was', 'were', 'be', 'been',
                      'with', 'from', 'by', 'as', 'it', 'its', 'that', 'this'}
        words1 -= stop_words
        words2 -= stop_words
        
        if not words1 or not words2:
            return 0.0
        
        intersection = len(words1 & words2)
        union = len(words1 | words2)
        return intersection / union if union > 0 else 0.0
    
    def _fallback_similarity_matrix(self, texts: List[str]):
        """Build similarity matrix using fallback method."""
        n = len(texts)
        matrix = [[0.0] * n for _ in range(n)]
        for i in range(n):
            for j in range(n):
                if i == j:
                    matrix[i][j] = 1.0
                elif j > i:
                    sim = self._fallback_similarity(texts[i], texts[j])
                    matrix[i][j] = sim
                    matrix[j][i] = sim
        return matrix


# Global instance
_matcher_instance: Optional[SemanticThreatMatcher] = None

def get_semantic_matcher() -> SemanticThreatMatcher:
    """Get or create global semantic threat matcher."""
    global _matcher_instance
    if _matcher_instance is None:
        _matcher_instance = SemanticThreatMatcher()
    return _matcher_instance
