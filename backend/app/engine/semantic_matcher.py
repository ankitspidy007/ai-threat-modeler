"""
Semantic Threat Matcher — Uses embeddings + vector search to match
architecture components against the threat knowledge base.

Replaces brute-force rule iteration with:
1. Embedding-based retrieval (top-K relevant threats per component)
2. Zero-shot STRIDE classification
3. Semantic deduplication for LLM merge
"""

import logging
import os
import re
from typing import List, Dict, Tuple, Optional, Any

logger = logging.getLogger(__name__)

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False


SECURITY_DOMAINS = {
    "aws", "azure", "gcp", "web_api", "identity", "data", "payments",
    "ai_llm", "agent_mcp", "container", "supply_chain", "general",
}
SPECIALIST_DOMAINS = {
    "aws", "azure", "gcp", "identity", "payments", "ai_llm", "agent_mcp",
    "container", "supply_chain",
}


class SecurityReranker:
    """Second-stage reranker with an optional cross-encoder and safe fallback."""

    def __init__(self):
        self.model_name = os.getenv("AEGIS_THREAT_RERANKER_MODEL", "").strip()
        self.model = None
        self.error = None
        if not self.model_name:
            return
        try:
            from sentence_transformers import CrossEncoder
            self.model = CrossEncoder(
                self.model_name, **model_policy.sentence_transformer_kwargs(self.model_name),
            )
            model_policy.note_model(self.model_name, "reranker", loaded=True)
        except Exception as exc:
            self.error = str(exc)
            model_policy.note_model(
                self.model_name, "reranker", loaded=False, error=str(exc),
                fallback="security_feature_reranker",
            )

    @property
    def backend(self) -> str:
        return "cross_encoder" if self.model is not None else "security_feature_reranker"

    def rerank(
        self,
        query: str,
        candidates: List[Tuple[Dict[str, Any], float]],
    ) -> List[Tuple[Dict[str, Any], float]]:
        if not candidates:
            return []
        cross_scores = None
        if self.model is not None:
            documents = [_retrieval_document(item[0].get("original") or item[0]) for item in candidates]
            try:
                cross_scores = self.model.predict([[query, document] for document in documents])
            except Exception as exc:
                logger.warning("Cross-encoder reranking failed: %s", exc)
        reranked = []
        query_tokens = _tokens(query)
        for index, (metadata, retrieval_score) in enumerate(candidates):
            original = metadata.get("original") or metadata
            document_tokens = _tokens(_retrieval_document(original))
            signal_terms = _tokens(" ".join(
                (original.get("applicability") or {}).get("required_signals") or []
            ))
            tag_terms = _tokens(" ".join(original.get("tags") or []))
            signal_overlap = _jaccard(query_tokens, signal_terms)
            tag_overlap = _jaccard(query_tokens, tag_terms)
            lexical_overlap = _jaccard(query_tokens, document_tokens)
            if cross_scores is not None:
                model_score = 1.0 / (1.0 + np.exp(-float(cross_scores[index])))
                score = retrieval_score * 0.55 + model_score * 0.45
            else:
                score = retrieval_score * 0.72 + lexical_overlap * 0.12 + signal_overlap * 0.1 + tag_overlap * 0.06
            enriched = dict(metadata)
            enriched["retrieval_score"] = round(float(retrieval_score), 6)
            enriched["reranker_backend"] = self.backend
            enriched["reranker_score"] = round(float(score), 6)
            reranked.append((enriched, max(0.0, min(1.0, float(score)))))
        return sorted(reranked, key=lambda item: item[1], reverse=True)


class SemanticThreatMatcher:
    """
    Matches architecture components against threats using semantic similarity.
    Works alongside the existing rule engine — provides candidate threats
    that the rule engine might miss through keyword matching alone.
    """
    
    def __init__(self):
        self._kb_vectorized = False
        self._vector_store = None
        self._domain_stores: Dict[str, Any] = {}
        self._embedding_service = None
        self._reranker = SecurityReranker()
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
            
            domains = _threat_domains(threat)
            metadata.append({
                'threat_id': threat.get('threat_id', threat.get('id', '')),
                'threat_name': threat.get('threat_name', threat.get('threat', {}).get('title', '')),
                'component': threat.get('component', ''),
                'category': threat.get('stride_category', threat.get('category', '')),
                'severity': threat.get('impact', threat.get('risk', {}).get('severity', 'Medium')),
                'domains': domains,
                'original': threat  # Keep reference to original
            })
        
        # Check if we can load from disk cache
        import hashlib
        import json
        import pickle
        from pathlib import Path
        
        try:
            # Create a simple hash of the threats to detect changes
            kb_summary = {
                "retrieval_schema": "security-domain-rerank-2.1",
                "threats": [
                    {
                        "id": t.get("id"), "title": t.get("title"),
                        "components": t.get("components"), "cloud": t.get("cloud_platform"),
                        "tags": t.get("tags"), "applicability": t.get("applicability"),
                    }
                    for t in threats
                ],
            }
            kb_hash = hashlib.md5(json.dumps(kb_summary, sort_keys=True).encode()).hexdigest()
            cache_dir = Path(__file__).parent.parent / "knowledge_base" / "cache"
            cache_dir.mkdir(exist_ok=True, parents=True)
            cache_file = cache_dir / f"kb_{kb_hash}.pkl"
            
            if cache_file.exists():
                with open(cache_file, 'rb') as f:
                    embeddings, cached_metadata = pickle.load(f)
                self._vector_store.add(embeddings, cached_metadata)
                self._build_domain_stores(embeddings, cached_metadata)
                self._kb_vectorized = True
                logger.info(f"Loaded {len(threats)} vectors from cache. Vector store size: {self._vector_store.size}")
                return
        except Exception as e:
            logger.warning(f"Cache check failed: {e}")
        
        # Batch embed
        try:
            embeddings = self._embedding_service.embed_batch(texts)
            self._vector_store.add(embeddings, metadata)
            self._build_domain_stores(embeddings, metadata)
            self._kb_vectorized = True
            
            # Save to cache
            try:
                if 'cache_file' in locals():
                    with open(cache_file, 'wb') as f:
                        pickle.dump((embeddings, metadata), f)
            except Exception as e:
                logger.warning(f"Failed to save embeddings cache: {e}")
                
            logger.info(f"Vectorized {len(threats)} threats. Vector store size: {self._vector_store.size}")
        except Exception as e:
            logger.error(f"Failed to vectorize knowledge base: {e}")

    def _build_domain_stores(self, embeddings, metadata: List[Dict[str, Any]]) -> None:
        """Build small domain indexes so unrelated security packs do not compete."""
        try:
            from .embedding_service import VectorStore
            grouped: Dict[str, Tuple[List[Any], List[Dict[str, Any]]]] = {}
            for index, item in enumerate(metadata):
                for domain in item.get("domains") or ["general"]:
                    vectors, records = grouped.setdefault(domain, ([], []))
                    vectors.append(embeddings[index])
                    records.append(item)
            self._domain_stores = {}
            for domain, (vectors, records) in grouped.items():
                store = VectorStore(self._embedding_service.dimension)
                store.add(np.asarray(vectors, dtype=np.float32), records)
                self._domain_stores[domain] = store
        except Exception as exc:
            logger.warning("Domain index construction failed: %s", exc)
            self._domain_stores = {}
    
    def find_relevant_threats(
        self, 
        component_description: str, 
        component_type: str = None,
        top_k: int = 15,
        stride_category: str = None,
        cloud_provider: str = None,
        security_domains: Optional[List[str]] = None,
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
            # Retrieve a wider semantic pool before applying hard metadata
            # filters; filtering only a tiny top-k can hide applicable rules.
            domains = set(security_domains or _query_domains(query, component_type, cloud_provider))
            stores = [self._domain_stores[name] for name in sorted(domains) if name in self._domain_stores]
            if not stores:
                stores = [self._vector_store]
            result_by_id: Dict[str, Tuple[Dict[str, Any], float]] = {}
            for store in stores:
                for meta, score in store.search(query_embedding, top_k=max(top_k * 6, 60)):
                    threat_id = meta.get("threat_id") or meta.get("threat_name")
                    current = result_by_id.get(threat_id)
                    if current is None or score > current[1]:
                        result_by_id[threat_id] = (meta, score)
            results = list(result_by_id.values())
            
            # Filter by component type if specified
            filtered = []
            query_tokens = _tokens(query)
            for meta, semantic_score in results:
                original = meta.get("original") or meta
                if component_type and not _component_filter_matches(original, component_type):
                    continue
                category = original.get("stride_category") or original.get("category")
                if stride_category and category != stride_category:
                    continue
                platforms = {str(item).lower() for item in original.get("cloud_platform") or []}
                if cloud_provider and platforms and cloud_provider.lower() not in platforms:
                    continue
                hard_negative_reasons = _hard_negative_reasons(
                    query, original, component_type, cloud_provider, domains,
                )
                if any(reason in hard_negative_reasons for reason in (
                    "incompatible_component", "incompatible_cloud", "unrelated_security_domain",
                )):
                    continue
                document = " ".join([
                    str(original.get("title") or original.get("threat_name") or ""),
                    str(original.get("description") or ""),
                    " ".join(original.get("tags") or []),
                    " ".join(original.get("components") or []),
                ])
                lexical = _jaccard(query_tokens, _tokens(document))
                component_bonus = 0.1 if component_type and _component_filter_matches(original, component_type, exact_only=True) else 0.0
                category_bonus = 0.1 if stride_category and category == stride_category else 0.0
                domain_bonus = 0.08 if domains & set(meta.get("domains") or []) else 0.0
                negative_penalty = min(0.35, 0.12 * len(hard_negative_reasons))
                hybrid_score = max(0.0, min(
                    1.0,
                    float(semantic_score) * 0.58 + lexical * 0.22
                    + component_bonus + category_bonus + domain_bonus - negative_penalty,
                ))
                enriched = dict(meta)
                enriched["semantic_score"] = float(semantic_score)
                enriched["lexical_score"] = lexical
                enriched["retrieval_scope"] = {
                    "component_type": component_type,
                    "stride_category": stride_category,
                    "cloud_provider": cloud_provider,
                    "security_domains": sorted(domains),
                }
                enriched["hard_negative_reasons"] = hard_negative_reasons
                filtered.append((enriched, hybrid_score))
            reranked = self._reranker.rerank(query, filtered)
            return reranked[:top_k]
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
            text = architecture_text or ""
            chunk_size = 1800
            overlap = 250
            chunks = []
            start = 0
            while start < len(text):
                chunks.append(text[start:start + chunk_size])
                start += chunk_size - overlap
            chunks = chunks or [""]

            best_by_id: Dict[str, Tuple[Dict, float]] = {}
            for chunk in chunks:
                query_embedding = self._embedding_service.embed(chunk)
                for metadata, score in self._vector_store.search(query_embedding, top_k=top_k):
                    threat_id = metadata.get("threat_id") or metadata.get("id") or metadata.get("threat_name")
                    current = best_by_id.get(threat_id)
                    if current is None or score > current[1]:
                        best_by_id[threat_id] = (metadata, score)
            return sorted(best_by_id.values(), key=lambda item: item[1], reverse=True)[:top_k]
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
        
        # Cache STRIDE embeddings on the instance to avoid re-computing per function call
        if not hasattr(self, '_stride_embeddings'):
            self._stride_embeddings = {}
            for category, desc in stride_descriptions.items():
                self._stride_embeddings[category] = self._embedding_service.embed(desc)
        
        try:
            text_emb = self._embedding_service.embed(text)
            
            scores = {}
            for category, cat_emb in self._stride_embeddings.items():
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


def _component_filter_matches(threat: Dict[str, Any], component_type: str, exact_only: bool = False) -> bool:
    expected = threat.get("components") or threat.get("component") or ["Any"]
    if isinstance(expected, str):
        expected = [expected]
    normalized_expected = {_normalize_type(value) for value in expected}
    normalized_actual = _normalize_type(component_type)
    if "any" in normalized_expected or normalized_actual in normalized_expected:
        return True
    if exact_only:
        return False
    aliases = {
        "api gateway": {"api", "load balancer"},
        "webclient": {"web application", "frontend", "client"},
        "ml service": {"llm", "ai agent", "rag", "model"},
        "container platform": {"kubernetes", "container", "k8s"},
        "database": {"data store", "sql database", "nosql database"},
        "object storage": {"storage", "cloud storage", "file storage", "bucket"},
        "data flow": {"flow", "interaction", "communication"},
    }
    compatible = aliases.get(normalized_actual, set())
    return bool(normalized_expected & compatible)


def _retrieval_document(threat: Dict[str, Any]) -> str:
    applicability = threat.get("applicability") or {}
    return " ".join(filter(None, [
        str(threat.get("title") or threat.get("threat_name") or ""),
        str(threat.get("description") or ""),
        " ".join(threat.get("tags") or []),
        " ".join(threat.get("components") or []),
        " ".join(threat.get("cloud_platform") or []),
        " ".join(threat.get("cloud_services") or []),
        " ".join(applicability.get("required_signals") or []),
        " ".join(applicability.get("excluded_signals") or []),
    ]))


def _threat_domains(threat: Dict[str, Any]) -> List[str]:
    text = _retrieval_document(threat).lower()
    domains = set()
    mappings = {
        "aws": ("aws", "amazon", "s3", "lambda", "dynamodb", "cloudtrail", "kms", "iam", "ec2"),
        "azure": ("azure", "entra", "key vault", "aks", "blob storage"),
        "gcp": ("gcp", "google cloud", "vertex", "gke", "bigquery", "cloud run"),
        "web_api": ("api", "graphql", "sql injection", "xss", "ssrf", "csrf", "web"),
        "identity": ("identity", "oauth", "oidc", "saml", "jwt", "session", "authentication", "authorization"),
        "data": ("database", "storage", "postgres", "mongo", "redis", "encryption", "data leak"),
        "payments": ("payment", "stripe", "refund", "webhook", "pci", "cardholder"),
        "ai_llm": ("llm", "prompt injection", "model", "rag", "vector store", "inference"),
        "agent_mcp": ("agent", "mcp", "tool call", "tool execution", "memory service"),
        "container": ("kubernetes", "k8s", "container", "pod", "service account", "docker"),
        "supply_chain": ("supply chain", "dependency", "artifact", "image signature", "ci/cd", "registry"),
    }
    for domain, terms in mappings.items():
        if any(_contains_term(text, term) for term in terms):
            domains.add(domain)
    return sorted((domains or {"general"}) & SECURITY_DOMAINS)


def _query_domains(query: str, component_type: Optional[str], cloud_provider: Optional[str]) -> List[str]:
    synthetic = {
        "title": query,
        "description": component_type or "",
        "cloud_platform": [cloud_provider] if cloud_provider else [],
    }
    return _threat_domains(synthetic)


def _hard_negative_reasons(
    query: str,
    threat: Dict[str, Any],
    component_type: Optional[str],
    cloud_provider: Optional[str],
    query_domains: set[str],
) -> List[str]:
    reasons = []
    expected_components = {_normalize_type(item) for item in threat.get("components") or []}
    if component_type and expected_components and "any" not in expected_components:
        if not _component_filter_matches(threat, component_type):
            reasons.append("incompatible_component")
    platforms = {str(item).lower() for item in threat.get("cloud_platform") or []}
    if cloud_provider and platforms and cloud_provider.lower() not in platforms:
        reasons.append("incompatible_cloud")
    threat_domains = set(_threat_domains(threat)) - {"general"}
    scoped_query_domains = query_domains - {"general"}
    threat_specialists = threat_domains & SPECIALIST_DOMAINS
    query_specialists = scoped_query_domains & SPECIALIST_DOMAINS
    if threat_specialists and not threat_specialists & query_specialists:
        reasons.append("unrelated_security_domain")
    elif threat_domains and scoped_query_domains and not threat_domains & scoped_query_domains:
        reasons.append("unrelated_security_domain")
    excluded = (threat.get("applicability") or {}).get("excluded_signals") or []
    lowered_query = query.lower()
    if any(str(signal).lower() in lowered_query for signal in excluded if signal):
        reasons.append("negating_signal_present")
    return reasons


def _contains_term(text: str, term: str) -> bool:
    return bool(re.search(r"(?<![a-z0-9])" + re.escape(term.lower()) + r"(?![a-z0-9])", text))


def _normalize_type(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(value or "").lower()).strip()


def _tokens(value: str) -> set[str]:
    return {
        token for token in re.findall(r"[a-z0-9]+", value.lower())
        if len(token) > 2 and token not in {"the", "and", "for", "with", "from", "component", "service"}
    }


def _jaccard(left: set[str], right: set[str]) -> float:
    return len(left & right) / len(left | right) if left and right else 0.0


# Global instance
_matcher_instance: Optional[SemanticThreatMatcher] = None

def get_semantic_matcher() -> SemanticThreatMatcher:
    """Get or create global semantic threat matcher."""
    global _matcher_instance
    if _matcher_instance is None:
        _matcher_instance = SemanticThreatMatcher()
    return _matcher_instance


def reset_semantic_matcher():
    """Reset the semantic matcher so embeddings/indexes can be rebuilt."""
    global _matcher_instance
    _matcher_instance = None
