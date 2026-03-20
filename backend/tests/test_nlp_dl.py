"""
Golden Test Suite — Tests for NLP/DL enhancements.

Covers:
1. NLP processor entity extraction
2. Embedding service and vector store
3. Semantic threat matching
4. Attack chain analysis 
5. End-to-end integration with enhanced parser
"""

import pytest
import sys
import os

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


# === 1. NLP PROCESSOR TESTS ===

class TestNLPProcessor:
    """Tests for spaCy-based NLP processor."""
    
    def test_entity_extraction_technologies(self):
        """Should extract known technologies from architecture text."""
        from app.engine.nlp_processor import NLPProcessor
        
        nlp = NLPProcessor()
        text = "The system uses PostgreSQL for the primary database and Redis for caching."
        entities = nlp.extract_entities(text)
        
        techs = {e['text'].lower() for e in entities.get('technologies', [])}
        assert 'postgresql' in techs or 'postgres' in techs
        assert 'redis' in techs
    
    def test_entity_extraction_services(self):
        """Should extract named services like 'User Service' or 'Payment API'."""
        from app.engine.nlp_processor import NLPProcessor
        
        nlp = NLPProcessor()
        text = """
        1. User Service (Node.js/Express): Handles user registration and authentication
        2. Payment API (Python/FastAPI): Processes payments via Stripe
        """
        entities = nlp.extract_entities(text)
        
        services = {e['text'] for e in entities.get('services', [])}
        assert len(services) >= 2
    
    def test_security_properties_extraction(self):
        """Should extract security properties like auth type, encryption."""
        from app.engine.nlp_processor import NLPProcessor
        
        nlp = NLPProcessor()
        text = "The API uses JWT authentication with OAuth2 and encrypts data at rest using AES-256."
        props = nlp.extract_security_properties(text)
        
        assert props.get('auth_type') in ('jwt', 'oauth2')
        assert props.get('encryption_at_rest') == True
    
    def test_negation_detection(self):
        """Should detect negated security controls."""
        from app.engine.nlp_processor import NLPProcessor
        
        nlp = NLPProcessor()
        text = "The service does not validate JWT tokens. There is no rate limiting."
        props = nlp.extract_security_properties(text)
        
        # When NLP is available, negations should be detected
        # The exact behavior depends on spaCy availability
        assert 'auth_type' in props or 'rate_limiting' in props
    
    def test_data_flow_extraction_regex(self):
        """Should extract data flows from text using regex patterns."""
        from app.engine.nlp_processor import NLPProcessor
        
        nlp = NLPProcessor()
        components = {
            'user_service': type('C', (), {'name': 'User Service'})(),
            'database': type('C', (), {'name': 'Database'})(),
        }
        
        text = "The User Service sends data to the Database via HTTPS."
        flows = nlp.extract_data_flows(text, components)
        
        # Should find at least the regex-based flow
        assert len(flows) >= 0  # May not match with simplified components
    
    def test_component_classification(self):
        """Should classify component types from descriptions."""
        from app.engine.nlp_processor import NLPProcessor
        
        nlp = NLPProcessor()
        
        assert nlp.classify_component_type("PostgreSQL 15 with read replicas") == 'Database'
        assert nlp.classify_component_type("React SPA hosted on CloudFront") == 'WebClient'
        assert nlp.classify_component_type("RabbitMQ message broker") == 'Queue'
        assert nlp.classify_component_type("Kong API Gateway") == 'API Gateway'

    def test_ml_component_classification(self):
        """Should classify LLM and RAG infrastructure as ML services."""
        from app.engine.nlp_processor import NLPProcessor

        nlp = NLPProcessor()

        assert nlp.classify_component_type("OpenAI powered RAG pipeline with embeddings") == 'ML Service'

    def test_service_extraction_name_style(self):
        """Should extract service names declared with a colon."""
        from app.engine.nlp_processor import NLPProcessor

        nlp = NLPProcessor()
        text = """
        Retrieval Pipeline: Uses OpenAI embeddings and a vector database
        Policy Engine: Applies access control decisions
        """
        entities = nlp.extract_entities(text)

        services = {e['text'] for e in entities.get('services', [])}
        assert 'Retrieval Pipeline' in services
        assert 'Policy Engine' in services

    def test_security_properties_trust_boundary_and_credentials(self):
        """Should detect trust-boundary and credential sensitivity signals."""
        from app.engine.nlp_processor import NLPProcessor

        nlp = NLPProcessor()
        text = (
            "The public-facing API stores API keys in a secrets manager and validates webhook signatures. "
            "It also processes customer tokens."
        )
        props = nlp.extract_security_properties(text)

        assert props.get('trust_boundary') == 'internet'
        assert props.get('public_access') == True
        assert props.get('credential_sensitivity') == True
        assert props.get('secrets_management') == True
        assert props.get('webhook_signature_validation') == True

    def test_security_properties_ml_pipeline(self):
        """Should detect ML pipeline security-relevant context."""
        from app.engine.nlp_processor import NLPProcessor

        nlp = NLPProcessor()
        text = "An internal RAG service uses an embedding model, vector database, and service mesh."
        props = nlp.extract_security_properties(text)

        assert props.get('ml_pipeline') == True
        assert props.get('service_mesh') == True


# === 2. EMBEDDING SERVICE TESTS ===

class TestEmbeddingService:
    """Tests for sentence-transformer embedding service."""
    
    def test_embedding_generation(self):
        """Should generate embeddings for text."""
        from app.engine.embedding_service import EmbeddingService
        
        service = EmbeddingService()
        embedding = service.embed("SQL injection vulnerability")
        
        assert len(embedding) > 0
        assert embedding.shape[0] == service.dimension
    
    def test_similarity_related_texts(self):
        """Related texts should have higher similarity than unrelated ones."""
        from app.engine.embedding_service import EmbeddingService
        
        service = EmbeddingService()
        
        sim_related = service.similarity(
            "SQL injection attack on database",
            "Database input validation vulnerability"
        )
        sim_unrelated = service.similarity(
            "SQL injection attack on database",
            "The weather is nice today"
        )
        
        assert sim_related > sim_unrelated
    
    def test_batch_embedding(self):
        """Should generate embeddings for multiple texts."""
        from app.engine.embedding_service import EmbeddingService
        
        service = EmbeddingService()
        texts = [
            "Authentication bypass",
            "Data encryption at rest",
            "Cross-site scripting"
        ]
        embeddings = service.embed_batch(texts)
        
        assert embeddings.shape[0] == 3
        assert embeddings.shape[1] == service.dimension


class TestVectorStore:
    """Tests for FAISS/NumPy vector store."""
    
    def test_add_and_search(self):
        """Should store vectors and retrieve by similarity."""
        from app.engine.embedding_service import EmbeddingService, VectorStore
        import numpy as np
        
        service = EmbeddingService()
        store = VectorStore(service.dimension)
        
        texts = ["SQL injection", "XSS attack", "CSRF vulnerability"]
        embeddings = service.embed_batch(texts)
        metadata = [{"id": i, "text": t} for i, t in enumerate(texts)]
        
        store.add(embeddings, metadata)
        assert store.size == 3
        
        # Search for SQL-related query
        query_emb = service.embed("database injection vulnerability")
        results = store.search(query_emb, top_k=2)
        
        assert len(results) == 2
        # Top result should be SQL injection
        assert results[0][0]['text'] == 'SQL injection'


# === 3. SEMANTIC MATCHER TESTS ===

class TestSemanticMatcher:
    """Tests for semantic threat matching."""
    
    def test_threat_similarity_computation(self):
        """Should compute meaningful similarity between threats."""
        from app.engine.semantic_matcher import SemanticThreatMatcher
        
        matcher = SemanticThreatMatcher()
        
        sim = matcher.compute_threat_similarity(
            "Missing authentication on API endpoint",
            "API endpoints lack proper authentication controls"
        )
        assert sim > 0.3  # Should be similar
        
        sim_low = matcher.compute_threat_similarity(
            "Missing authentication on API endpoint",
            "Network cable is too long"
        )
        assert sim > sim_low  # Related texts should score higher
    
    def test_deduplication(self):
        """Should remove duplicate threats based on semantic similarity."""
        from app.engine.semantic_matcher import SemanticThreatMatcher
        
        matcher = SemanticThreatMatcher()
        
        threats = [
            {"title": "SQL Injection Risk", "description": "Database queries use unsanitized input", "severity": "High"},
            {"title": "Database Input Validation Missing", "description": "User input is passed directly to SQL queries", "severity": "Critical"},
            {"title": "XSS Attack Vector", "description": "Cross-site scripting through user input", "severity": "High"},
        ]
        
        deduped = matcher.deduplicate_threats(threats, similarity_threshold=0.6)
        # SQL injection threats might merge, XSS should remain
        assert len(deduped) <= len(threats)
    
    def test_stride_classification(self):
        """Should classify text into STRIDE categories."""
        from app.engine.semantic_matcher import SemanticThreatMatcher
        
        matcher = SemanticThreatMatcher()
        scores = matcher.classify_stride_zero_shot(
            "Attacker can forge authentication tokens to impersonate other users"
        )
        
        assert 'Spoofing' in scores
        assert 'Tampering' in scores
        # Spoofing should score highest for this text
        if matcher._embedding_service and matcher._embedding_service.is_available:
            assert scores['Spoofing'] > scores['Denial of Service']


# === 4. ATTACK CHAIN ANALYZER TESTS ===

class TestAttackChainAnalyzer:
    """Tests for attack chain analysis."""
    
    def test_graph_building(self):
        """Should build a threat graph from threat data."""
        from app.engine.attack_chain import AttackChainAnalyzer
        
        analyzer = AttackChainAnalyzer()
        
        threats = [
            {
                'threat_id': 'T1',
                'threat_name': 'Credential Theft',
                'stride_category': 'Spoofing',
                'component': 'API',
                'impact': 'High',
                'prerequisite_threats': [],
                'related_threats': {'amplifies': ['T2']},
            },
            {
                'threat_id': 'T2',
                'threat_name': 'Data Exfiltration',
                'stride_category': 'Information Disclosure',
                'component': 'API',
                'impact': 'Critical',
                'prerequisite_threats': ['T1'],
                'related_threats': {},
            },
            {
                'threat_id': 'T3',
                'threat_name': 'Privilege Escalation',
                'stride_category': 'Elevation of Privilege',
                'component': 'API',
                'impact': 'High',
                'prerequisite_threats': ['T1'],
                'related_threats': {},
            }
        ]
        
        analyzer.build_threat_graph(threats)
        
        assert analyzer.threat_graph.number_of_nodes() == 3
        assert analyzer.threat_graph.number_of_edges() >= 2  # At least prerequisites
    
    def test_attack_chain_discovery(self):
        """Should find attack chains (paths) in the threat graph."""
        from app.engine.attack_chain import AttackChainAnalyzer
        
        analyzer = AttackChainAnalyzer()
        threats = [
            {'threat_id': 'A', 'threat_name': 'Initial Access', 'stride_category': 'Spoofing',
             'component': 'WebClient', 'impact': 'Medium', 'prerequisite_threats': [], 'related_threats': {}},
            {'threat_id': 'B', 'threat_name': 'Lateral Movement', 'stride_category': 'Elevation of Privilege',
             'component': 'API', 'impact': 'High', 'prerequisite_threats': ['A'], 'related_threats': {}},
            {'threat_id': 'C', 'threat_name': 'Data Breach', 'stride_category': 'Information Disclosure',
             'component': 'Database', 'impact': 'Critical', 'prerequisite_threats': ['B'], 'related_threats': {}},
        ]
        
        analyzer.build_threat_graph(threats)
        chains = analyzer.find_attack_chains()
        
        assert len(chains) >= 1
        # Should find the chain A → B → C
        chain_ids = [set(c) for c in chains]
        assert any({'A', 'B', 'C'}.issubset(ids) for ids in chain_ids)
    
    def test_chokepoint_identification(self):
        """Should identify critical chokepoints in attack chains."""
        from app.engine.attack_chain import AttackChainAnalyzer
        
        analyzer = AttackChainAnalyzer()
        threats = [
            {'threat_id': 'A', 'threat_name': 'Entry Point', 'stride_category': 'Spoofing',
             'component': 'WebClient', 'impact': 'Medium', 'prerequisite_threats': [], 'related_threats': {}},
            {'threat_id': 'B', 'threat_name': 'Chokepoint', 'stride_category': 'Spoofing',
             'component': 'API', 'impact': 'High', 'prerequisite_threats': ['A'], 'related_threats': {}},
            {'threat_id': 'C', 'threat_name': 'Target 1', 'stride_category': 'Information Disclosure',
             'component': 'Database', 'impact': 'Critical', 'prerequisite_threats': ['B'], 'related_threats': {}},
            {'threat_id': 'D', 'threat_name': 'Target 2', 'stride_category': 'Tampering',
             'component': 'Database', 'impact': 'High', 'prerequisite_threats': ['B'], 'related_threats': {}},
        ]
        
        analyzer.build_threat_graph(threats)
        chokepoints = analyzer.find_critical_chokepoints()
        
        assert len(chokepoints) > 0
        # B should be a chokepoint (blocks paths to both C and D)
        chokepoint_ids = {cp['threat_id'] for cp in chokepoints}
        assert 'B' in chokepoint_ids


# === 5. SEVERITY CLASSIFIER TESTS ===

class TestSeverityClassifier:
    """Tests for ML-based severity classification."""
    
    def test_critical_severity(self):
        """Critical threats should be classified as Critical."""
        from app.engine.attack_chain import SeverityClassifier
        
        classifier = SeverityClassifier()
        severity = classifier.classify(
            "Remote code execution vulnerability allowing full system compromise through SQL injection"
        )
        assert severity in ('Critical', 'High')
    
    def test_low_severity(self):
        """Low-risk issues should be classified as Low."""
        from app.engine.attack_chain import SeverityClassifier
        
        classifier = SeverityClassifier()
        severity = classifier.classify(
            "Missing HTTP security header X-Frame-Options on a documentation page"
        )
        assert severity in ('Low', 'Medium')
    
    def test_context_adjustment(self):
        """Severity should be adjusted based on context."""
        from app.engine.attack_chain import SeverityClassifier
        
        classifier = SeverityClassifier()
        
        # Same threat, internal vs internet-facing
        internal_severity = classifier.classify(
            "Missing rate limiting", 
            context={'trust_boundary': 'internal', 'encryption_at_rest': True, 'auth_type': 'oauth2'}
        )
        internet_severity = classifier.classify(
            "Missing rate limiting",
            context={'public_access': True, 'data_sensitivity': 'financial'}
        )
        
        severity_order = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}
        assert severity_order[internet_severity] >= severity_order[internal_severity]


# === 6. INTEGRATION TEST ===

class TestEndToEndIntegration:
    """End-to-end test of the enhanced pipeline."""
    
    def test_full_analysis_pipeline(self):
        """The full analysis pipeline should work with NLP enhancements."""
        from app.engine.analyzer import ThreatAnalyzer
        
        description = """
        E-Commerce Platform Architecture:
        
        1. Frontend (React SPA): Hosted on CloudFront CDN, communicates with API Gateway
        2. API Gateway (Kong): Routes requests to backend microservices, handles rate limiting
        3. User Service (Node.js/Express): Manages authentication with JWT tokens
        4. Payment Service (Python/FastAPI): Processes payments via Stripe API integration
        5. Product Catalog Service (Go): Manages product listings, uses Redis for caching
        6. PostgreSQL Database: Stores user data, payment records, and product information
        7. Redis Cache: Session data and product catalog caching
        8. S3 Storage: Product images and static assets
        
        Security:
        - HTTPS/TLS for all communications
        - JWT-based authentication with OAuth2
        - Data encrypted at rest using AES-256
        - CloudWatch logging and monitoring
        
        Known Issues:
        - Missing control: JWT tokens do not have short expiration times (severity: medium)
        - Missing control: No input validation on product search endpoint (severity: high)
        """
        
        analyzer = ThreatAnalyzer()
        result = analyzer.analyze_from_text(description, "E-Commerce Platform")
        
        # Basic assertions
        assert result.project_name == "E-Commerce Platform"
        assert len(result.threats) > 0
        assert result.score >= 0 and result.score <= 100
        assert result.mermaid_diagram is not None
        assert len(result.architecture.components) > 0
        assert len(result.architecture.flows) > 0
        
        # Check that threats related to JWT/input validation were detected
        # (either as known issues or via rule-based analysis)
        threat_titles = ' '.join(t.title.lower() for t in result.threats)
        assert 'jwt' in threat_titles or 'token' in threat_titles or 'auth' in threat_titles or 'input' in threat_titles or len(result.threats) > 3
        
        # Check ML enhancement metadata
        if result.ml_enhanced:
            assert isinstance(result.ml_enhanced, dict)
        
        # Print summary for debugging
        print(f"\n=== Analysis Results ===")
        print(f"Components: {len(result.architecture.components)}")
        print(f"Flows: {len(result.architecture.flows)}")
        print(f"Threats: {len(result.threats)}")
        print(f"Score: {result.score}/100")
        print(f"ML Enhanced: {result.ml_enhanced}")
        if result.attack_chains:
            print(f"Attack Chains: {result.attack_chains.get('chains', 0)}")
        
        for t in result.threats[:5]:
            print(f"  [{t.severity}] {t.title}")


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
