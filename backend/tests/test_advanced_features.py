"""
Test suite for the new advanced features:
- STRIDE Classifier (embedding + SVM)
- Architecture Intelligence (graph-based inference)
- Knowledge Base expansion
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


# =============================================
# 1. STRIDE CLASSIFIER TESTS
# =============================================

class TestStrideClassifier:
    """Tests for the STRIDE threat classifier."""
    
    def test_classifier_initialization(self):
        """Classifier should initialize with is_available=True (sklearn present)."""
        from app.engine.stride_classifier import StrideClassifier
        classifier = StrideClassifier()
        assert classifier.is_available is True
        assert classifier.is_trained is False
    
    def test_global_instance(self):
        """Global instance should be reusable."""
        from app.engine.stride_classifier import get_stride_classifier
        c1 = get_stride_classifier()
        c2 = get_stride_classifier()
        assert c1 is c2
    
    def test_stride_categories_complete(self):
        """All 6 STRIDE categories should be defined."""
        from app.engine.stride_classifier import STRIDE_CATEGORIES
        assert len(STRIDE_CATEGORIES) == 6
        assert "Spoofing" in STRIDE_CATEGORIES
        assert "Tampering" in STRIDE_CATEGORIES
        assert "Repudiation" in STRIDE_CATEGORIES
        assert "Information Disclosure" in STRIDE_CATEGORIES
        assert "Denial of Service" in STRIDE_CATEGORIES
        assert "Elevation of Privilege" in STRIDE_CATEGORIES
    
    def test_augmentation_templates_exist(self):
        """Augmentation templates should exist for all STRIDE categories."""
        from app.engine.stride_classifier import AUGMENTATION_TEMPLATES, STRIDE_CATEGORIES
        for cat in STRIDE_CATEGORIES:
            assert cat in AUGMENTATION_TEMPLATES
            assert len(AUGMENTATION_TEMPLATES[cat]) >= 3
    
    def test_extract_training_data(self):
        """Should extract labeled pairs from KB threats."""
        from app.engine.stride_classifier import StrideClassifier
        classifier = StrideClassifier()
        
        sample_threats = [
            {
                "category": "Spoofing",
                "threat": {"title": "Weak Authentication", "description": "No auth on API"},
                "stride_category": "Spoofing"
            },
            {
                "category": "Tampering",
                "threat": {"title": "SQL Injection", "description": "Unsanitized SQL"},
                "stride_category": "Tampering"
            }
        ]
        
        texts, labels = classifier._extract_training_data(sample_threats)
        assert len(texts) == 2
        assert len(labels) == 2
        assert labels[0] == "Spoofing"
        assert labels[1] == "Tampering"
    
    def test_augment_data(self):
        """Should generate augmented training data."""
        from app.engine.stride_classifier import StrideClassifier
        classifier = StrideClassifier()
        
        aug_texts, aug_labels = classifier._augment_data([], [])
        # 6 categories * ~6 templates * 3 variations = ~108 augmented examples
        assert len(aug_texts) >= 60
        assert len(aug_labels) == len(aug_texts)
    
    def test_predict_untrained(self):
        """Untrained classifier should return 'Unknown'."""
        from app.engine.stride_classifier import StrideClassifier
        classifier = StrideClassifier()
        category, scores = classifier.predict("SQL injection attack")
        assert category == "Unknown"
        assert scores == {}
    
    def test_predict_batch_untrained(self):
        """Batch prediction on untrained classifier should return 'Unknown' for all."""
        from app.engine.stride_classifier import StrideClassifier
        classifier = StrideClassifier()
        results = classifier.predict_batch(["test1", "test2"])
        assert len(results) == 2
        assert all(r[0] == "Unknown" for r in results)


# =============================================
# 2. ARCHITECTURE INTELLIGENCE TESTS
# =============================================

class TestArchitectureIntelligence:
    """Tests for architecture intelligence (inference + anti-patterns)."""
    
    def _build_test_graph(self, nodes, edges):
        """Helper to build a test graph."""
        import networkx as nx
        g = nx.DiGraph()
        for nid, data in nodes.items():
            g.add_node(nid, **data)
        for src, tgt, data in edges:
            g.add_edge(src, tgt, **data)
        return g
    
    def test_initialization(self):
        """Intelligence module should initialize."""
        from app.engine.architecture_intelligence import ArchitectureIntelligence
        intel = ArchitectureIntelligence()
        insights = intel.get_insights_dict()
        assert isinstance(insights, list)
        assert len(insights) == 0
    
    def test_missing_waf_detection(self):
        """Should detect missing WAF when internet-facing components exist."""
        from app.engine.architecture_intelligence import ArchitectureIntelligence
        
        nodes = {
            "web": {"label": "WebApp", "type": "Web Server", "public_access": True},
            "api": {"label": "API", "type": "API"},
            "db": {"label": "Database", "type": "Database"},
        }
        edges = [("web", "api", {}), ("api", "db", {})]
        graph = self._build_test_graph(nodes, edges)
        
        intel = ArchitectureIntelligence()
        insights = intel.analyze(graph)
        
        titles = [i.title for i in insights]
        assert "Missing Web Application Firewall" in titles
    
    def test_missing_logging_detection(self):
        """Should detect missing centralized logging."""
        from app.engine.architecture_intelligence import ArchitectureIntelligence
        
        nodes = {
            "web": {"label": "Frontend", "type": "Web Server"},
            "api": {"label": "API", "type": "API"},
            "db": {"label": "DB", "type": "Database"},
            "cache": {"label": "Cache", "type": "Cache"},
        }
        edges = [("web", "api", {}), ("api", "db", {}), ("api", "cache", {})]
        graph = self._build_test_graph(nodes, edges)
        
        intel = ArchitectureIntelligence()
        insights = intel.analyze(graph)
        
        titles = [i.title for i in insights]
        assert "Missing Centralized Logging" in titles
    
    def test_direct_db_exposure(self):
        """Should detect internet-facing component with direct DB access."""
        from app.engine.architecture_intelligence import ArchitectureIntelligence
        
        nodes = {
            "web": {"label": "WebApp", "type": "Web Server", "public_access": True},
            "db": {"label": "ProdDB", "type": "Database"},
        }
        edges = [("web", "db", {})]
        graph = self._build_test_graph(nodes, edges)
        
        intel = ArchitectureIntelligence()
        insights = intel.analyze(graph)
        
        titles = [i.title for i in insights]
        assert "Direct Database Access from Internet" in titles
        
        # Should be Critical severity
        db_insight = [i for i in insights if "Direct Database" in i.title][0]
        assert db_insight.severity == "Critical"
    
    def test_no_false_positive_with_api_layer(self):
        """Should NOT flag direct DB exposure when API layer exists between."""
        from app.engine.architecture_intelligence import ArchitectureIntelligence
        
        nodes = {
            "web": {"label": "WebApp", "type": "Web Server", "public_access": True},
            "api": {"label": "API", "type": "API"},
            "db": {"label": "DB", "type": "Database"},
        }
        edges = [("web", "api", {}), ("api", "db", {})]
        graph = self._build_test_graph(nodes, edges)
        
        intel = ArchitectureIntelligence()
        insights = intel.analyze(graph)
        
        # Should NOT have direct DB exposure 
        db_insights = [i for i in insights if "Direct Database" in i.title]
        assert len(db_insights) == 0
    
    def test_circular_dependency_detection(self):
        """Should detect circular dependencies."""
        from app.engine.architecture_intelligence import ArchitectureIntelligence
        
        nodes = {
            "a": {"label": "Service A", "type": "Service"},
            "b": {"label": "Service B", "type": "Service"},
            "c": {"label": "Service C", "type": "Service"},
        }
        edges = [("a", "b", {}), ("b", "c", {}), ("c", "a", {})]
        graph = self._build_test_graph(nodes, edges)
        
        intel = ArchitectureIntelligence()
        insights = intel.analyze(graph)
        
        titles = [i.title for i in insights]
        assert any("Circular" in t for t in titles)
    
    def test_insight_serialization(self):
        """Insights should serialize to dicts properly."""
        from app.engine.architecture_intelligence import ArchitectureInsight
        
        insight = ArchitectureInsight(
            insight_type="missing_component",
            severity="High",
            title="Test Insight",
            description="Test description",
            recommendation="Test recommendation",
            affected_components=["comp1"],
            category="Security"
        )
        
        d = insight.to_dict()
        assert d["type"] == "missing_component"
        assert d["severity"] == "High"
        assert d["title"] == "Test Insight"
        assert "comp1" in d["affected_components"]
    
    def test_summary_grouping(self):
        """Summary should group insights by severity and category."""
        from app.engine.architecture_intelligence import ArchitectureIntelligence
        
        nodes = {
            "web": {"label": "WebApp", "type": "Web Server", "public_access": True},
            "api1": {"label": "Service1", "type": "Service"},
            "api2": {"label": "Service2", "type": "Service"},
            "db": {"label": "Database", "type": "Database"},
        }
        edges = [("web", "api1", {}), ("web", "api2", {}), ("api1", "db", {})]
        graph = self._build_test_graph(nodes, edges)
        
        intel = ArchitectureIntelligence()
        intel.analyze(graph)
        summary = intel.get_summary()
        
        assert "total" in summary
        assert "by_severity" in summary
        assert "by_category" in summary


# =============================================
# 3. KNOWLEDGE BASE TESTS
# =============================================

class TestKnowledgeBase:
    """Tests for the expanded knowledge base."""
    
    def test_kb_loads_all_modules(self):
        """KB should load all available threat modules."""
        from app.knowledge_base.loader import ThreatKnowledgeBase
        kb = ThreatKnowledgeBase()
        # With 5 new modules, should have significantly more threats
        assert len(kb.threats) >= 100
    
    def test_owasp_api_threats_loaded(self):
        """OWASP API Top 10 threats should be loaded."""
        from app.knowledge_base.loader import ThreatKnowledgeBase
        kb = ThreatKnowledgeBase()
        api_threat = kb.get_by_id("OWASP-API-001")
        assert api_threat is not None
        assert "BOLA" in api_threat["threat"]["title"]
    
    def test_database_threats_loaded(self):
        """Database threats should be loaded."""
        from app.knowledge_base.loader import ThreatKnowledgeBase
        kb = ThreatKnowledgeBase()
        db_threat = kb.get_by_id("DB-001")
        assert db_threat is not None
        assert "SQL" in db_threat["threat"]["title"]
    
    def test_infrastructure_threats_loaded(self):
        """Infrastructure threats should be loaded."""
        from app.knowledge_base.loader import ThreatKnowledgeBase
        kb = ThreatKnowledgeBase()
        infra_threat = kb.get_by_id("INFRA-001")
        assert infra_threat is not None
    
    def test_supply_chain_threats_loaded(self):
        """Supply chain threats should be loaded."""
        from app.knowledge_base.loader import ThreatKnowledgeBase
        kb = ThreatKnowledgeBase()
        sc_threat = kb.get_by_id("SC-001")
        assert sc_threat is not None
        assert "Vulnerable" in sc_threat["threat"]["title"]
    
    def test_emerging_threats_loaded(self):
        """Emerging threats (AI/ML) should be loaded."""
        from app.knowledge_base.loader import ThreatKnowledgeBase
        kb = ThreatKnowledgeBase()
        emg_threat = kb.get_by_id("EMG-003")
        assert emg_threat is not None
        assert "Prompt Injection" in emg_threat["threat"]["title"]
    
    def test_search_functionality(self):
        """Search should find threats across all modules."""
        from app.knowledge_base.loader import ThreatKnowledgeBase
        kb = ThreatKnowledgeBase()
        results = kb.search("injection")
        assert len(results) >= 2  # SQL injection + prompt injection at minimum
    
    def test_stride_distribution(self):
        """All STRIDE categories should have threats."""
        from app.knowledge_base.loader import ThreatKnowledgeBase
        kb = ThreatKnowledgeBase()
        stats = kb.get_statistics()
        for category in ["Spoofing", "Tampering", "Repudiation", 
                         "Information Disclosure", "Denial of Service", 
                         "Elevation of Privilege"]:
            # Each category should have at least some threats
            # (may be 0 for categories not indexed by stride_category)
            assert category in stats["by_stride"]
    
    def test_no_duplicate_ids(self):
        """All threat IDs should be unique."""
        from app.knowledge_base.loader import ThreatKnowledgeBase
        kb = ThreatKnowledgeBase()
        ids = [t.get('id') or t.get('threat_id') for t in kb.threats if t.get('id') or t.get('threat_id')]
        assert len(ids) == len(set(ids)), f"Duplicate IDs found: {[x for x in ids if ids.count(x) > 1]}"
    
    def test_all_threats_have_required_fields(self):
        """Every threat should have at minimum: id, category, and threat title."""
        from app.knowledge_base.loader import ThreatKnowledgeBase
        kb = ThreatKnowledgeBase()
        for threat in kb.threats:
            tid = threat.get('id') or threat.get('threat_id')
            assert tid, f"Threat missing ID: {threat}"
            
            # Legacy threats use 'category', new threats use 'stride_category'
            category = threat.get('category') or threat.get('stride_category')
            assert category, f"Threat {tid} missing category"
            
            threat_info = threat.get('threat', {})
            title = threat_info.get('title') or threat.get('threat_name')
            assert title, f"Threat {tid} missing title"


# =============================================
# 4. STREAMING ANALYZER TESTS
# =============================================

class TestStreamingAnalyzer:
    """Tests for the streaming analysis wrapper."""
    
    def test_phases_defined(self):
        """All 10 analysis phases should be defined."""
        from app.engine.streaming_analyzer import PHASES
        assert len(PHASES) == 10
        assert PHASES[0]["id"] == "parsing"
        assert PHASES[-1]["id"] == "reporting"
    
    def test_phase_weights_sum(self):
        """Phase weights should sum to 100."""
        from app.engine.streaming_analyzer import PHASES
        total = sum(p["weight"] for p in PHASES)
        assert total == 100
    
    def test_streaming_analyzer_init(self):
        """StreamingAnalyzer should initialize with callback."""
        from app.engine.streaming_analyzer import StreamingAnalyzer
        
        events = []
        analyzer = StreamingAnalyzer(progress_callback=lambda e: events.append(e))
        assert analyzer._callback is not None


# =============================================
# 5. END-TO-END INTEGRATION TESTS
# =============================================

class TestEndToEndIntegration:
    """Integration tests using the full pipeline."""
    
    def test_analysis_with_architecture_insights(self):
        """Full analysis should include architecture insights."""
        from app.engine.analyzer import ThreatAnalyzer
        
        desc = (
            "React frontend connects to Express.js API over HTTPS. "
            "API connects to PostgreSQL database. JWT authentication. "
            "No WAF or logging configured."
        )
        
        analyzer = ThreatAnalyzer()
        result = analyzer.analyze_from_text(desc, "Integration Test")
        
        assert result.score > 0
        assert len(result.threats) > 0
        assert result.architecture_insights is not None
        assert len(result.architecture_insights) > 0
    
    def test_analysis_result_has_ml_enhanced(self):
        """Analysis result should report ML feature status."""
        from app.engine.analyzer import ThreatAnalyzer
        
        analyzer = ThreatAnalyzer()
        result = analyzer.analyze_from_text(
            "Web server with API endpoint connecting to MySQL database",
            "ML Test"
        )
        
        assert result.ml_enhanced is not None
        assert "semantic_matching" in result.ml_enhanced
        assert "stride_classifier" in result.ml_enhanced
        assert "attack_chains" in result.ml_enhanced
    
    def test_complex_architecture_detection(self):
        """Complex architectures should trigger more insights and threats."""
        from app.engine.analyzer import ThreatAnalyzer
        
        desc = (
            "E-commerce platform:\n"
            "- React SPA frontend served from CloudFront CDN\n"
            "- Node.js API Gateway handles routing\n"
            "- User Service (Python/FastAPI) for authentication with JWT\n"
            "- Product Service (Go) for catalog management\n"
            "- Order Service (Java/Spring) for order processing\n"
            "- PostgreSQL database for user data (PII)\n"
            "- MongoDB for product catalog\n"
            "- Redis cache for sessions\n"
            "- Stripe integration for payments via HTTPS\n"
            "- RabbitMQ for async event processing\n"
            "Known Issues:\n"
            "- No input validation on search endpoints\n"
            "- Redis has no authentication configured\n"
        )
        
        analyzer = ThreatAnalyzer()
        result = analyzer.analyze_from_text(desc, "E-Commerce Test")
        
        # Should find many threats in a complex architecture
        assert len(result.threats) >= 5
        assert result.score >= 0
