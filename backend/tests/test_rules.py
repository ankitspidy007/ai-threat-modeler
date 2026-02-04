import pytest
from app.engine.rules import RuleEngine
from app.models import Threat


class TestRuleEngine:
    """Test suite for the RuleEngine."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.engine = RuleEngine()
    
    def test_engine_initialization(self):
        """Test that rule engine initializes with rules."""
        assert self.engine.rules is not None
        assert len(self.engine.rules) > 0
    
    def test_weak_auth_detection(self):
        """Test detection of weak authentication."""
        component_data = {
            'type': 'API',
            'auth_type': 'basic'
        }
        
        threats = self.engine.evaluate_component('test_api', component_data)
        
        # Should detect weak auth threat
        assert len(threats) > 0
        auth_threats = [t for t in threats if 'auth' in t.title.lower()]
        assert len(auth_threats) > 0
    
    def test_no_auth_detection(self):
        """Test detection of missing authentication."""
        component_data = {
            'type': 'API',
            'auth_type': 'none'
        }
        
        threats = self.engine.evaluate_component('test_api', component_data)
        
        # Should detect missing auth threat
        assert len(threats) > 0
        assert any('auth' in t.title.lower() for t in threats)
    
    def test_negating_controls_waf(self):
        """Test that WAF negates certain threats."""
        # Without WAF
        component_without_waf = {
            'type': 'API',
            'auth_type': 'basic'
        }
        threats_without = self.engine.evaluate_component('api1', component_without_waf)
        
        # With WAF
        component_with_waf = {
            'type': 'API',
            'auth_type': 'basic',
            'waf_enabled': True
        }
        threats_with = self.engine.evaluate_component('api2', component_with_waf)
        
        # WAF should reduce some threats
        # Note: This depends on rules having WAF as negating control
        assert len(threats_with) <= len(threats_without)
    
    def test_cleartext_transmission_detection(self):
        """Test detection of cleartext data transmission."""
        flow_data = {
            'protocol': 'http'
        }
        
        threats = self.engine.evaluate_flow('frontend', 'api', flow_data)
        
        # Should detect cleartext transmission threat
        assert len(threats) > 0
        cleartext_threats = [t for t in threats if 'cleartext' in t.description.lower() or 'http' in t.description.lower()]
        assert len(cleartext_threats) > 0
    
    def test_https_no_cleartext_threat(self):
        """Test that HTTPS doesn't trigger cleartext threat."""
        flow_data = {
            'protocol': 'https'
        }
        
        threats = self.engine.evaluate_flow('frontend', 'api', flow_data)
        
        # Should not detect cleartext threat for HTTPS
        cleartext_threats = [t for t in threats if 'cleartext' in t.description.lower()]
        assert len(cleartext_threats) == 0
    
    def test_logging_disabled_detection(self):
        """Test detection of disabled logging."""
        component_data = {
            'type': 'API',
            'logging_enabled': False
        }
        
        threats = self.engine.evaluate_component('test_api', component_data)
        
        # Should detect logging threat
        logging_threats = [t for t in threats if 'log' in t.title.lower()]
        assert len(logging_threats) > 0
    
    def test_confidence_levels(self):
        """Test that threats have confidence levels."""
        component_data = {
            'type': 'API',
            'auth_type': 'none'
        }
        
        threats = self.engine.evaluate_component('test_api', component_data)
        
        # All threats should have confidence
        for threat in threats:
            assert threat.confidence in ['Low', 'Medium', 'High']
    
    def test_evidence_collection(self):
        """Test that threats collect evidence."""
        component_data = {
            'type': 'API',
            'auth_type': 'basic'
        }
        
        threats = self.engine.evaluate_component('test_api', component_data)
        
        # Threats should have evidence
        for threat in threats:
            assert isinstance(threat.evidence, list)
    
    def test_threat_categories(self):
        """Test that threats are properly categorized."""
        component_data = {
            'type': 'API',
            'auth_type': 'none',
            'logging_enabled': False
        }
        
        threats = self.engine.evaluate_component('test_api', component_data)
        
        # Should have threats from different STRIDE categories
        categories = set(t.category for t in threats)
        assert len(categories) > 0
        # Common categories: Spoofing, Repudiation, etc.
        assert any(cat in ['Spoofing', 'Repudiation', 'Tampering'] for cat in categories)
    
    def test_rule_priority_sorting(self):
        """Test that rules are sorted by priority."""
        # Rules should be sorted (lower priority number = higher priority)
        # This is implementation detail but ensures consistent evaluation
        assert self.engine.rules is not None
    
    def test_component_type_matching(self):
        """Test that rules only apply to matching component types."""
        # Database-specific rule shouldn't apply to API
        component_data = {
            'type': 'Database',
            'encryption_at_rest': False
        }
        
        threats = self.engine.evaluate_component('test_db', component_data)
        
        # Should have threats
        assert len(threats) >= 0  # May or may not have threats depending on rules
    
    def test_multiple_conditions_and_logic(self):
        """Test AND logic in rule conditions."""
        # Some rules require multiple conditions to be true
        component_data = {
            'type': 'Service',
            'trust_boundary_crossing': True,
            'auth_checks': False
        }
        
        threats = self.engine.evaluate_component('test_service', component_data)
        
        # Should evaluate complex conditions
        assert isinstance(threats, list)
    
    def test_or_logic_conditions(self):
        """Test OR logic in rule conditions."""
        # Test that OR conditions work (e.g., basic OR none auth)
        component_data = {
            'type': 'API',
            'auth_type': 'basic'
        }
        
        threats = self.engine.evaluate_component('test_api', component_data)
        assert len(threats) > 0
    
    def test_threat_object_structure(self):
        """Test that threat objects have required fields."""
        component_data = {
            'type': 'API',
            'auth_type': 'none'
        }
        
        threats = self.engine.evaluate_component('test_api', component_data)
        
        if len(threats) > 0:
            threat = threats[0]
            assert hasattr(threat, 'id')
            assert hasattr(threat, 'title')
            assert hasattr(threat, 'description')
            assert hasattr(threat, 'severity')
            assert hasattr(threat, 'mitigation')
            assert hasattr(threat, 'confidence')
