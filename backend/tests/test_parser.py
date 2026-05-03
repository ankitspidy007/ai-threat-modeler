import pytest
from app.engine.parser import ArchitectureParser
from app.models import SystemArchitecture


class TestArchitectureParser:
    """Test suite for the ArchitectureParser."""
    
    def setup_method(self):
        """Setup test fixtures."""
        self.parser = ArchitectureParser()
    
    def test_basic_component_detection(self):
        """Test that basic components are detected."""
        text = "A web app with React frontend and PostgreSQL database"
        result = self.parser.parse(text)
        
        assert len(result.components) >= 2
        component_types = [c.type for c in result.components]
        assert 'WebClient' in component_types
        assert 'Database' in component_types
    
    def test_synonym_detection(self):
        """Test that synonyms are properly detected."""
        text = "System with MongoDB, REST API, and S3 bucket"
        result = self.parser.parse(text)
        
        component_types = [c.type for c in result.components]
        assert 'Database' in component_types  # MongoDB
        assert 'API' in component_types  # REST API
        assert 'Object Storage' in component_types  # S3
    
    def test_authentication_property_inference(self):
        """Test authentication property detection."""
        text = "API with JWT authentication"
        result = self.parser.parse(text)
        
        api_component = next((c for c in result.components if c.type == 'API'), None)
        assert api_component is not None
        assert api_component.properties.get('auth_type') == 'jwt'
        assert api_component.properties.get('has_jwt') is True
    
    def test_oauth_detection(self):
        """Test OAuth2 detection."""
        text = "Service using OAuth2 for authentication"
        result = self.parser.parse(text)
        
        service = next((c for c in result.components if c.type == 'Service'), None)
        assert service is not None
        assert service.properties.get('auth_type') == 'oauth2'
        assert service.properties.get('idp_integration') is True
    
    def test_no_auth_detection(self):
        """Test detection of missing authentication."""
        text = "Public API with no authentication"
        result = self.parser.parse(text)
        
        api = next((c for c in result.components if c.type == 'API'), None)
        assert api is not None
        assert api.properties.get('auth_type') == 'none'
    
    def test_encryption_detection(self):
        """Test encryption property detection."""
        text = "Database with encryption at rest and HTTPS for transit"
        result = self.parser.parse(text)
        
        db = next((c for c in result.components if c.type == 'Database'), None)
        assert db is not None
        assert db.properties.get('encryption_at_rest') is True
        assert db.properties.get('encryption_in_transit') is True
    
    def test_logging_detection(self):
        """Test logging property detection."""
        text = "API with CloudWatch logging enabled"
        result = self.parser.parse(text)
        
        api = next((c for c in result.components if c.type == 'API'), None)
        assert api is not None
        assert api.properties.get('logging_enabled') is True
        assert api.properties.get('centralized_logging') is True
    
    def test_security_controls_detection(self):
        """Test detection of security controls."""
        text = "API Gateway with WAF and rate limiting"
        result = self.parser.parse(text)
        
        gateway = next((c for c in result.components if c.type == 'API Gateway'), None)
        assert gateway is not None
        assert gateway.properties.get('waf_enabled') is True
        assert gateway.properties.get('rate_limiting') is True
    
    def test_data_sensitivity_detection(self):
        """Test data sensitivity classification."""
        text = "Database storing PII and payment information"
        result = self.parser.parse(text)
        
        db = next((c for c in result.components if c.type == 'Database'), None)
        assert db is not None
        # Should detect either PII or financial
        sensitivity = db.properties.get('data_sensitivity')
        assert sensitivity in ['pii', 'financial']
    
    def test_deployment_environment_detection(self):
        """Test deployment environment detection."""
        text = "Microservices deployed on Kubernetes"
        result = self.parser.parse(text)
        
        service = next((c for c in result.components if c.type == 'Service'), None)
        assert service is not None
        assert service.properties.get('deployment') == 'k8s'
    
    def test_flow_creation(self):
        """Test that data flows are created between components."""
        text = "Frontend connects to API which uses database"
        result = self.parser.parse(text)
        
        assert len(result.flows) > 0
        # Check that flows have source and target
        for flow in result.flows:
            assert flow.source_id is not None
            assert flow.target_id is not None
            assert isinstance(flow.assumed, bool)

    def test_architecture_modeling_enrichment(self):
        text = "Public React frontend sends patient data to a FastAPI service and PostgreSQL database with a Stripe integration"
        result = self.parser.parse(text)

        assert len(result.trust_boundaries) > 0
        assert len(result.assets) > 0
        assert any(component.trust_level in ['public', 'restricted', 'internal', 'external'] for component in result.components)
    
    def test_protocol_inference(self):
        """Test protocol inference for flows."""
        text = "Frontend uses HTTPS to connect to API"
        result = self.parser.parse(text)
        
        # Should have HTTPS protocol
        https_flows = [f for f in result.flows if f.protocol == 'https']
        assert len(https_flows) > 0
    
    def test_complex_architecture(self):
        """Test parsing of complex architecture description."""
        text = """
        E-commerce platform with:
        - React frontend (public-facing)
        - API Gateway with WAF and rate limiting
        - Node.js REST API with JWT authentication
        - PostgreSQL database with encryption at rest
        - Redis cache
        - S3 bucket for file storage
        - All deployed on Kubernetes with centralized logging
        """
        result = self.parser.parse(text)
        
        # Should detect multiple components
        assert len(result.components) >= 5
        
        # Check for key components
        component_types = [c.type for c in result.components]
        assert 'WebClient' in component_types
        assert 'API Gateway' in component_types
        assert 'API' in component_types
        assert 'Database' in component_types
        assert 'Object Storage' in component_types
    
    def test_empty_input(self):
        """Test handling of empty input."""
        result = self.parser.parse("")
        assert isinstance(result, SystemArchitecture)
        assert len(result.components) == 0
    
    def test_minimal_input(self):
        """Test handling of minimal input."""
        result = self.parser.parse("A simple web application")
        assert isinstance(result, SystemArchitecture)
        # Should at least detect web application
        assert len(result.components) >= 1
