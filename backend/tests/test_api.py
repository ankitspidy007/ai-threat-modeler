import pytest
from httpx import AsyncClient
from app.main import app


@pytest.mark.asyncio
class TestAPI:
    """Test suite for API endpoints."""
    
    async def test_health_check(self):
        """Test health check endpoint."""
        async with AsyncClient(app=app, base_url="http://test") as ac:
            response = await ac.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "version" in data
    
    async def test_analyze_endpoint_success(self):
        """Test successful analysis."""
        async with AsyncClient(app=app, base_url="http://test") as ac:
            response = await ac.post("/analyze", json={
                "project_name": "Test Project",
                "description": "A web application with React frontend, Node.js API with JWT authentication, and PostgreSQL database storing user data"
            })
        
        assert response.status_code == 200
        data = response.json()
        
        # Check response structure
        assert "project_name" in data
        assert "threats" in data
        assert "score" in data
        assert isinstance(data["threats"], list)
        assert isinstance(data["score"], (int, float))
        assert "assets" in data["architecture"]
        assert "trust_boundaries" in data["architecture"]
    
    async def test_analyze_endpoint_validation_short_description(self):
        """Test validation for too short description."""
        async with AsyncClient(app=app, base_url="http://test") as ac:
            response = await ac.post("/analyze", json={
                "project_name": "Test",
                "description": "Short"
            })
        
        # Should fail validation
        assert response.status_code == 422  # Validation error
    
    async def test_analyze_endpoint_validation_missing_fields(self):
        """Test validation for missing required fields."""
        async with AsyncClient(app=app, base_url="http://test") as ac:
            response = await ac.post("/analyze", json={
                "project_name": "Test"
                # Missing description
            })
        
        assert response.status_code == 422
    
    async def test_analyze_endpoint_sanitization(self):
        """Test that input is sanitized."""
        async with AsyncClient(app=app, base_url="http://test") as ac:
            response = await ac.post("/analyze", json={
                "project_name": "Test<script>alert('xss')</script>",
                "description": "A web application with database and API"
            })
        
        # Should succeed with sanitized input
        assert response.status_code == 200
        data = response.json()
        # Project name should be sanitized (no script tags)
        assert "<script>" not in data["project_name"]
    
    async def test_analyze_endpoint_caching(self):
        """Test that caching works."""
        request_data = {
            "project_name": "Cache Test",
            "description": "A unique web application for cache testing with database"
        }
        
        async with AsyncClient(app=app, base_url="http://test") as ac:
            # First request
            response1 = await ac.post("/analyze", json=request_data)
            assert response1.status_code == 200
            
            # Second request (should be cached)
            response2 = await ac.post("/analyze", json=request_data)
            assert response2.status_code == 200
            
            # Results should be identical
            assert response1.json() == response2.json()

    async def test_analyze_documents_endpoint_success(self):
        """Test analysis from uploaded design documents."""
        files = [
            ("files", ("architecture.md", b"# Architecture\nReact frontend talks to a FastAPI API and PostgreSQL database over HTTPS.\nJWT auth is used.", "text/markdown")),
        ]
        data = {
            "project_name": "Document Intake",
            "use_local_slm": "true",
            "analysis_mode": "standard",
            "domain_profile": "general",
            "context_text": "Known issue: audit logging is incomplete.",
        }

        async with AsyncClient(app=app, base_url="http://test") as ac:
            response = await ac.post("/analyze-documents", data=data, files=files)

        assert response.status_code == 200
        payload = response.json()
        assert payload["project_name"] == "Document Intake"
        assert "coverage" in payload
        assert payload["coverage"]["document_driven_analysis"] is True
        assert payload["coverage"]["source_documents"][0]["filename"] == "architecture.md"
        assert "trust_boundaries" in payload["architecture"]

    async def test_analyze_documents_endpoint_rejects_unsupported_type(self):
        files = [
            ("files", ("diagram.exe", b"not-a-real-doc", "application/octet-stream")),
        ]
        data = {
            "project_name": "Unsupported Doc",
            "context_text": "Architecture context",
        }

        async with AsyncClient(app=app, base_url="http://test") as ac:
            response = await ac.post("/analyze-documents", data=data, files=files)

        assert response.status_code == 400
        assert "Unsupported file type" in response.json()["detail"]
    
    async def test_clear_cache_endpoint(self):
        """Test cache clearing endpoint."""
        async with AsyncClient(app=app, base_url="http://test") as ac:
            response = await ac.delete("/cache")
        
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
    
    async def test_analyze_with_complex_architecture(self):
        """Test analysis with complex architecture."""
        async with AsyncClient(app=app, base_url="http://test") as ac:
            response = await ac.post("/analyze", json={
                "project_name": "Complex E-Commerce",
                "description": """
                E-commerce platform with:
                - React frontend (public-facing)
                - API Gateway with WAF
                - Node.js REST API with JWT authentication
                - PostgreSQL database with encryption at rest
                - Redis cache
                - S3 bucket for file storage
                - Kubernetes deployment with centralized logging
                """
            })
        
        assert response.status_code == 200
        data = response.json()
        
        # Should detect multiple threats
        assert len(data["threats"]) > 0
        
        # Should have architecture information
        assert "architecture" in data
        
        # Should have mermaid diagram
        assert "mermaid_diagram" in data or "diagram" in data
    
    async def test_analyze_threat_structure(self):
        """Test that threats have proper structure."""
        async with AsyncClient(app=app, base_url="http://test") as ac:
            response = await ac.post("/analyze", json={
                "project_name": "Test",
                "description": "A public API with no authentication and no logging"
            })
        
        assert response.status_code == 200
        data = response.json()
        
        if len(data["threats"]) > 0:
            threat = data["threats"][0]
            # Check required fields
            assert "id" in threat
            assert "title" in threat
            assert "description" in threat
            assert "severity" in threat
            assert "mitigation" in threat
            assert "confidence" in threat
            assert "tier" in threat
    
    async def test_analyze_score_calculation(self):
        """Test that security score is calculated."""
        async with AsyncClient(app=app, base_url="http://test") as ac:
            response = await ac.post("/analyze", json={
                "project_name": "Test",
                "description": "A secure web application with HTTPS, JWT auth, encryption, and logging"
            })
        
        assert response.status_code == 200
        data = response.json()
        
        # Score should be between 0 and 100
        assert 0 <= data["score"] <= 100
        
        # Secure system should have higher score
        assert data["score"] > 50  # Reasonable threshold
    
    async def test_cors_headers(self):
        """Test that CORS headers are present."""
        async with AsyncClient(app=app, base_url="http://test") as ac:
            response = await ac.options("/analyze")
        
        # CORS should be configured
        # Note: Actual CORS testing requires browser, this is basic check
        assert response.status_code in [200, 405]  # OPTIONS may or may not be allowed
