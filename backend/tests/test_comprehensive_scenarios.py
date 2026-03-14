import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

class TestComprehensiveScenarios:
    """Extensive test cases covering various modern system architectures."""

    def test_complete_serverless_architecture(self):
        from app.engine.analyzer import ThreatAnalyzer
        desc = (
            "AWS API Gateway routes requests to multiple AWS Lambda functions. "
            "Lambdas write and read data from DynamoDB and publish events to SNS. "
            "Authentication is handled by AWS Cognito. No WAF in front of API Gateway."
        )
        analyzer = ThreatAnalyzer()
        result = analyzer.analyze_from_text(desc, "Serverless App")
        
        # Verify
        assert len(result.threats) > 0
        titles = [t.title for t in result.threats]
        assert any("Missing Web Application Firewall" in t for t in titles)

    def test_microservices_with_service_mesh(self):
        from app.engine.analyzer import ThreatAnalyzer
        desc = (
            "Kubernetes cluster with Istio service mesh. "
            "Frontend service talks to Auth service, Cart service, and Catalog service. "
            "All services communicate via mTLS. Cart service uses Redis, Catalog uses MongoDB. "
            "External traffic comes through an Ingress controller with a WAF."
        )
        analyzer = ThreatAnalyzer()
        result = analyzer.analyze_from_text(desc, "Microservices App")
        assert len(result.threats) > 0

    def test_iot_edge_architecture(self):
        from app.engine.analyzer import ThreatAnalyzer
        desc = (
            "IoT devices collect sensor data and send it over MQTT to an Edge Gateway. "
            "Edge Gateway processes data locally and forwards aggregate metrics to a Cloud MQTT Broker over TLS. "
            "Cloud broker stores data in Time Series Database. "
            "No mutual authentication between IoT devices and Edge Gateway."
        )
        analyzer = ThreatAnalyzer()
        result = analyzer.analyze_from_text(desc, "IoT App")
        assert len(result.threats) > 0
        titles = [t.title for t in result.threats]
        # Should catch spoofing risks for IoT devices
        categories = [t.category for t in result.threats]
        assert "Spoofing" in categories

    def test_heavy_data_pipeline(self):
        from app.engine.analyzer import ThreatAnalyzer
        desc = (
            "Data pipeline using Apache Kafka for streaming events. "
            "Spark cluster consumes from Kafka and writes to a Data Lake (S3). "
            "Airflow schedules ETL jobs. BI tool (Tableau) connects directly to Data Lake. "
            "No data encryption at rest in S3."
        )
        analyzer = ThreatAnalyzer()
        result = analyzer.analyze_from_text(desc, "Data Pipeline")
        assert len(result.threats) > 0

    def test_ai_ml_deployment(self):
        from app.engine.analyzer import ThreatAnalyzer
        desc = (
            "User submits prompts via a React frontend to a FastAPI backend. "
            "Backend forwards prompts to an LLM running on a GPU instance. "
            "LLM outputs are sent back. No output validation or prompt sanitization."
        )
        analyzer = ThreatAnalyzer()
        result = analyzer.analyze_from_text(desc, "AI App")
        assert len(result.threats) > 0
        titles = [t.title.lower() for t in result.threats]
        # Assuming the knowledge base handles Prompt Injection or related AI threats
        assert any("injection" in t for t in titles)
