"""Whole-pipeline checks across the architecture shapes the tool is used on.

Each test analyzes one architecture and asserts what a reviewer would expect to
read in the report. They share the session analyzer rather than building one
each, because loading the knowledge base and the embedding index costs more than
every analysis in this file put together.
"""


class TestComprehensiveScenarios:
    """Extensive test cases covering various modern system architectures."""

    def test_complete_serverless_architecture(self, analyze):
        desc = (
            "AWS API Gateway routes requests to multiple AWS Lambda functions. "
            "Lambdas write and read data from DynamoDB and publish events to SNS. "
            "Authentication is handled by AWS Cognito. No WAF in front of API Gateway."
        )
        result = analyze(desc, "Serverless App")

        # The explicit missing WAF is reportable; other unknown controls stay
        # in the coverage matrix instead of becoming synthetic findings.
        assert result.stride_coverage["assessment_percent"] == 100.0
        assert not any("cleartext" in item.title.lower() for item in result.threats)
        assert result.engine_status["quality_gate"]["confirmed_without_evidence"] == 0
        titles = [t.title for t in result.threats]
        assert any("Missing Web Application Firewall" in t for t in titles)

    def test_microservices_with_service_mesh(self, analyze):
        desc = (
            "Kubernetes cluster with Istio service mesh. "
            "Frontend service talks to Auth service, Cart service, and Catalog service. "
            "All services communicate via mTLS. Cart service uses Redis, Catalog uses MongoDB. "
            "External traffic comes through an Ingress controller with a WAF."
        )
        result = analyze(desc, "Microservices App")

        # mTLS and WAF are stated controls; architecture complexity is not
        # evidence of a vulnerability.
        assert result.stride_coverage["assessment_percent"] == 100.0
        assert not any("cleartext" in item.title.lower() for item in result.threats)
        assert result.engine_status["quality_gate"]["confirmed_without_evidence"] == 0

    def test_iot_edge_architecture(self, analyze):
        desc = (
            "IoT devices collect sensor data and send it over MQTT to an Edge Gateway. "
            "Edge Gateway processes data locally and forwards aggregate metrics to a Cloud MQTT Broker over TLS. "
            "Cloud broker stores data in Time Series Database. "
            "No mutual authentication between IoT devices and Edge Gateway."
        )
        result = analyze(desc, "IoT App")

        assert len(result.threats) > 0
        # Unauthenticated devices are a spoofing problem before anything else.
        assert "Spoofing" in [t.category for t in result.threats]

    def test_heavy_data_pipeline(self, analyze):
        desc = (
            "Data pipeline using Apache Kafka for streaming events. "
            "Spark cluster consumes from Kafka and writes to a Data Lake (S3). "
            "Airflow schedules ETL jobs. BI tool (Tableau) connects directly to Data Lake. "
            "No data encryption at rest in S3."
        )
        result = analyze(desc, "Data Pipeline")

        assert len(result.threats) > 0

    def test_ai_ml_deployment(self, analyze):
        desc = (
            "User submits prompts via a React frontend to a FastAPI backend. "
            "Backend forwards prompts to an LLM running on a GPU instance. "
            "LLM outputs are sent back. No output validation or prompt sanitization."
        )
        result = analyze(desc, "AI App")

        assert len(result.threats) > 0
        titles = [t.title.lower() for t in result.threats]
        assert any("injection" in t for t in titles)
