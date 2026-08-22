import re

import pytest

from app.engine.analyzer import ThreatAnalyzer


SCENARIOS = [
    (
        "aws_multi_account",
        """An AWS Organization uses production and analytics accounts. Route 53 sends customers to CloudFront and WAF, then a public ALB and EKS. Cognito protects API Gateway and Lambda. EKS uses IRSA to access Aurora PostgreSQL, DynamoDB, ElastiCache Redis, S3, KMS, Secrets Manager, SQS, SNS, EventBridge and Step Functions. AWS Glue writes an S3 lake queried by Athena. GitHub Actions pushes to ECR and Argo CD deploys to EKS. Stripe webhooks enter API Gateway.
KNOWN ISSUES:
- The ALB remains directly internet reachable, allowing requests to bypass CloudFront WAF.
- The partner API accepts Cognito ID tokens as API access tokens and does not validate the audience.
- A vendor cross-account role trusts any principal in the vendor AWS account and requires no ExternalId.
- An EKS node group still permits IMDSv1 and application pods can reach instance metadata.
- The checkout IRSA role grants kms:Decrypt on every key and does not restrict the encryption context.
- The analytics bucket policy allows the production account root principal to read every object.
- SQS dead-letter queue retention is shorter than source queue retention and poison messages are not alarmed.
- GitHub Actions references third-party actions by mutable version tags instead of commit SHA.
- ECR image signatures and admission verification are not enforced.
- Stripe webhook signatures are not verified before order fulfillment.""",
        {
            "AWS-ORIGIN-WAF-BYPASS-001", "AUTH-OIDC-TOKEN-CONFUSION-001",
            "AWS-IAM-CONFUSED-DEPUTY-001", "AWS-EC2-IMDS-CREDENTIAL-EXPOSURE-001",
            "AWS-KMS-BROAD-DECRYPT-001", "AWS-S3-CROSS-ACCOUNT-POLICY-001",
            "QUEUE-DLQ-RETENTION-MONITORING-001", "SUPPLY-CHAIN-UNPINNED-ACTION-001",
            "CONTAINER-IMAGE-PROVENANCE-001", "PAYMENT-WEBHOOK-SIGNATURE-001",
        },
        {"eventbridge", "step_functions", "glue", "athena", "vendor_cross_account_role"},
    ),
    (
        "enterprise_saas",
        """A public React SPA uses a Node.js GraphQL gateway on Kubernetes. Tenants use SAML identity providers or Okta OIDC and SCIM endpoints. The gateway calls account, project, search, export, notification, audit, and billing microservices over mTLS. PostgreSQL uses row-level security, Elasticsearch indexes documents, Redis caches authorization, Kafka carries events, S3 stores exports, Stripe handles subscriptions and customers configure outbound webhooks. Support engineers can impersonate tenant administrators.
KNOWN ISSUES:
- The SAML ACS endpoint selects the tenant from an unsigned RelayState value and accepts assertions without enforcing InResponseTo.
- The PostgreSQL application role owns the RLS-protected tables and can bypass row-level security.
- Elasticsearch searches apply the tenant filter supplied by the browser rather than the authenticated tenant context.
- Redis authorization cache keys contain user ID and resource ID but omit tenant ID.
- Failed SCIM deprovisioning events are retried for only one hour and then silently discarded.
- Customer webhook URLs are fetched without blocking private, loopback, link-local, or metadata addresses.
- CSV exports allow cells beginning with =, +, -, or @ without neutralization.
- Support impersonation requires no approval and actions are logged as the customer, not the support operator.
- Audit records in PostgreSQL can be updated or deleted by the application service account.
- GraphQL field-level authorization is missing on project.billingDetails.
- Stripe webhook events are processed without idempotency protection.""",
        {
            "AUTH-SAML-RESPONSE-BINDING-001", "DATA-POSTGRES-RLS-OWNER-BYPASS-001",
            "SAAS-SEARCH-TENANT-ISOLATION-001", "SAAS-CACHE-TENANT-COLLISION-001",
            "AUTH-SCIM-DEPROVISIONING-FAILURE-001", "WEB-SSRF-CALLBACK-001",
            "EXPORT-CSV-FORMULA-INJECTION-001", "AUTH-SUPPORT-IMPERSONATION-001",
            "AUDIT-LOG-MUTABILITY-001", "API-GRAPHQL-FIELD-AUTHORIZATION-001",
            "PAYMENT-IDEMPOTENCY-001",
        },
        {"saml_identity", "scim_endpoint", "search_service", "export_service", "audit_service", "billing_service"},
    ),
    (
        "autonomous_ai",
        """A React console behind Cloudflare calls AWS API Gateway. Keycloak federates Azure AD. Kubernetes runs an agent orchestrator, policy service, workflow service and memory service. It selects Azure OpenAI, Bedrock or a self-hosted model and performs RAG over Pinecone. OCR and parsing workers ingest S3 uploads through SQS. Agents call GitHub, Jira, Salesforce, PostgreSQL, browser, filesystem and shell MCP servers. A code execution service runs Kubernetes jobs. Agents deploy through Argo CD and trigger Stripe refunds. DynamoDB stores memory and traces go to a third-party observability SaaS. A human approval service protects consequential actions. GitHub Actions builds images into ECR. Cross-cloud secrets are synchronized from Secrets Manager to Key Vault.
KNOWN ISSUES:
- Retrieved documents and GitHub issue text are inserted into the agent context without marking them untrusted or separating instructions from data.
- Pinecone namespaces are selected from a tenant_id supplied in the request body.
- The orchestrator forwards the user's OAuth access token to every MCP server, including third-party MCP servers.
- MCP server identity is not pinned and tool manifests may change after approval.
- The approval screen displays an AI-generated summary but not the exact tool name or arguments; execution arguments can change after approval.
- The shell execution pod mounts the host Docker socket and runs privileged with a writable hostPath.
- The browser tool does not revalidate redirects or DNS resolution, allowing SSRF and DNS rebinding.
- Tool output is checked only for valid JSON, not authorization, data classification, or business invariants.
- Agent loops have no token, tool-call, time, or spend budget.
- The fallback self-hosted model does not apply the policy checks used for Azure OpenAI and Bedrock.
- Long-term memory stores secrets and has no tenant-scoped deletion workflow.
- Prompt and tool traces containing credentials are sent to the observability vendor without redaction.
- Uploaded source archives are extracted without path traversal checks or malware quarantine.
- GitHub Actions are referenced by mutable tags and build provenance is not verified at admission.
- Stripe refunds trust the amount proposed by the model without server-side invoice validation or idempotency keys.
- The cross-cloud secret synchronization identity can read every AWS secret and write every Azure Key Vault secret.""",
        {
            "AI-INDIRECT-PROMPT-INJECTION-001", "AI-RAG-TENANT-ISOLATION-001",
            "MCP-OAUTH-TOKEN-DELEGATION-001", "MCP-SERVER-IDENTITY-001",
            "AI-AGENT-APPROVAL-TOCTOU-001", "K8S-PRIVILEGED-HOSTPATH-001",
            "WEB-SSRF-DNS-REBINDING-001", "AI-TOOL-OUTPUT-POLICY-001",
            "AI-AGENT-RESOURCE-EXHAUSTION-001", "AI-MODEL-POLICY-PARITY-001",
            "AI-MEMORY-SECRET-RETENTION-001", "AI-SENSITIVE-TELEMETRY-001",
            "UPLOAD-ARCHIVE-EXTRACTION-001", "SUPPLY-CHAIN-UNPINNED-ACTION-001",
            "PAYMENT-AI-REFUND-INTEGRITY-001", "CLOUD-SECRET-SYNC-OVERPRIVILEGE-001",
        },
        {"agent_orchestrator", "policy_service", "memory_service", "code_execution_service", "approval_service", "observability_vendor", "self_hosted_model", "mcp_browser"},
    ),
]


def canonical_id(value):
    return re.sub(r"-(?:K\d+|\d{2})$", "", value)


@pytest.mark.slow
@pytest.mark.parametrize("name,description,expected_ids,expected_components", SCENARIOS)
def test_advanced_holdout_is_classified_scoped_and_publishable(name, description, expected_ids, expected_components):
    result = ThreatAnalyzer().analyze_from_text(description, name, use_local_slm=True, analysis_mode="deep")
    confirmed = [item for item in result.threats if item.tier == "Confirmed"]
    actual_ids = {canonical_id(item.id) for item in confirmed}
    component_ids = {item.id for item in result.architecture.components}
    quality = result.engine_status["quality_gate"]

    assert expected_ids <= actual_ids
    assert expected_components <= component_ids
    assert all(item.affected_stride_categories for item in confirmed)
    assert all(item.affected_components for item in confirmed)
    assert not any(item.id.startswith("UNCLASSIFIED-") for item in confirmed)
    assert quality["unclassified_known_issues"] == 0
    assert quality["confirmed_unmapped_findings"] == 0
    assert quality["omitted_named_components"] == 0
    assert quality["duplicate_component_aliases"] == 0
    assert quality["publication_status"] != "blocked"
