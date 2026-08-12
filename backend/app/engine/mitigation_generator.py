from typing import Dict


MITIGATION_LIBRARY = {
    "missing_authentication": {
        "specific_control": "Strong API authentication and authorization",
        "implementation_detail": "Enforce OAuth2/OIDC or signed service-to-service identity at the entry point and require authorization checks on every resource access path.",
        "optional_config_example": "Example: reject unauthenticated requests at the API gateway and require scoped JWT validation in downstream services.",
    },
    "bola": {
        "specific_control": "Object-level authorization",
        "implementation_detail": "Check tenant, owner, and role constraints before every resource fetch or update instead of trusting client-supplied object identifiers.",
        "optional_config_example": "Example: enforce `WHERE tenant_id = caller.tenant_id` and deny access when owner or tenant context mismatches.",
    },
    "cleartext_flow": {
        "specific_control": "TLS for data in transit",
        "implementation_detail": "Require HTTPS or mTLS on the affected flow and disable plaintext listeners between trust boundaries.",
        "optional_config_example": "Example: terminate only TLS 1.2+ at the gateway and re-encrypt internal hops with service certificates.",
    },
    "unencrypted_storage": {
        "specific_control": "Encryption at rest with managed keys",
        "implementation_detail": "Enable native storage encryption and bind key usage to least-privilege workload identities.",
        "optional_config_example": "Example: use KMS-backed database encryption and rotate customer-managed keys on a defined schedule.",
    },
    "secrets_exposure": {
        "specific_control": "Dedicated secrets management",
        "implementation_detail": "Move credentials and tokens out of code, images, and flat config files into a secrets manager with rotation and access logging.",
        "optional_config_example": "Example: inject secrets at runtime from Vault or AWS Secrets Manager rather than environment files committed to source control.",
    },
    "supply_chain": {
        "specific_control": "Dependency and image provenance controls",
        "implementation_detail": "Pin dependency versions, verify signatures, and block builds when vulnerability or provenance checks fail.",
        "optional_config_example": "Example: require SBOM generation and signed container images before deployment promotion.",
    },
    "iam_misconfig": {
        "specific_control": "Least-privilege workload identity",
        "implementation_detail": "Scope IAM roles to the exact storage, queue, or API actions required by the component and remove wildcard permissions.",
        "optional_config_example": "Example: replace `s3:*` or `*:*` permissions with bucket-specific read/write actions only.",
    },
    "llm_prompt_injection": {
        "specific_control": "Prompt and tool isolation",
        "implementation_detail": "Separate untrusted retrieved content from tool instructions, require policy checks before tool execution, and constrain model outputs before actioning them.",
        "optional_config_example": "Example: place retrieved text in a quoted context block and run allowlisted tool-call authorization on each action request.",
    },
    "external_data_exposure": {
        "specific_control": "Outbound data minimization and egress policy",
        "implementation_detail": "Restrict sensitive fields before data leaves the trust boundary and explicitly approve which integrations may receive regulated or secret data.",
        "optional_config_example": "Example: mask PII fields before sending telemetry or third-party API payloads.",
    },
    "redis_missing_auth": {
        "specific_control": "Authenticated and isolated Redis session access",
        "implementation_detail": "Require Redis ACL credentials, TLS, private network access, key-prefix isolation, and rotation of session-signing material.",
        "optional_config_example": "Example: expose Redis only on a private subnet, require TLS and a least-privilege ACL user, and deny the default user.",
    },
    "redis_session_auth_unknown": {
        "specific_control": "Document and verify Redis session-store protections",
        "implementation_detail": "Confirm Redis ACL authentication, TLS, private subnet isolation, restricted security groups, and server-side session invalidation.",
        "optional_config_example": "Validation question: which workload identity and Redis ACL user authenticate each session-store client?",
    },
    "fhir_partner_authentication": {
        "specific_control": "Strong FHIR partner identity",
        "implementation_detail": "Require OAuth2 client credentials with strict issuer, audience, and scope validation; use mTLS or sender-constrained tokens for partner systems and authorize each FHIR resource operation.",
        "optional_config_example": "Example: map each partner certificate and OAuth client to permitted FHIR scopes and patient compartments.",
    },
    "oauth_token_lifecycle_unknown": {
        "specific_control": "OAuth token lifecycle and replay protection",
        "implementation_detail": "Use short access-token lifetimes, refresh-token rotation with reuse detection, revocation on security events, and step-up authentication for PHI access.",
        "optional_config_example": "Validation question: what invalidates active access and refresh tokens after logout, role change, password reset, or account disablement?",
    },
}


def generate_mitigation(threat: Dict) -> Dict[str, str]:
    template = MITIGATION_LIBRARY.get(threat.get("pattern"), {
        "specific_control": "Targeted compensating security control",
        "implementation_detail": "Implement a control at the boundary where the weakness appears and validate it with automated tests.",
        "optional_config_example": "Example: add a policy gate, schema validation, or identity check directly on the affected request path.",
    })
    return {
        "specific_control": template["specific_control"],
        "implementation_detail": template["implementation_detail"],
        "optional_config_example": template["optional_config_example"],
        "mitigation": f"{template['specific_control']}. {template['implementation_detail']}",
    }
