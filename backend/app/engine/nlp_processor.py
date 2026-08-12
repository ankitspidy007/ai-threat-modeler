"""
Hybrid NLP processor for architecture descriptions.

This module intentionally avoids a hard dependency on spaCy and instead uses:
- blingfire for fast sentence splitting when available
- regex and domain dictionaries as the primary extraction engine
- optional transformers pipeline for targeted NER enrichment

The public API is kept compatible with the previous NLPProcessor so the rest of
the analyzer can use the same methods without change.
"""

import logging
import os
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    from blingfire import text_to_sentences

    BLINGFIRE_AVAILABLE = True
except Exception:
    BLINGFIRE_AVAILABLE = False
    logger.warning("blingfire not available. Falling back to regex sentence splitting.")

try:
    from transformers import pipeline

    TRANSFORMERS_AVAILABLE = True
except Exception:
    TRANSFORMERS_AVAILABLE = False
    logger.warning("transformers not available. Named-entity enrichment will be disabled.")


NER_MODEL = os.getenv("AEGIS_THREAT_NER_MODEL", "dslim/bert-base-NER")

TECH_COMPONENT_MAP = {
    "postgresql": "Database",
    "postgres": "Database",
    "mysql": "Database",
    "mongodb": "Database",
    "mongo": "Database",
    "redis": "Database",
    "dynamodb": "Database",
    "cassandra": "Database",
    "mariadb": "Database",
    "oracle": "Database",
    "mssql": "Database",
    "cosmosdb": "Database",
    "firestore": "Database",
    "documentdb": "Database",
    "elasticsearch": "Database",
    "opensearch": "Database",
    "snowflake": "Database",
    "redshift": "Database",
    "bigquery": "Database",
    "sqlite": "Database",
    "cockroachdb": "Database",
    "neo4j": "Database",
    "influxdb": "Database",
    "timescaledb": "Database",
    "supabase": "Database",
    "planetscale": "Database",
    "neon": "Database",
    "turso": "Database",
    "valkey": "Database",
    "dragonfly": "Database",
    "dragonflydb": "Database",
    "memcached": "Database",
    "couchdb": "Database",
    "rethinkdb": "Database",
    "vector database": "Database",
    "vector db": "Database",
    "vector store": "Database",
    "pinecone": "Database",
    "weaviate": "Database",
    "qdrant": "Database",
    "milvus": "Database",
    "express": "API",
    "fastapi": "API",
    "django": "API",
    "flask": "API",
    "spring boot": "API",
    "spring": "API",
    "rails": "API",
    "laravel": "API",
    "gin": "API",
    "fiber": "API",
    "actix": "API",
    "nest": "API",
    "nestjs": "API",
    "graphql": "API",
    "rest api": "API",
    "grpc": "API",
    "api server": "API",
    "web service": "API",
    "koa": "API",
    "hapi": "API",
    "adonisjs": "API",
    "node.js": "API",
    "nodejs": "API",
    "llm gateway": "API Gateway",
    "react": "WebClient",
    "vue": "WebClient",
    "angular": "WebClient",
    "svelte": "WebClient",
    "next.js": "WebClient",
    "nextjs": "WebClient",
    "nuxt": "WebClient",
    "gatsby": "WebClient",
    "remix": "WebClient",
    "astro": "WebClient",
    "spa": "WebClient",
    "frontend": "WebClient",
    "mobile app": "WebClient",
    "ios": "WebClient",
    "android": "WebClient",
    "flutter": "WebClient",
    "react native": "WebClient",
    "kiosk": "WebClient",
    "nginx": "Load Balancer",
    "haproxy": "Load Balancer",
    "alb": "Load Balancer",
    "nlb": "Load Balancer",
    "elb": "Load Balancer",
    "traefik": "Load Balancer",
    "kong": "API Gateway",
    "apigee": "API Gateway",
    "api gateway": "API Gateway",
    "aws api gateway": "API Gateway",
    "azure api management": "API Gateway",
    "service mesh": "Service",
    "istio": "Service",
    "linkerd": "Service",
    "kafka": "Queue",
    "rabbitmq": "Queue",
    "sqs": "Queue",
    "sns": "Queue",
    "pubsub": "Queue",
    "nats": "Queue",
    "mqtt": "Queue",
    "activemq": "Queue",
    "celery": "Queue",
    "bull": "Queue",
    "sidekiq": "Queue",
    "s3": "Object Storage",
    "azure blob": "Object Storage",
    "gcs": "Object Storage",
    "minio": "Object Storage",
    "cloudflare r2": "Object Storage",
    "aws kms": "Key Management",
    "kms": "Key Management",
    "route 53": "DNS",
    "route53": "DNS",
    "eks": "Container Platform",
    "ecr": "Container Registry",
    "rds": "Database",
    "aurora": "Database",
    "elasticache": "Database",
    "cloudfront": "CDN",
    "cloudflare": "CDN",
    "akamai": "CDN",
    "fastly": "CDN",
    "auth0": "Identity Provider",
    "okta": "Identity Provider",
    "cognito": "Identity Provider",
    "keycloak": "Identity Provider",
    "azure ad": "Identity Provider",
    "firebase auth": "Identity Provider",
    "datadog": "Monitoring",
    "splunk": "Monitoring",
    "grafana": "Monitoring",
    "prometheus": "Monitoring",
    "new relic": "Monitoring",
    "elk": "Monitoring",
    "cloudwatch": "Monitoring",
    "sentry": "Monitoring",
    "lambda": "Service",
    "ec2": "Compute",
    "cloud function": "Service",
    "azure function": "Service",
    "github actions": "CI/CD",
    "argo cd": "CI/CD",
    "argocd": "CI/CD",
    "github mcp": "MCP Server",
    "jira mcp": "MCP Server",
    "salesforce mcp": "MCP Server",
    "mcp server": "MCP Server",
    "shell executor": "Tool",
    "filesystem": "Tool",
    "iot device": "IoT Device",
    "sensor": "IoT Device",
    "medical device": "IoT Device",
    "smart device": "IoT Device",
    "guardduty": "Threat Detection",
    "security hub": "Threat Detection",
    "waf": "Threat Detection",
    "vault": "Secrets Manager",
    "key vault": "Secrets Manager",
    "secrets manager": "Secrets Manager",
    "openai": "ML Service",
    "azure openai": "ML Service",
    "anthropic": "ML Service",
    "claude": "ML Service",
    "gemini": "ML Service",
    "vertex ai": "ML Service",
    "sagemaker": "ML Service",
    "bedrock": "ML Service",
    "ollama": "ML Service",
    "llm": "ML Service",
    "rag": "ML Service",
    "embedding model": "ML Service",
    "model serving": "ML Service",
    "orchestration agent": "ML Service",
}

FLOW_VERBS = {
    "send",
    "sends",
    "sent",
    "transmit",
    "transmits",
    "forward",
    "forwards",
    "connect",
    "connects",
    "connected",
    "communicate",
    "communicates",
    "query",
    "queries",
    "queried",
    "read",
    "reads",
    "write",
    "writes",
    "call",
    "calls",
    "invoke",
    "invokes",
    "fetch",
    "fetches",
    "push",
    "pushes",
    "pull",
    "pulls",
    "store",
    "stores",
    "stored",
    "route",
    "routes",
    "routed",
    "redirect",
    "redirects",
    "authenticate",
    "authenticates",
    "authorize",
    "authorizes",
    "publish",
    "publishes",
    "subscribe",
    "subscribes",
    "consume",
    "consumes",
    "upload",
    "uploads",
    "download",
    "downloads",
    "stream",
    "streams",
    "proxy",
    "proxies",
    "cache",
    "caches",
    "replicate",
    "replicates",
}

PROTOCOL_INDICATORS = {
    "https": "HTTPS",
    "http": "HTTP",
    "grpc": "gRPC",
    "graphql": "GraphQL",
    "websocket": "WebSocket",
    "ws": "WebSocket",
    "wss": "WebSocket",
    "tcp": "TCP",
    "tls": "HTTPS",
    "ssl": "HTTPS",
    "mqtt": "MQTT",
    "amqp": "AMQP",
    "rest": "HTTPS",
    "ssh": "SSH",
    "sftp": "SFTP",
}

SERVICE_NAME_PATTERNS = [
    r"(?:^|\n)\s*(?:\d+\.|-|\*)\s+([A-Z][A-Za-z0-9/&\-\s]+?(?:Service|API|Gateway|Worker|Job|Handler|Manager|Controller|Processor|Engine|Store|Database|Cache|Agent|Pipeline))\s*(?:\(([^)]+)\))?",
    r"(?:^|\n)\s*([A-Z][A-Za-z0-9/&\-\s]+?(?:Service|API|Gateway|Worker|Job|Handler|Manager|Controller|Processor|Engine|Store|Database|Cache|Agent|Pipeline))\s*:\s*([^\n]+)",
]


class NLPProcessor:
    """Hybrid NLP processor for architecture descriptions."""

    def __init__(self):
        self.sentence_splitter = text_to_sentences if BLINGFIRE_AVAILABLE else None
        self.ner_pipeline = None
        self.ready = True
        self._load_optional_models()

    def _load_optional_models(self) -> None:
        if not TRANSFORMERS_AVAILABLE:
            return

        if os.getenv("AEGIS_THREAT_ENABLE_TRANSFORMERS", "").lower() not in {"1", "true", "yes"}:
            return

        try:
            self.ner_pipeline = pipeline(
                "token-classification",
                model=NER_MODEL,
                aggregation_strategy="simple",
                local_files_only=True,
            )
            logger.info("Transformers NER pipeline initialized.")
        except Exception as exc:
            logger.info("Transformers NER pipeline unavailable: %s", exc)
            self.ner_pipeline = None

    def _split_sentences(self, text: str) -> List[str]:
        if not text:
            return []
        if self.sentence_splitter:
            try:
                return [line.strip() for line in self.sentence_splitter(text).splitlines() if line.strip()]
            except Exception:
                pass
        chunks = re.split(r"(?<=[.!?])\s+|\n+", text)
        return [chunk.strip() for chunk in chunks if chunk.strip()]

    def _normalize_component_name(self, text: str) -> str:
        normalized = re.sub(r"[^a-z0-9\s/-]", " ", text.lower())
        normalized = re.sub(r"\b(?:the|a|an)\b", " ", normalized)
        return re.sub(r"\s+", " ", normalized).strip()

    def extract_entities(self, text: str) -> Dict[str, List[Dict]]:
        result = {
            "technologies": [],
            "services": [],
            "protocols": [],
            "security_controls": [],
        }

        result = self._merge_entities(result, self._extract_with_regex(text))
        if self.ner_pipeline:
            result = self._merge_entities(result, self._extract_with_transformers(text))
        return result

    def _extract_with_transformers(self, text: str) -> Dict[str, List[Dict]]:
        result = {
            "technologies": [],
            "services": [],
            "protocols": [],
            "security_controls": [],
        }
        try:
            entities = self.ner_pipeline(text)
        except Exception as exc:
            logger.info("Transformers NER extraction skipped: %s", exc)
            return result

        for ent in entities:
            label = ent.get("entity_group", "")
            value = ent.get("word", "").strip()
            normalized = self._normalize_component_name(value)
            if not normalized or len(normalized) < 3:
                continue

            if normalized in TECH_COMPONENT_MAP:
                result["technologies"].append(
                    {
                        "text": value,
                        "label": "TECH",
                        "component_type": TECH_COMPONENT_MAP[normalized],
                        "source": "transformers",
                    }
                )
            elif label in {"ORG", "MISC", "PRODUCT"} and re.search(
                r"(service|api|gateway|worker|engine|pipeline|database|cache)$",
                value,
                re.IGNORECASE,
            ):
                result["services"].append(
                    {
                        "text": value,
                        "label": "SERVICE",
                        "component_type": self.classify_component_type(value),
                        "source": "transformers",
                    }
                )

        return result

    def _extract_with_regex(self, text: str) -> Dict[str, List[Dict]]:
        result = {
            "technologies": [],
            "services": [],
            "protocols": [],
            "security_controls": [],
        }
        text_lower = text.lower()
        seen = set()

        for tech in sorted(TECH_COMPONENT_MAP, key=len, reverse=True):
            comp_type = TECH_COMPONENT_MAP[tech]
            # Technologies are terms, not arbitrary substrings. Without token
            # boundaries, "gin" matched words such as "logging".
            if re.search(r'(?<![a-z0-9])' + re.escape(tech) + r'(?![a-z0-9])', text_lower) and tech not in seen:
                seen.add(tech)
                result["technologies"].append(
                    {
                        "text": tech,
                        "label": "TECH",
                        "component_type": comp_type,
                        "source": "regex",
                    }
                )

        for service_pattern in SERVICE_NAME_PATTERNS:
            for match in re.finditer(service_pattern, text, re.MULTILINE):
                name = match.group(1).strip()
                tech_stack = (match.group(2) or "").strip()
                normalized_name = self._normalize_component_name(name)
                if not normalized_name or normalized_name in seen:
                    continue
                seen.add(normalized_name)
                result["services"].append(
                    {
                        "text": name,
                        "tech_stack": tech_stack,
                        "label": "SERVICE",
                        "component_type": self.classify_component_type(f"{name} {tech_stack}".strip()),
                        "source": "regex",
                    }
                )

        for proto_key, proto_name in PROTOCOL_INDICATORS.items():
            if proto_key in text_lower and proto_key not in seen:
                seen.add(proto_key)
                result["protocols"].append({"text": proto_name, "label": "PROTOCOL", "source": "regex"})

        security_patterns = {
            "oauth2": ("OAuth2", "authentication"),
            "jwt": ("JWT", "authentication"),
            "mfa": ("MFA", "authentication"),
            "multi-factor": ("MFA", "authentication"),
            "rbac": ("RBAC", "authorization"),
            "role-based": ("RBAC", "authorization"),
            "encryption at rest": ("Encryption at Rest", "encryption"),
            "tls": ("TLS", "encryption"),
            "mtls": ("mTLS", "encryption"),
            "waf": ("WAF", "defense"),
            "rate limit": ("Rate Limiting", "defense"),
            "input validation": ("Input Validation", "defense"),
            "api key": ("API Key", "authentication"),
            "certificate pinning": ("Certificate Pinning", "encryption"),
            "cors": ("CORS", "defense"),
            "csp": ("CSP", "defense"),
            "service mesh": ("Service Mesh", "defense"),
            "zero trust": ("Zero Trust", "defense"),
        }

        for keyword, (name, category) in security_patterns.items():
            if keyword in text_lower and keyword not in seen:
                seen.add(keyword)
                result["security_controls"].append(
                    {
                        "text": name,
                        "category": category,
                        "label": "SECURITY",
                        "source": "regex",
                    }
                )

        return result

    def extract_data_flows(self, text: str, components: Dict[str, Any]) -> List[Dict]:
        flows = []
        component_names = self._build_component_name_map(components)
        existing_pairs = set()

        for sentence in self._split_sentences(text):
            sentence_lower = sentence.lower()
            if not any(verb in sentence_lower for verb in FLOW_VERBS):
                continue

            sentence_flows = self._extract_sentence_flows(sentence, component_names)
            for flow in sentence_flows:
                pair = (flow["source"], flow["target"])
                if pair in existing_pairs:
                    continue
                existing_pairs.add(pair)
                flows.append(flow)

        return flows

    def _extract_sentence_flows(self, sentence: str, component_names: Dict[str, str]) -> List[Dict]:
        sentence_lower = sentence.lower()
        protocol = self._infer_protocol(sentence_lower)
        matches = []

        patterns = [
            r"(\b[\w\s/.-]+?)\s+(?:calls?|invokes?|proxies?\s+to|routes?\s+(?:requests?\s+)?to)\s+(\b[\w\s/.-]+)",
            r"(\b[\w\s/-]+?)\s+(?:sends?|forwards?|pushes?|transmits?|routes?)\s+(?:[\w\s/-]+?\s+)?(?:to|into)\s+(\b[\w\s/-]+)",
            r"(\b[\w\s/-]+?)\s+(?:connects?|communicates?|integrates?|interfaces?)\s+(?:with|to)\s+(\b[\w\s/-]+)",
            r"(\b[\w\s/-]+?)\s+(?:queries|reads?\s+from|writes?\s+to|stores?\s+(?:data\s+)?in|fetches?\s+from|pulls?\s+from)\s+(\b[\w\s/-]+)",
            r"(\b[\w\s/-]+?)\s*(?:->|=>)\s*(\b[\w\s/-]+)",
            r"(?:data|traffic|requests?)\s+(?:flows?|goes?|moves?|travels?)\s+from\s+(\b[\w\s/-]+?)\s+to\s+(\b[\w\s/-]+)",
            r"(\b[\w\s/-]+?)\s+(?:receives?|consumes?|ingests?)\s+(?:[\w\s/-]+?\s+)?from\s+(\b[\w\s/-]+)",
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, sentence_lower):
                source_text = self._normalize_component_name(match.group(1).strip())
                target_text = self._normalize_component_name(match.group(2).strip())
                source_id = self._match_component(source_text, component_names)
                target_id = self._match_component(target_text, component_names)
                if source_id and target_id and source_id != target_id:
                    matches.append(
                        {
                            "source": source_id,
                            "target": target_id,
                            "protocol": protocol,
                            "evidence": sentence.strip(),
                            "method": "hybrid_regex",
                        }
                    )
        return matches

    def _build_component_name_map(self, components: Dict[str, Any]) -> Dict[str, str]:
        component_names = {}
        for cid, comp in components.items():
            name = comp.name if hasattr(comp, "name") else comp.get("name", "")
            normalized_name = self._normalize_component_name(name)
            if not normalized_name:
                continue
            component_names[normalized_name] = cid
            for word in normalized_name.split():
                if len(word) > 3:
                    component_names[word] = cid
        return component_names

    def _match_component(self, text: str, component_names: Dict[str, str]) -> Optional[str]:
        text = self._normalize_component_name(text)
        if text in component_names:
            return component_names[text]
        for name, cid in component_names.items():
            if name in text or text in name:
                return cid
        for tech in TECH_COMPONENT_MAP:
            if tech in text:
                for name, cid in component_names.items():
                    if tech in name:
                        return cid
        return None

    def _infer_protocol(self, text: str) -> str:
        for proto_key, proto_name in PROTOCOL_INDICATORS.items():
            if proto_key in text:
                return proto_name
        return "HTTPS"

    def _merge_entities(self, base: Dict, overlay: Dict) -> Dict:
        merged = {}
        for key in base:
            seen_texts = {entity["text"].lower() for entity in base.get(key, [])}
            merged[key] = list(base.get(key, []))
            for entity in overlay.get(key, []):
                if entity["text"].lower() not in seen_texts:
                    merged[key].append(entity)
                    seen_texts.add(entity["text"].lower())
        return merged

    def classify_component_type(self, text: str) -> str:
        text_lower = text.lower()
        for tech, comp_type in TECH_COMPONENT_MAP.items():
            if tech in text_lower:
                return comp_type
        if any(word in text_lower for word in ["database", "db", "sql", "store"]):
            return "Database"
        if any(word in text_lower for word in ["api", "endpoint", "rest", "backend"]):
            return "API"
        if any(word in text_lower for word in ["frontend", "ui", "client", "browser", "app"]):
            return "WebClient"
        if any(word in text_lower for word in ["queue", "message", "broker", "event"]):
            return "Queue"
        if any(word in text_lower for word in ["storage", "bucket", "file", "blob"]):
            return "Object Storage"
        if any(word in text_lower for word in ["gateway", "proxy", "ingress"]):
            return "API Gateway"
        if any(word in text_lower for word in ["load balancer", "balancer", "lb"]):
            return "Load Balancer"
        if any(word in text_lower for word in ["llm", "rag", "model", "embedding"]):
            return "ML Service"
        return "Service"

    def extract_security_properties(self, text: str) -> Dict[str, Any]:
        text_lower = text.lower()
        props = {
            "auth_type": "unknown",
            "encryption_at_rest": None,
            "logging_enabled": None,
            "input_validation": None,
            "rate_limiting": None,
            "public_access": None,
            "compliance_frameworks": [],
            "trust_boundary": "internal",
        }

        auth_checks = [
            ("cognito", "cognito"),
            ("auth0", "auth0"),
            ("okta", "okta"),
            ("keycloak", "keycloak"),
            ("azure ad", "azure_ad"),
            ("google identity", "google_identity"),
            ("firebase auth", "firebase"),
            ("oauth", "oauth2"),
            ("oidc", "oauth2"),
            ("jwt", "jwt"),
            ("json web token", "jwt"),
            ("api key", "api_key"),
            ("basic auth", "basic"),
            ("no auth", "none"),
            ("unauthenticated", "none"),
        ]
        for keyword, auth_type in auth_checks:
            if keyword in text_lower:
                props["auth_type"] = auth_type
                break

        if any(word in text_lower for word in ["encrypted", "encrypts", "encryption at rest", "tde", "kms"]):
            props["encryption_at_rest"] = True
        if any(word in text_lower for word in ["https", "tls", "ssl"]):
            props["encryption_in_transit"] = True
        if "mtls" in text_lower or "mutual tls" in text_lower:
            props["mtls_enabled"] = True

        if any(word in text_lower for word in ["logging", "logs", "audit"]):
            props["logging_enabled"] = True
        if any(word in text_lower for word in ["cloudwatch", "datadog", "splunk", "elk"]):
            props["centralized_logging"] = True
            props["logging_enabled"] = True

        if any(word in text_lower for word in ["waf", "web application firewall"]):
            props["waf_enabled"] = True
        if any(word in text_lower for word in ["rate limit", "throttling"]):
            props["rate_limiting"] = True
        if any(word in text_lower for word in ["query depth limit", "query depth limiting", "depth limiting"]):
            props["query_depth_limiting"] = True
        if any(word in text_lower for word in ["input validation", "sanitization"]):
            props["input_validation"] = True
        if any(word in text_lower for word in ["rbac", "role-based"]):
            props["rbac_enabled"] = True
        if any(word in text_lower for word in ["mfa", "multi-factor", "2fa"]):
            props["mfa_enabled"] = True
        if any(word in text_lower for word in ["service mesh", "istio", "linkerd"]):
            props["service_mesh"] = True
        if any(word in text_lower for word in ["zero trust", "zero-trust"]):
            props["zero_trust"] = True
        if any(word in text_lower for word in ["private subnet", "private network"]):
            props["private_subnet"] = True
        if any(word in text_lower for word in ["signed url", "signed urls", "pre-signed"]):
            props["signed_urls"] = True
        if any(word in text_lower for word in ["webhook signature", "signature validation", "hmac signature"]):
            props["webhook_signature_validation"] = True
        if any(word in text_lower for word in ["dlp", "data loss prevention"]):
            props["dlp_enabled"] = True
        if any(word in text_lower for word in ["vault", "key vault", "secrets manager", "secret store"]):
            props["secrets_management"] = True

        if any(word in text_lower for word in ["hipaa", "phi"]):
            props["compliance_frameworks"].append("HIPAA")
        if "gdpr" in text_lower:
            props["compliance_frameworks"].append("GDPR")
        if "pci" in text_lower:
            props["compliance_frameworks"].append("PCI DSS")
        if "soc 2" in text_lower:
            props["compliance_frameworks"].append("SOC 2")

        if any(word in text_lower for word in ["pii", "personal", "phi"]):
            props["data_sensitivity"] = "pii"
        if any(word in text_lower for word in ["payment", "credit card", "financial"]):
            props["data_sensitivity"] = "financial"
        if any(word in text_lower for word in ["secret", "credential", "token", "password", "api key"]):
            props["credential_sensitivity"] = True

        if any(word in text_lower for word in ["kubernetes", "k8s"]):
            props["deployment"] = "k8s"
        if any(word in text_lower for word in ["docker", "container"]):
            props["containerized"] = True
        if any(
            re.search(r"(?<![a-z0-9])" + re.escape(term) + r"(?![a-z0-9])", text_lower)
            for term in ("llm", "rag", "embedding model", "vector database", "model serving")
        ):
            props["ml_pipeline"] = True

        if any(word in text_lower for word in ["internet-facing", "public-facing", "public endpoint", "external users"]):
            props["public_access"] = True
            props["trust_boundary"] = "internet"
        elif any(word in text_lower for word in ["third-party", "external api", "partner api", "vendor api"]):
            props["trust_boundary"] = "external"
        elif any(word in text_lower for word in ["internal only", "private network", "backoffice only"]):
            props["trust_boundary"] = "internal"

        self._apply_negation_signals(text_lower, props)
        return props

    def _apply_negation_signals(self, text_lower: str, props: Dict[str, Any]) -> None:
        negation_checks = [
            (r"(does not|do not|doesn't|no|without).{0,40}(validate|validation).{0,20}(jwt|token)", lambda: props.update({"jwt_validation": False})),
            (r"(does not|do not|doesn't|no|without).{0,30}(rate limit|throttl)", lambda: props.update({"rate_limiting": False})),
            (r"(does not|do not|doesn't|no|without).{0,30}(encrypt|encryption)", lambda: props.update({"encryption_at_rest": False})),
            (r"(does not|do not|doesn't|no|without).{0,30}(log|logging|audit)", lambda: props.update({"logging_enabled": False})),
            (r"(does not|do not|doesn't|no|without).{0,30}(input validation|sanitize)", lambda: props.update({"input_validation": False})),
        ]
        for pattern, action in negation_checks:
            if re.search(pattern, text_lower):
                action()


_nlp_instance: Optional[NLPProcessor] = None


def get_nlp_processor() -> NLPProcessor:
    global _nlp_instance
    if _nlp_instance is None:
        _nlp_instance = NLPProcessor()
    return _nlp_instance


def nlp_runtime_ready() -> bool:
    try:
        processor = get_nlp_processor()
        return processor.ready
    except Exception:
        return False
