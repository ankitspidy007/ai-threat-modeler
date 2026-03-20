"""
NLP Processor - spaCy-based NER and dependency parsing for architecture descriptions.

Replaces pure regex parsing with linguistic analysis:
- Named Entity Recognition for components, technologies, protocols
- Dependency parsing for data flow extraction
- Semantic similarity for component classification
"""

import logging
import re
from collections import OrderedDict
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    import spacy

    SPACY_AVAILABLE = True
except Exception:
    SPACY_AVAILABLE = False
    logger.warning("spaCy not available. NLP features will be disabled, falling back to regex.")


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
    "cloud function": "Service",
    "azure function": "Service",
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
}

FLOW_VERBS = {
    "send", "sends", "sent", "transmit", "transmits", "forward", "forwards",
    "connect", "connects", "connected", "communicate", "communicates",
    "query", "queries", "queried", "read", "reads", "write", "writes",
    "call", "calls", "invoke", "invokes", "fetch", "fetches",
    "push", "pushes", "pull", "pulls", "store", "stores", "stored",
    "route", "routes", "routed", "redirect", "redirects",
    "authenticate", "authenticates", "authorize", "authorizes",
    "publish", "publishes", "subscribe", "subscribes", "consume", "consumes",
    "upload", "uploads", "download", "downloads", "stream", "streams",
    "proxy", "proxies", "cache", "caches", "replicate", "replicates",
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
    """Advanced NLP processor for architecture descriptions."""

    def __init__(self):
        self.nlp = None
        self._doc_cache: "OrderedDict[str, Any]" = OrderedDict()
        self._max_doc_cache = 64
        self._load_nlp()

    def _load_nlp(self):
        """Load spaCy model with custom pipeline components."""
        if not SPACY_AVAILABLE:
            return

        try:
            try:
                self.nlp = spacy.load("en_core_web_sm")
            except OSError:
                logger.info("Downloading spaCy English model...")
                import subprocess

                subprocess.run(
                    ["python", "-m", "spacy", "download", "en_core_web_sm"],
                    check=True,
                    capture_output=True,
                )
                self.nlp = spacy.load("en_core_web_sm")

            if "entity_ruler" not in self.nlp.pipe_names:
                ruler = self.nlp.add_pipe("entity_ruler", before="ner")
                ruler.add_patterns(self._build_entity_patterns())

            logger.info("NLP processor initialized with spaCy")
        except Exception as exc:
            logger.warning(f"Failed to load spaCy: {exc}. Falling back to regex.")
            self.nlp = None

    def _build_entity_patterns(self) -> List[Dict]:
        """Build spaCy entity patterns from our technology map."""
        patterns = []
        for tech, comp_type in TECH_COMPONENT_MAP.items():
            label = "TECH"
            if comp_type == "Database":
                label = "DATABASE"
            elif comp_type in ("API", "API Gateway"):
                label = "API_TECH"
            elif comp_type == "WebClient":
                label = "FRONTEND"
            elif comp_type == "Queue":
                label = "QUEUE"
            elif comp_type in ("Object Storage", "CDN"):
                label = "STORAGE"
            elif comp_type == "Identity Provider":
                label = "AUTH"
            elif comp_type == "Monitoring":
                label = "MONITORING"
            elif comp_type == "IoT Device":
                label = "IOT"
            elif comp_type == "ML Service":
                label = "ML"

            patterns.append({"label": label, "pattern": [{"LOWER": word.lower()} for word in tech.split()]})
        return patterns

    def _cache_get_doc(self, text: str):
        doc = self._doc_cache.get(text)
        if doc is not None:
            self._doc_cache.move_to_end(text)
        return doc

    def _cache_set_doc(self, text: str, doc) -> None:
        self._doc_cache[text] = doc
        self._doc_cache.move_to_end(text)
        if len(self._doc_cache) > self._max_doc_cache:
            self._doc_cache.popitem(last=False)

    def _get_doc(self, text: str):
        if not self.nlp:
            return None
        cached = self._cache_get_doc(text)
        if cached is not None:
            return cached
        doc = self.nlp(text)
        self._cache_set_doc(text, doc)
        return doc

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

        if self.nlp:
            result = self._extract_with_spacy(text)

        return self._merge_entities(result, self._extract_with_regex(text))

    def _extract_with_spacy(self, text: str) -> Dict[str, List[Dict]]:
        doc = self._get_doc(text)
        result = {
            "technologies": [],
            "services": [],
            "protocols": [],
            "security_controls": [],
        }
        seen = set()

        for ent in doc.ents:
            key = (ent.text.lower(), ent.label_)
            if key in seen:
                continue
            seen.add(key)

            entity_info = {
                "text": ent.text,
                "label": ent.label_,
                "start": ent.start_char,
                "end": ent.end_char,
                "component_type": TECH_COMPONENT_MAP.get(ent.text.lower()),
            }

            if ent.label_ in {"DATABASE", "API_TECH", "FRONTEND", "QUEUE", "STORAGE", "AUTH", "MONITORING", "IOT", "TECH", "ML"}:
                result["technologies"].append(entity_info)
            elif ent.label_ in {"ORG", "PRODUCT"}:
                if ent.text.lower() in TECH_COMPONENT_MAP:
                    entity_info["component_type"] = TECH_COMPONENT_MAP[ent.text.lower()]
                    result["technologies"].append(entity_info)
                else:
                    result["services"].append(entity_info)

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

        for tech, comp_type in TECH_COMPONENT_MAP.items():
            if tech in text_lower and tech not in seen:
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
        if self.nlp:
            flows = self._extract_flows_with_spacy(text, components)

        regex_flows = self._extract_flows_with_regex(text, components)
        existing_pairs = {(flow["source"], flow["target"]) for flow in flows}
        for regex_flow in regex_flows:
            pair = (regex_flow["source"], regex_flow["target"])
            if pair not in existing_pairs:
                flows.append(regex_flow)
                existing_pairs.add(pair)
        return flows

    def _extract_flows_with_spacy(self, text: str, components: Dict[str, Any]) -> List[Dict]:
        flows = []
        doc = self._get_doc(text)
        component_names = self._build_component_name_map(components)

        for sent in doc.sents:
            for token in sent:
                if token.lemma_.lower() in FLOW_VERBS or token.text.lower() in FLOW_VERBS:
                    source_id = None
                    target_id = None
                    protocol = "HTTPS"

                    for child in token.children:
                        if child.dep_ in {"nsubj", "nsubjpass", "agent"}:
                            source_text = self._normalize_component_name(self._get_compound_text(child))
                            source_id = self._match_component(source_text, component_names)

                        if child.dep_ in {"dobj", "pobj", "attr"}:
                            target_text = self._normalize_component_name(self._get_compound_text(child))
                            target_id = self._match_component(target_text, component_names)

                        if child.dep_ == "prep":
                            for pobj in child.children:
                                if pobj.dep_ == "pobj":
                                    target_text = self._normalize_component_name(self._get_compound_text(pobj))
                                    tid = self._match_component(target_text, component_names)
                                    if tid:
                                        target_id = tid

                    for proto_key, proto_name in PROTOCOL_INDICATORS.items():
                        if proto_key in sent.text.lower():
                            protocol = proto_name
                            break

                    if source_id and target_id and source_id != target_id:
                        flows.append(
                            {
                                "source": source_id,
                                "target": target_id,
                                "protocol": protocol,
                                "verb": token.text,
                                "evidence": sent.text.strip(),
                                "method": "nlp_dependency",
                            }
                        )

        return flows

    def _extract_flows_with_regex(self, text: str, components: Dict[str, Any]) -> List[Dict]:
        flows = []
        text_lower = text.lower()
        component_names = self._build_component_name_map(components)
        patterns = [
            r"(\b\w[\w\s]+?)\s+(?:sends?|forwards?|pushes?|transmits?|routes?)\s+(?:[\w\s]+?\s+)?(?:to|into)\s+(\b\w[\w\s]+?)(?:\.|,|;|\n)",
            r"(\b\w[\w\s]+?)\s+(?:connects?|communicates?|integrates?|interfaces?)\s+(?:with|to)\s+(\b\w[\w\s]+?)(?:\.|,|;|\n)",
            r"(\b\w[\w\s]+?)\s+(?:queries|reads?\s+from|writes?\s+to|stores?\s+(?:data\s+)?in|fetches?\s+from|pulls?\s+from)\s+(\b\w[\w\s]+?)(?:\.|,|;|\n)",
            r"(\b\w[\w\s]+?)\s*(?:->|=>)\s*(\b\w[\w\s]+?)(?:\.|,|;|\n)",
            r"(\b\w[\w\s]+?)\s+(?:authenticates?|authorizes?|validates?)\s+(?:with|through|via|using)\s+(\b\w[\w\s]+?)(?:\.|,|;|\n)",
            r"(?:data|traffic|requests?)\s+(?:flows?|goes?|moves?|travels?)\s+from\s+(\b\w[\w\s]+?)\s+to\s+(\b\w[\w\s]+?)(?:\.|,|;|\n)",
            r"(\b\w[\w\s]+?)\s+(?:receives?|consumes?|ingests?)\s+(?:[\w\s]+?\s+)?from\s+(\b\w[\w\s]+?)(?:\.|,|;|\n)",
        ]

        existing_pairs = set()
        for pattern in patterns:
            for match in re.finditer(pattern, text_lower):
                source_text = self._normalize_component_name(match.group(1).strip())
                target_text = self._normalize_component_name(match.group(2).strip())
                source_id = self._match_component(source_text, component_names)
                target_id = self._match_component(target_text, component_names)
                if source_id and target_id and source_id != target_id:
                    pair = (source_id, target_id)
                    if pair in existing_pairs:
                        continue
                    existing_pairs.add(pair)
                    flows.append(
                        {
                            "source": source_id,
                            "target": target_id,
                            "protocol": self._infer_protocol(text_lower),
                            "evidence": match.group(0).strip(),
                            "method": "regex",
                        }
                    )
        return flows

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

    def _get_compound_text(self, token) -> str:
        parts = []
        for child in token.children:
            if child.dep_ in {"compound", "amod", "nmod"}:
                parts.append(child.text)
        parts.append(token.text)
        return " ".join(parts)

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
        if self.nlp:
            return self._extract_security_with_nlp(self._get_doc(text), text_lower)
        return self._extract_security_with_regex(text_lower)

    def _extract_security_with_nlp(self, doc, text_lower: str) -> Dict[str, Any]:
        props = self._extract_security_with_regex(text_lower)
        for sent in doc.sents:
            sent_text = sent.text.lower()
            for token in sent:
                if token.dep_ == "neg" or token.text.lower() in {"not", "no", "without", "lacking", "missing"}:
                    negated_text = token.head.text.lower()
                    if any(word in negated_text for word in ["encrypt", "encryption"]):
                        props["encryption_at_rest"] = False
                    if any(word in negated_text for word in ["auth", "authenticate", "authentication"]):
                        props["auth_type"] = "none"
                    if any(word in negated_text for word in ["log", "logging", "audit"]):
                        props["logging_enabled"] = False
                    if any(word in negated_text for word in ["valid", "validate", "validation"]):
                        props["input_validation"] = False
                    if any(word in negated_text for word in ["rate", "limit", "throttl"]):
                        props["rate_limiting"] = False
            if "does not" in sent_text or "doesn't" in sent_text or "do not" in sent_text:
                if "validate" in sent_text and "jwt" in sent_text:
                    props["jwt_validation"] = False
                if "encrypt" in sent_text:
                    props["encryption_at_rest"] = False
                if "log" in sent_text:
                    props["logging_enabled"] = False
        return props

    def _extract_security_with_regex(self, text_lower: str) -> Dict[str, Any]:
        props = {
            "auth_type": "none",
            "encryption_at_rest": False,
            "logging_enabled": False,
            "input_validation": False,
            "rate_limiting": False,
            "public_access": False,
            "compliance_frameworks": [],
            "trust_boundary": "internal",
        }

        auth_checks = [
            ("cognito", "cognito"),
            ("auth0", "auth0"),
            ("okta", "okta"),
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
        if any(word in text_lower for word in ["llm", "rag", "embedding model", "vector database", "model serving"]):
            props["ml_pipeline"] = True

        if any(word in text_lower for word in ["internet-facing", "public-facing", "public endpoint", "external users"]):
            props["public_access"] = True
            props["trust_boundary"] = "internet"
        elif any(word in text_lower for word in ["third-party", "external api", "partner api", "vendor api"]):
            props["trust_boundary"] = "external"
        elif any(word in text_lower for word in ["internal only", "private network", "backoffice only"]):
            props["trust_boundary"] = "internal"

        return props


_nlp_instance: Optional[NLPProcessor] = None


def get_nlp_processor() -> NLPProcessor:
    """Get or create global NLP processor instance."""
    global _nlp_instance
    if _nlp_instance is None:
        _nlp_instance = NLPProcessor()
    return _nlp_instance
