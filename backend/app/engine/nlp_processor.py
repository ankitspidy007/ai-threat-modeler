"""
NLP Processor — spaCy-based NER and dependency parsing for architecture descriptions.

Replaces pure regex parsing with linguistic analysis:
- Named Entity Recognition for components, technologies, protocols
- Dependency parsing for data flow extraction
- Semantic similarity for component classification
"""

import re
import logging
from typing import List, Dict, Tuple, Optional, Any
from collections import defaultdict

logger = logging.getLogger(__name__)

# Try to load spaCy; fall back to regex if unavailable
try:
    import spacy
    from spacy.tokens import Doc, Span
    SPACY_AVAILABLE = True
except Exception:
    SPACY_AVAILABLE = False
    logger.warning("spaCy not available. NLP features will be disabled, falling back to regex.")



# Technology → component type mapping for NER-based classification
TECH_COMPONENT_MAP = {
    # Databases
    'postgresql': 'Database', 'postgres': 'Database', 'mysql': 'Database',
    'mongodb': 'Database', 'mongo': 'Database', 'redis': 'Database',
    'dynamodb': 'Database', 'cassandra': 'Database', 'mariadb': 'Database',
    'oracle': 'Database', 'mssql': 'Database', 'cosmosdb': 'Database',
    'firestore': 'Database', 'documentdb': 'Database', 'elasticsearch': 'Database',
    'snowflake': 'Database', 'redshift': 'Database', 'bigquery': 'Database',
    'sqlite': 'Database', 'cockroachdb': 'Database', 'neo4j': 'Database',
    'influxdb': 'Database', 'timescaledb': 'Database', 'supabase': 'Database',
    'planetscale': 'Database', 'neon': 'Database', 'turso': 'Database',
    'valkey': 'Database', 'dragonfly': 'Database', 'dragonflydb': 'Database',
    'memcached': 'Database', 'couchdb': 'Database', 'rethinkdb': 'Database',
    
    # API/Web Frameworks
    'express': 'API', 'fastapi': 'API', 'django': 'API', 'flask': 'API',
    'spring boot': 'API', 'spring': 'API', 'rails': 'API', 'laravel': 'API',
    'gin': 'API', 'fiber': 'API', 'actix': 'API', 'nest': 'API', 'nestjs': 'API',
    'graphql': 'API', 'rest api': 'API', 'grpc': 'API', 'api server': 'API',
    'web service': 'API', 'koa': 'API', 'hapi': 'API', 'adonisjs': 'API',
    
    # Frontend
    'react': 'WebClient', 'vue': 'WebClient', 'angular': 'WebClient',
    'svelte': 'WebClient', 'next.js': 'WebClient', 'nextjs': 'WebClient',
    'nuxt': 'WebClient', 'gatsby': 'WebClient', 'remix': 'WebClient',
    'astro': 'WebClient', 'spa': 'WebClient', 'frontend': 'WebClient',
    'mobile app': 'WebClient', 'ios': 'WebClient', 'android': 'WebClient',
    'flutter': 'WebClient', 'react native': 'WebClient', 'kiosk': 'WebClient',
    
    # Infrastructure
    'nginx': 'Load Balancer', 'haproxy': 'Load Balancer', 'alb': 'Load Balancer',
    'nlb': 'Load Balancer', 'elb': 'Load Balancer', 'traefik': 'Load Balancer',
    'kong': 'API Gateway', 'apigee': 'API Gateway', 'api gateway': 'API Gateway',
    'aws api gateway': 'API Gateway', 'azure api management': 'API Gateway',
    
    # Message Queues
    'kafka': 'Queue', 'rabbitmq': 'Queue', 'sqs': 'Queue', 'sns': 'Queue',
    'pubsub': 'Queue', 'nats': 'Queue', 'mqtt': 'Queue', 'activemq': 'Queue',
    'celery': 'Queue', 'bull': 'Queue', 'sidekiq': 'Queue',
    
    # Storage
    's3': 'Object Storage', 'azure blob': 'Object Storage', 'gcs': 'Object Storage',
    'minio': 'Object Storage', 'cloudflare r2': 'Object Storage',
    
    # CDN
    'cloudfront': 'CDN', 'cloudflare': 'CDN', 'akamai': 'CDN', 'fastly': 'CDN',
    
    # Auth/Identity
    'auth0': 'Identity Provider', 'okta': 'Identity Provider',
    'cognito': 'Identity Provider', 'keycloak': 'Identity Provider',
    'azure ad': 'Identity Provider', 'firebase auth': 'Identity Provider',
    
    # Monitoring
    'datadog': 'Monitoring', 'splunk': 'Monitoring', 'grafana': 'Monitoring',
    'prometheus': 'Monitoring', 'new relic': 'Monitoring', 'elk': 'Monitoring',
    'cloudwatch': 'Monitoring', 'sentry': 'Monitoring',
    
    # Serverless
    'lambda': 'Service', 'cloud function': 'Service', 'azure function': 'Service',
    
    # IoT
    'iot device': 'IoT Device', 'sensor': 'IoT Device',
    'medical device': 'IoT Device', 'smart device': 'IoT Device',
    
    # Security
    'guardduty': 'Threat Detection', 'security hub': 'Threat Detection',
    'waf': 'Threat Detection', 'vault': 'Secrets Manager',
    'key vault': 'Secrets Manager', 'secrets manager': 'Secrets Manager',
}

# Flow indicator verbs for dependency parsing
FLOW_VERBS = {
    'send', 'sends', 'sent', 'transmit', 'transmits', 'forward', 'forwards',
    'connect', 'connects', 'connected', 'communicate', 'communicates',
    'query', 'queries', 'queried', 'read', 'reads', 'write', 'writes',
    'call', 'calls', 'invoke', 'invokes', 'fetch', 'fetches',
    'push', 'pushes', 'pull', 'pulls', 'store', 'stores', 'stored',
    'route', 'routes', 'routed', 'redirect', 'redirects',
    'authenticate', 'authenticates', 'authorize', 'authorizes',
    'publish', 'publishes', 'subscribe', 'subscribes', 'consume', 'consumes',
    'upload', 'uploads', 'download', 'downloads', 'stream', 'streams',
    'proxy', 'proxies', 'cache', 'caches', 'replicate', 'replicates',
}

# Protocol keywords
PROTOCOL_INDICATORS = {
    'https': 'HTTPS', 'http': 'HTTP', 'grpc': 'gRPC', 'graphql': 'GraphQL',
    'websocket': 'WebSocket', 'ws': 'WebSocket', 'wss': 'WebSocket',
    'tcp': 'TCP', 'tls': 'HTTPS', 'ssl': 'HTTPS', 'mqtt': 'MQTT',
    'amqp': 'AMQP', 'rest': 'HTTPS', 'ssh': 'SSH', 'sftp': 'SFTP',
}


class NLPProcessor:
    """
    Advanced NLP processor for architecture descriptions.
    Uses spaCy for NER and dependency parsing with fallback to regex.
    """
    
    def __init__(self):
        self.nlp = None
        self._load_nlp()
    
    def _load_nlp(self):
        """Load spaCy model with custom pipeline components."""
        if not SPACY_AVAILABLE:
            return
        
        try:
            # Try to load the English model
            try:
                self.nlp = spacy.load("en_core_web_sm")
            except OSError:
                logger.info("Downloading spaCy English model...")
                import subprocess
                subprocess.run(
                    ["python", "-m", "spacy", "download", "en_core_web_sm"],
                    check=True, capture_output=True
                )
                self.nlp = spacy.load("en_core_web_sm")
            
            # Add custom entity ruler for technology detection
            if "entity_ruler" not in self.nlp.pipe_names:
                ruler = self.nlp.add_pipe("entity_ruler", before="ner")
                patterns = self._build_entity_patterns()
                ruler.add_patterns(patterns)
            
            logger.info("NLP processor initialized with spaCy")
        except Exception as e:
            logger.warning(f"Failed to load spaCy: {e}. Falling back to regex.")
            self.nlp = None
    
    def _build_entity_patterns(self) -> List[Dict]:
        """Build spaCy entity patterns from our technology map."""
        patterns = []
        for tech, comp_type in TECH_COMPONENT_MAP.items():
            # Map component types to entity labels
            label = "TECH"
            if comp_type == 'Database':
                label = "DATABASE"
            elif comp_type in ('API', 'API Gateway'):
                label = "API_TECH"
            elif comp_type == 'WebClient':
                label = "FRONTEND"
            elif comp_type == 'Queue':
                label = "QUEUE"
            elif comp_type in ('Object Storage', 'CDN'):
                label = "STORAGE"
            elif comp_type == 'Identity Provider':
                label = "AUTH"
            elif comp_type == 'Monitoring':
                label = "MONITORING"
            elif comp_type == 'IoT Device':
                label = "IOT"
            
            # Create pattern (handle multi-word technologies)
            words = tech.split()
            if len(words) == 1:
                patterns.append({
                    "label": label,
                    "pattern": [{"LOWER": tech.lower()}]
                })
            else:
                patterns.append({
                    "label": label,
                    "pattern": [{"LOWER": w.lower()} for w in words]
                })
        
        return patterns
    
    def extract_entities(self, text: str) -> Dict[str, List[Dict]]:
        """
        Extract named entities from architecture description.
        
        Returns dict with categories:
        - technologies: detected tech stack items
        - services: named services/components
        - protocols: communication protocols
        - security_controls: security features mentioned
        """
        result = {
            'technologies': [],
            'services': [],
            'protocols': [],
            'security_controls': []
        }
        
        if self.nlp:
            result = self._extract_with_spacy(text)
        
        # Always augment with regex patterns (catches things spaCy might miss)
        regex_entities = self._extract_with_regex(text)
        result = self._merge_entities(result, regex_entities)
        
        return result
    
    def _extract_with_spacy(self, text: str) -> Dict[str, List[Dict]]:
        """Extract entities using spaCy NLP pipeline."""
        doc = self.nlp(text)
        result = {
            'technologies': [],
            'services': [],
            'protocols': [],
            'security_controls': []
        }
        
        seen = set()
        
        for ent in doc.ents:
            key = (ent.text.lower(), ent.label_)
            if key in seen:
                continue
            seen.add(key)
            
            entity_info = {
                'text': ent.text,
                'label': ent.label_,
                'start': ent.start_char,
                'end': ent.end_char,
                'component_type': TECH_COMPONENT_MAP.get(ent.text.lower())
            }
            
            if ent.label_ in ('DATABASE', 'API_TECH', 'FRONTEND', 'QUEUE', 
                             'STORAGE', 'AUTH', 'MONITORING', 'IOT', 'TECH'):
                result['technologies'].append(entity_info)
            elif ent.label_ in ('ORG', 'PRODUCT'):
                # Check if it's a known tech
                if ent.text.lower() in TECH_COMPONENT_MAP:
                    entity_info['component_type'] = TECH_COMPONENT_MAP[ent.text.lower()]
                    result['technologies'].append(entity_info)
                else:
                    result['services'].append(entity_info)
        
        return result
    
    def _extract_with_regex(self, text: str) -> Dict[str, List[Dict]]:
        """Extract entities using regex patterns (fallback/augmentation)."""
        result = {
            'technologies': [],
            'services': [],
            'protocols': [],
            'security_controls': []
        }
        text_lower = text.lower()
        seen = set()
        
        # 1. Extract technologies
        for tech, comp_type in TECH_COMPONENT_MAP.items():
            if tech in text_lower and tech not in seen:
                seen.add(tech)
                result['technologies'].append({
                    'text': tech,
                    'label': 'TECH',
                    'component_type': comp_type,
                    'source': 'regex'
                })
        
        # 2. Extract named services (e.g., "User Service", "Payment API")
        service_pattern = r'(?:^|\n)\s*(?:\d+\.|-|•)\s+([A-Z][A-Za-z\s]+(?:Service|API|Gateway|Worker|Job|Handler|Manager|Controller|Processor|Engine))\s*(?:\(([^)]+)\))?'
        for match in re.finditer(service_pattern, text, re.MULTILINE):
            name = match.group(1).strip()
            tech_stack = match.group(2) or ''
            if name.lower() not in seen:
                seen.add(name.lower())
                result['services'].append({
                    'text': name,
                    'tech_stack': tech_stack,
                    'label': 'SERVICE',
                    'component_type': 'Service',
                    'source': 'regex'
                })
        
        # 3. Extract protocols
        for proto_key, proto_name in PROTOCOL_INDICATORS.items():
            if proto_key in text_lower and proto_key not in seen:
                seen.add(proto_key)
                result['protocols'].append({
                    'text': proto_name,
                    'label': 'PROTOCOL',
                    'source': 'regex'
                })
        
        # 4. Extract security controls
        security_patterns = {
            'oauth2': ('OAuth2', 'authentication'),
            'jwt': ('JWT', 'authentication'),
            'mfa': ('MFA', 'authentication'),
            'multi-factor': ('MFA', 'authentication'),
            'rbac': ('RBAC', 'authorization'),
            'role-based': ('RBAC', 'authorization'),
            'encryption at rest': ('Encryption at Rest', 'encryption'),
            'tls': ('TLS', 'encryption'),
            'mtls': ('mTLS', 'encryption'),
            'waf': ('WAF', 'defense'),
            'rate limit': ('Rate Limiting', 'defense'),
            'input validation': ('Input Validation', 'defense'),
            'api key': ('API Key', 'authentication'),
            'certificate pinning': ('Certificate Pinning', 'encryption'),
            'cors': ('CORS', 'defense'),
            'csp': ('CSP', 'defense'),
        }
        
        for keyword, (name, category) in security_patterns.items():
            if keyword in text_lower and keyword not in seen:
                seen.add(keyword)
                result['security_controls'].append({
                    'text': name,
                    'category': category,
                    'label': 'SECURITY',
                    'source': 'regex'
                })
        
        return result
    
    def extract_data_flows(self, text: str, components: Dict[str, Any]) -> List[Dict]:
        """
        Extract data flows using NLP dependency parsing.
        
        Looks for subject-verb-object patterns like:
        - "User Service sends data to Payment Service"
        - "The frontend communicates with the API gateway"
        - "Redis caches session data from the auth service"
        """
        flows = []
        
        if self.nlp:
            flows = self._extract_flows_with_spacy(text, components)
        
        # Augment with regex flow patterns
        regex_flows = self._extract_flows_with_regex(text, components)
        
        # Merge avoiding duplicates
        existing_pairs = {(f['source'], f['target']) for f in flows}
        for rf in regex_flows:
            pair = (rf['source'], rf['target'])
            if pair not in existing_pairs:
                flows.append(rf)
                existing_pairs.add(pair)
        
        return flows
    
    def _extract_flows_with_spacy(self, text: str, components: Dict[str, Any]) -> List[Dict]:
        """Extract data flows using spaCy dependency parsing."""
        flows = []
        doc = self.nlp(text)
        
        component_names = {}
        for cid, comp in components.items():
            name_lower = comp.name.lower() if hasattr(comp, 'name') else comp.get('name', '').lower()
            component_names[name_lower] = cid
            # Also add partial matches
            for word in name_lower.split():
                if len(word) > 3:
                    component_names[word] = cid
        
        for sent in doc.sents:
            # Find verbs that indicate data flow
            for token in sent:
                if token.lemma_.lower() in FLOW_VERBS or token.text.lower() in FLOW_VERBS:
                    source_id = None
                    target_id = None
                    protocol = 'HTTPS'
                    
                    # Find subject (source)
                    for child in token.children:
                        if child.dep_ in ('nsubj', 'nsubjpass', 'agent'):
                            source_text = self._get_compound_text(child).lower()
                            source_id = self._match_component(source_text, component_names)
                        
                        # Find object (target)
                        if child.dep_ in ('dobj', 'pobj', 'attr'):
                            target_text = self._get_compound_text(child).lower()
                            target_id = self._match_component(target_text, component_names)
                        
                        # Check prepositional phrases for target
                        if child.dep_ == 'prep':
                            for pobj in child.children:
                                if pobj.dep_ == 'pobj':
                                    target_text = self._get_compound_text(pobj).lower()
                                    tid = self._match_component(target_text, component_names)
                                    if tid:
                                        target_id = tid
                    
                    # Detect protocol from sentence context
                    sent_text = sent.text.lower()
                    for proto_key, proto_name in PROTOCOL_INDICATORS.items():
                        if proto_key in sent_text:
                            protocol = proto_name
                            break
                    
                    if source_id and target_id and source_id != target_id:
                        flows.append({
                            'source': source_id,
                            'target': target_id,
                            'protocol': protocol,
                            'verb': token.text,
                            'evidence': sent.text.strip(),
                            'method': 'nlp_dependency'
                        })
        
        return flows
    
    def _extract_flows_with_regex(self, text: str, components: Dict[str, Any]) -> List[Dict]:
        """Extract data flows using enhanced regex patterns."""
        flows = []
        text_lower = text.lower()
        
        component_names = {}
        for cid, comp in components.items():
            name_lower = comp.name.lower() if hasattr(comp, 'name') else comp.get('name', '').lower()
            component_names[name_lower] = cid
            for word in name_lower.split():
                if len(word) > 3:
                    component_names[word] = cid
        
        # Enhanced flow patterns
        patterns = [
            # "A sends/forwards/pushes data to B"
            r'(\b\w[\w\s]+?)\s+(?:sends?|forwards?|pushes?|transmits?|routes?)\s+(?:[\w\s]+?\s+)?(?:to|into)\s+(\b\w[\w\s]+?)(?:\.|,|;|\n)',
            # "A connects/communicates with B"
            r'(\b\w[\w\s]+?)\s+(?:connects?|communicates?|integrates?|interfaces?)\s+(?:with|to)\s+(\b\w[\w\s]+?)(?:\.|,|;|\n)',
            # "A queries/reads/writes B"
            r'(\b\w[\w\s]+?)\s+(?:queries|reads?\s+from|writes?\s+to|stores?\s+(?:data\s+)?in|fetches?\s+from|pulls?\s+from)\s+(\b\w[\w\s]+?)(?:\.|,|;|\n)',
            # "A → B" or "A -> B"
            r'(\b\w[\w\s]+?)\s*(?:→|->|=>)\s*(\b\w[\w\s]+?)(?:\.|,|;|\n)',
            # "A authenticates with/through B"
            r'(\b\w[\w\s]+?)\s+(?:authenticates?|authorizes?|validates?)\s+(?:with|through|via|using)\s+(\b\w[\w\s]+?)(?:\.|,|;|\n)',
            # "data flows from A to B"
            r'(?:data|traffic|requests?)\s+(?:flows?|goes?|moves?|travels?)\s+from\s+(\b\w[\w\s]+?)\s+to\s+(\b\w[\w\s]+?)(?:\.|,|;|\n)',
        ]
        
        existing_pairs = set()
        for pattern in patterns:
            for match in re.finditer(pattern, text_lower):
                source_text = match.group(1).strip()
                target_text = match.group(2).strip()
                
                source_id = self._match_component(source_text, component_names)
                target_id = self._match_component(target_text, component_names)
                
                if source_id and target_id and source_id != target_id:
                    pair = (source_id, target_id)
                    if pair not in existing_pairs:
                        existing_pairs.add(pair)
                        flows.append({
                            'source': source_id,
                            'target': target_id,
                            'protocol': self._infer_protocol(text_lower, source_id, target_id),
                            'evidence': match.group(0).strip(),
                            'method': 'regex'
                        })
        
        return flows
    
    def _get_compound_text(self, token) -> str:
        """Get the full compound noun phrase for a token."""
        parts = []
        for child in token.children:
            if child.dep_ in ('compound', 'amod', 'nmod'):
                parts.append(child.text)
        parts.append(token.text)
        return ' '.join(parts)
    
    def _match_component(self, text: str, component_names: Dict[str, str]) -> Optional[str]:
        """Match text to a component ID using fuzzy matching."""
        text = text.strip().lower()
        
        # Direct match
        if text in component_names:
            return component_names[text]
        
        # Partial match — check if any component name is contained in the text
        for name, cid in component_names.items():
            if name in text or text in name:
                return cid
        
        # Check against TECH_COMPONENT_MAP for technology names
        for tech in TECH_COMPONENT_MAP:
            if tech in text:
                # Find component with matching type
                comp_type = TECH_COMPONENT_MAP[tech]
                for name, cid in component_names.items():
                    if tech in name:
                        return cid
        
        return None
    
    def _infer_protocol(self, text: str, source_id: str, target_id: str) -> str:
        """Infer protocol based on component types and text context."""
        for proto_key, proto_name in PROTOCOL_INDICATORS.items():
            if proto_key in text:
                return proto_name
        return 'HTTPS'  # Default

    def _merge_entities(self, base: Dict, overlay: Dict) -> Dict:
        """Merge two entity dicts, avoiding duplicates."""
        merged = {}
        for key in base:
            seen_texts = {e['text'].lower() for e in base.get(key, [])}
            merged[key] = list(base.get(key, []))
            for entity in overlay.get(key, []):
                if entity['text'].lower() not in seen_texts:
                    merged[key].append(entity)
                    seen_texts.add(entity['text'].lower())
        return merged
    
    def classify_component_type(self, text: str) -> str:
        """
        Classify a component type from its description using NLP.
        Falls back to keyword matching if spaCy unavailable.
        """
        text_lower = text.lower()
        
        # Check direct technology map first
        for tech, comp_type in TECH_COMPONENT_MAP.items():
            if tech in text_lower:
                return comp_type
        
        # Keyword-based classification
        if any(w in text_lower for w in ['database', 'db', 'sql', 'store']):
            return 'Database'
        if any(w in text_lower for w in ['api', 'endpoint', 'rest', 'backend']):
            return 'API'
        if any(w in text_lower for w in ['frontend', 'ui', 'client', 'browser', 'app']):
            return 'WebClient'
        if any(w in text_lower for w in ['queue', 'message', 'broker', 'event']):
            return 'Queue'
        if any(w in text_lower for w in ['storage', 'bucket', 'file', 'blob']):
            return 'Object Storage'
        if any(w in text_lower for w in ['gateway', 'proxy', 'ingress']):
            return 'API Gateway'
        if any(w in text_lower for w in ['load balancer', 'balancer', 'lb']):
            return 'Load Balancer'
        
        return 'Service'  # Default
    
    def extract_security_properties(self, text: str) -> Dict[str, Any]:
        """
        Extract security-relevant properties from architecture description.
        Uses NLP to understand context, not just keyword presence.
        """
        props = {}
        text_lower = text.lower()
        
        if self.nlp:
            doc = self.nlp(text)
            props = self._extract_security_with_nlp(doc, text_lower)
        else:
            props = self._extract_security_with_regex(text_lower)
        
        return props
    
    def _extract_security_with_nlp(self, doc, text_lower: str) -> Dict[str, Any]:
        """Extract security properties using NLP understanding."""
        props = self._extract_security_with_regex(text_lower)
        
        # NLP-enhanced: Check for negations
        for sent in doc.sents:
            sent_text = sent.text.lower()
            
            for token in sent:
                # Detect negation patterns
                if token.dep_ == 'neg' or token.text.lower() in ('not', 'no', 'without', 'lacking', 'missing'):
                    # Check what's being negated
                    head = token.head
                    negated_text = head.text.lower()
                    
                    if any(w in negated_text for w in ['encrypt', 'encryption']):
                        props['encryption_at_rest'] = False
                    if any(w in negated_text for w in ['auth', 'authenticate', 'authentication']):
                        props['auth_type'] = 'none'
                    if any(w in negated_text for w in ['log', 'logging', 'audit']):
                        props['logging_enabled'] = False
                    if any(w in negated_text for w in ['valid', 'validate', 'validation']):
                        props['input_validation'] = False
                    if any(w in negated_text for w in ['rate', 'limit', 'throttl']):
                        props['rate_limiting'] = False
            
            # Detect "does not" patterns
            if 'does not' in sent_text or "doesn't" in sent_text or 'do not' in sent_text:
                if 'validate' in sent_text and 'jwt' in sent_text:
                    props['jwt_validation'] = False
                if 'encrypt' in sent_text:
                    props['encryption_at_rest'] = False
                if 'log' in sent_text:
                    props['logging_enabled'] = False
        
        return props
    
    def _extract_security_with_regex(self, text_lower: str) -> Dict[str, Any]:
        """Extract security properties using regex patterns."""
        props = {
            'auth_type': 'none',
            'encryption_at_rest': False,
            'logging_enabled': False,
            'input_validation': False,
            'rate_limiting': False,
            'public_access': False,
            'compliance_frameworks': []
        }
        
        # Auth detection (priority order)
        auth_checks = [
            ('cognito', 'cognito'), ('auth0', 'auth0'), ('okta', 'okta'),
            ('azure ad', 'azure_ad'), ('google identity', 'google_identity'),
            ('firebase auth', 'firebase'),
            ('oauth', 'oauth2'), ('oidc', 'oauth2'),
            ('jwt', 'jwt'), ('json web token', 'jwt'),
            ('api key', 'api_key'), ('basic auth', 'basic'),
            ('no auth', 'none'), ('unauthenticated', 'none'),
        ]
        for keyword, auth_type in auth_checks:
            if keyword in text_lower:
                props['auth_type'] = auth_type
                break
        
        # Encryption
        if any(w in text_lower for w in ['encrypted', 'encrypts', 'encryption at rest', 'tde', 'kms']):
            props['encryption_at_rest'] = True
        if any(w in text_lower for w in ['https', 'tls', 'ssl']):
            props['encryption_in_transit'] = True
        if 'mtls' in text_lower or 'mutual tls' in text_lower:
            props['mtls_enabled'] = True
        
        # Logging
        if any(w in text_lower for w in ['logging', 'logs', 'audit']):
            props['logging_enabled'] = True
        if any(w in text_lower for w in ['cloudwatch', 'datadog', 'splunk', 'elk']):
            props['centralized_logging'] = True
            props['logging_enabled'] = True
        
        # Security controls
        if any(w in text_lower for w in ['waf', 'web application firewall']):
            props['waf_enabled'] = True
        if any(w in text_lower for w in ['rate limit', 'throttling']):
            props['rate_limiting'] = True
        if any(w in text_lower for w in ['input validation', 'sanitization']):
            props['input_validation'] = True
        if any(w in text_lower for w in ['rbac', 'role-based']):
            props['rbac_enabled'] = True
        if any(w in text_lower for w in ['mfa', 'multi-factor', '2fa']):
            props['mfa_enabled'] = True
        
        # Compliance
        if any(w in text_lower for w in ['hipaa', 'phi']):
            props['compliance_frameworks'].append('HIPAA')
        if 'gdpr' in text_lower:
            props['compliance_frameworks'].append('GDPR')
        if 'pci' in text_lower:
            props['compliance_frameworks'].append('PCI DSS')
        if 'soc 2' in text_lower:
            props['compliance_frameworks'].append('SOC 2')
        
        # Data sensitivity
        if any(w in text_lower for w in ['pii', 'personal', 'phi']):
            props['data_sensitivity'] = 'pii'
        if any(w in text_lower for w in ['payment', 'credit card', 'financial']):
            props['data_sensitivity'] = 'financial'
        
        # Deployment
        if any(w in text_lower for w in ['kubernetes', 'k8s']):
            props['deployment'] = 'k8s'
        if any(w in text_lower for w in ['docker', 'container']):
            props['containerized'] = True
        
        return props


# Global singleton
_nlp_instance: Optional[NLPProcessor] = None

def get_nlp_processor() -> NLPProcessor:
    """Get or create global NLP processor instance."""
    global _nlp_instance
    if _nlp_instance is None:
        _nlp_instance = NLPProcessor()
    return _nlp_instance
