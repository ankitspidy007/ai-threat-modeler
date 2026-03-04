import re
import uuid
import logging
from typing import List, Dict, Any
from ..models import Component, DataFlow, SystemArchitecture
import networkx as nx
from collections import defaultdict

logger = logging.getLogger(__name__)

# Import NLP processor (graceful fallback if unavailable)
try:
    from .nlp_processor import get_nlp_processor, TECH_COMPONENT_MAP
    NLP_AVAILABLE = True
except Exception:
    NLP_AVAILABLE = False
    TECH_COMPONENT_MAP = {}
    logger.warning("NLP processor not available. Using regex-only parsing.")


# Component type synonyms for better detection
COMPONENT_SYNONYMS = {
    'Database': ['db', 'database', 'sql', 'mysql', 'postgresql', 'postgres', 'mongodb', 'mongo', 
                 'dynamodb', 'cassandra', 'redis', 'mariadb', 'oracle', 'mssql', 'documentdb',
                 'cosmosdb', 'firestore'],
    'API': ['api', 'rest api', 'graphql', 'backend', 'api server', 'web service', 'rest', 'grpc'],
    'WebClient': ['frontend', 'ui', 'client', 'spa', 'react', 'vue', 'angular', 'web app', 
                  'mobile app', 'mobile', 'app', 'webapp', 'ios', 'android', 'kiosk'],
    'API Gateway': ['gateway', 'api gateway', 'proxy', 'apigw', 'reverse proxy', 'kong', 'apigee'],
    'Load Balancer': ['load balancer', 'lb', 'alb', 'nlb', 'balancer', 'elb'],
    'Queue': ['queue', 'kafka', 'rabbitmq', 'sqs', 'message queue', 'mq', 'pubsub', 'sns', 
              'mqtt', 'mqtt broker', 'iot core'],
    'Service': ['worker', 'job', 'service', 'microservice', 'lambda', 'function', 'serverless',
                'cloud function', 'azure function'],
    'Object Storage': ['storage', 's3', 'bucket', 'blob', 'object storage', 'cloud storage',
                       'azure blob', 'gcs'],
    'IoT Device': ['iot device', 'sensor', 'medical device', 'glucose monitor', 'heart rate monitor',
                   'blood pressure', 'infusion pump', 'smart device', 'connected device'],
    'CDN': ['cdn', 'cloudfront', 'content delivery', 'edge network', 'akamai'],
    'Secrets Manager': ['secrets manager', 'vault', 'key vault', 'parameter store', 'secrets'],
    'Threat Detection': ['guardduty', 'security hub', 'defender', 'threat detection', 'siem'],
    'Data Warehouse': ['data warehouse', 'snowflake', 'redshift', 'bigquery', 'synapse'],
    'ML Service': ['sagemaker', 'ml', 'machine learning', 'ai', 'model', 'ml pipeline',
                   'vertex ai', 'azure ml'],
    'VPN': ['vpn', 'vpn tunnel', 'site-to-site', 'ipsec'],
    'Bastion': ['bastion', 'bastion host', 'jump box', 'jump server'],
    'Identity Provider': ['idp', 'identity provider', 'auth0', 'okta', 'active directory',
                          'ldap', 'azure ad', 'cognito'],
    'Monitoring': ['monitoring', 'cloudwatch', 'datadog', 'splunk', 'elk', 'prometheus',
                   'grafana', 'new relic'],
    'Backup': ['backup', 'glacier', 'backup vault', 'snapshot'],
}

class ArchitectureParser:
    def parse_known_issues(self, text: str) -> List[Dict]:
        """
        Extract and classify known security issues from description.
        Looks for 'Known Issues:' section and parses each issue.
        """
        issues = []
        
        # Find "Known Issues:" section (case-insensitive)
        match = re.search(
            r'known issues?:(.+?)(?=\n\n[A-Z]|\Z)', 
            text, 
            re.IGNORECASE | re.DOTALL
        )
        
        if not match:
            return issues
        
        issues_text = match.group(1)
        
        # Parse each line/bullet point
        for line in issues_text.split('\n'):
            line = line.strip('- ').strip()
            if not line:
                continue
            
            issue = self._classify_known_issue(line)
            if issue:
                issues.append(issue)
        
        return issues
    
    def _classify_known_issue(self, issue_text: str) -> Dict:
        """Classify a known issue into threat category and severity"""
        issue_lower = issue_text.lower()
        
        # JWT validation issues
        if 'jwt' in issue_lower and any(word in issue_lower for word in ['not validate', 'does not', 'no validation', 'without validation', 'only decode', 'don\'t validate']):
            return {
                'type': 'missing_control',
                'control': 'jwt_validation',
                'severity': 'critical',
                'description': issue_text,
                'suggested_threat_id': 'S-008'
            }
        
        # GraphQL depth limiting
        if 'graphql' in issue_lower and any(word in issue_lower for word in ['no depth', 'depth limit', 'no query depth', 'without depth']):
            return {
                'type': 'missing_control',
                'control': 'query_depth_limiting',
                'severity': 'high',
                'description': issue_text,
                'suggested_threat_id': 'DOS-007'
            }
        
        # Webhook signature validation
        if 'webhook' in issue_lower and any(word in issue_lower for word in ['no signature', 'don\'t verify', 'without signature', 'no verification']):
            return {
                'type': 'missing_control',
                'control': 'webhook_signature_validation',
                'severity': 'high',
                'description': issue_text,
                'suggested_threat_id': 'T-008'
            }
        
        # XSS / inline JavaScript
        if any(word in issue_lower for word in ['inline javascript', 'allows javascript', 'xss', 'user-provided html']):
            return {
                'type': 'missing_control',
                'control': 'html_sanitization',
                'severity': 'critical',
                'description': issue_text,
                'suggested_threat_id': 'T-009'
            }
        
        # CSV injection
        if 'csv' in issue_lower and any(word in issue_lower for word in ['formula', 'injection', 'sanitize', 'doesn\'t sanitize']):
            return {
                'type': 'missing_control',
                'control': 'csv_sanitization',
                'severity': 'medium',
                'description': issue_text,
                'suggested_threat_id': 'T-010'
            }
        
        # CORS wildcard
        if 'cors' in issue_lower and any(word in issue_lower for word in ['wildcard', '*', 'any origin']):
            return {
                'type': 'misconfiguration',
                'control': 'cors_wildcard',
                'severity': 'high',
                'description': issue_text,
                'suggested_threat_id': 'CORS-001'
            }
        
        # Stack traces / detailed errors
        if any(word in issue_lower for word in ['stack trace', 'detailed error', 'error message', 'exposes stack']):
            return {
                'type': 'information_disclosure',
                'control': 'detailed_errors',
                'severity': 'medium',
                'description': issue_text,
                'suggested_threat_id': 'ID-010'
            }
        
        # Session timeout issues
        if 'session' in issue_lower and any(word in issue_lower for word in ['no absolute', 'sliding expiration', 'only sliding', 'timeout']):
            return {
                'type': 'misconfiguration',
                'control': 'absolute_timeout',
                'severity': 'medium',
                'description': issue_text,
                'suggested_threat_id': 'S-007'
            }
        
        # File upload validation
        if 'file' in issue_lower and any(word in issue_lower for word in ['no content-type', 'no validation', 'upload', 'without validation']):
            return {
                'type': 'missing_control',
                'control': 'content_type_validation',
                'severity': 'high',
                'description': issue_text,
                'suggested_threat_id': 'T-011'
            }
        
        # HTTP Basic Auth
        if any(word in issue_lower for word in ['basic auth', 'http basic']):
            return {
                'type': 'weak_auth',
                'control': 'auth_type',
                'severity': 'high',
                'description': issue_text,
                'suggested_threat_id': 'S-001'
            }
        
        # Encryption issues
        if 'encryption' in issue_lower and any(word in issue_lower for word in ['no encryption', 'not encrypted', 'without encryption', 'has no']):
            return {
                'type': 'missing_encryption',
                'control': 'encryption_at_rest',
                'severity': 'critical',
                'description': issue_text,
                'suggested_threat_id': 'ID-005'
            }
        
        # Public access issues
        if any(word in issue_lower for word in ['publicly accessible', 'public access', 'without signed']):
            return {
                'type': 'public_access',
                'control': 'signed_urls',
                'severity': 'medium',
                'description': issue_text,
                'suggested_threat_id': 'ID-006'
            }
        
        # Shared authentication issues
        if any(word in issue_lower for word in ['same authentication', 'shared auth', 'uses same']):
            return {
                'type': 'shared_auth',
                'control': 'admin_separation',
                'severity': 'high',
                'description': issue_text,
                'suggested_threat_id': 'EOP-003'
            }
        
        # Generic issue (couldn't classify)
        return {
            'type': 'unknown',
            'description': issue_text,
            'severity': 'medium'
        }
    
    def _detect_negations(self, text: str) -> Dict[str, bool]:
        """
        Detect explicit negations indicating missing security controls.
        Returns dict of control_name: False for missing controls.
        """
        negations = {}
        text_lower = text.lower()
        
        # JWT validation patterns
        jwt_patterns = [
            r'does not validate jwt',
            r'no jwt validation',
            r'jwt.*not.*validated',
            r'without.*jwt.*validation',
            r'jwt.*validation.*missing'
        ]
        for pattern in jwt_patterns:
            if re.search(pattern, text_lower):
                negations['jwt_validation'] = False
                break
        
        # Encryption at rest patterns
        encryption_patterns = [
            r'no encryption at rest',
            r'not encrypted',
            r'without encryption',
            r'has no encryption',
            r'unencrypted'
        ]
        for pattern in encryption_patterns:
            if re.search(pattern, text_lower):
                negations['encryption_at_rest'] = False
                break
        
        # Signed URLs patterns
        signed_url_patterns = [
            r'without signed urls',
            r'no signed urls',
            r'publicly accessible',
            r'public access'
        ]
        for pattern in signed_url_patterns:
            if re.search(pattern, text_lower):
                negations['signed_urls'] = False
                break
        
        # Admin separation patterns
        admin_sep_patterns = [
            r'same authentication',
            r'shared.*auth',
            r'uses same.*auth',
            r'no.*separate.*admin'
        ]
        for pattern in admin_sep_patterns:
            if re.search(pattern, text_lower):
                negations['admin_separation'] = False
                break
        
        return negations
    
    def parse(self, text: str) -> SystemArchitecture:
        """
        Enhanced parser with NLP integration.
        Uses spaCy NER and dependency parsing when available,
        falls back to regex-based extraction.
        """
        text_lower = text.lower()
        components: Dict[str, Component] = {}
        flows: List[DataFlow] = []

        # ========================================
        # NLP-ENHANCED: Extract entities with NLP
        # ========================================
        nlp_entities = None
        nlp_security_props = {}
        if NLP_AVAILABLE:
            try:
                nlp = get_nlp_processor()
                nlp_entities = nlp.extract_entities(text)
                nlp_security_props = nlp.extract_security_properties(text)
                logger.info(f"NLP extracted {len(nlp_entities.get('technologies', []))} technologies, "
                           f"{len(nlp_entities.get('services', []))} services")
            except Exception as e:
                logger.warning(f"NLP entity extraction failed: {e}")

        # 1. Extract individual microservices (regex)
        microservices = self._extract_microservices(text)
        for service in microservices:
            components[service['id']] = Component(
                id=service['id'],
                name=service['name'],
                type='Service',
                properties=service['properties']
            )
        
        # 2. Extract individual databases (regex)
        databases = self._extract_databases(text)
        for db in databases:
            components[db['id']] = Component(
                id=db['id'],
                name=db['name'],
                type='Database',
                properties=db['properties']
            )
        
        # 3. Extract third-party services (regex)
        third_party = self._extract_third_party_services(text)
        for service in third_party:
            components[service['id']] = Component(
                id=service['id'],
                name=service['name'],
                type=service['type'],
                properties=service['properties']
            )
        
        # 4. NLP-ENHANCED: Add components discovered by NLP that regex missed
        if nlp_entities:
            for tech_entity in nlp_entities.get('technologies', []):
                comp_type = tech_entity.get('component_type')
                if not comp_type:
                    continue
                tech_name = tech_entity['text']
                tech_id = tech_name.lower().replace(' ', '_').replace('.', '_')
                
                # Skip if already exists
                if tech_id in components:
                    continue
                # Also skip if a similar component already exists
                already_found = False
                for cid in components:
                    if tech_id in cid or cid in tech_id:
                        already_found = True
                        break
                if already_found:
                    continue
                
                props = self._infer_properties(text_lower, comp_type)
                components[tech_id] = Component(
                    id=tech_id,
                    name=tech_name.title(),
                    type=comp_type,
                    properties=props
                )
                logger.debug(f"NLP discovered component: {tech_name} ({comp_type})")
            
            # Add NLP-discovered named services
            for svc_entity in nlp_entities.get('services', []):
                svc_name = svc_entity['text']
                svc_id = svc_name.lower().replace(' ', '_').replace('-', '_')
                if svc_id not in components:
                    props = self._infer_properties(text_lower, 'Service')
                    if svc_entity.get('tech_stack'):
                        props['tech_stack'] = svc_entity['tech_stack']
                    components[svc_id] = Component(
                        id=svc_id,
                        name=svc_name,
                        type='Service',
                        properties=props
                    )
        
        # 5. Detect other standard components using synonym detection (original regex)
        found_types = set()
        for component_type, synonyms in COMPONENT_SYNONYMS.items():
            if component_type in ['Database', 'Service']:
                continue
            for synonym in synonyms:
                if synonym in text_lower:
                    found_types.add(component_type)
                    break
        
        for c_type in found_types:
            c_id = c_type.lower().replace(" ", "_")
            if c_id in components:
                continue
            props = self._infer_properties(text_lower, c_type)
            comp = Component(id=c_id, name=c_type, type=c_type, properties=props)
            components[comp.id] = comp

        # 6. Infer data flows (regex-based)
        flows = self._infer_flows(text, components)
        
        # 7. NLP-ENHANCED: Extract additional flows using dependency parsing
        if NLP_AVAILABLE and nlp_entities:
            try:
                nlp = get_nlp_processor()
                nlp_flows = nlp.extract_data_flows(text, components)
                existing_pairs = {(f.source_id, f.target_id) for f in flows}
                for nf in nlp_flows:
                    pair = (nf['source'], nf['target'])
                    if pair not in existing_pairs and nf['source'] in components and nf['target'] in components:
                        flows.append(DataFlow(
                            source_id=nf['source'],
                            target_id=nf['target'],
                            protocol=nf.get('protocol', 'HTTPS'),
                            properties={
                                'trust_boundary': 'inferred',
                                'evidence': nf.get('evidence', ''),
                                'extraction_method': nf.get('method', 'nlp')
                            }
                        ))
                        existing_pairs.add(pair)
                        logger.debug(f"NLP flow: {nf['source']} → {nf['target']}")
            except Exception as e:
                logger.warning(f"NLP flow extraction failed: {e}")
        
        # 8. Detect negations and apply to components
        negations = self._detect_negations(text)
        for comp in components.values():
            for control, value in negations.items():
                comp.properties[control] = value
        
        # 9. NLP-ENHANCED: Apply NLP-extracted security properties
        if nlp_security_props:
            for comp in components.values():
                for key, value in nlp_security_props.items():
                    # Only override if NLP found something definitive
                    if value is not None and key not in ('compliance_frameworks',):
                        if key not in comp.properties or comp.properties[key] in (None, False, 'none'):
                            comp.properties[key] = value
                # Merge compliance frameworks
                if 'compliance_frameworks' in nlp_security_props:
                    existing = comp.properties.get('compliance_frameworks', [])
                    for fw in nlp_security_props['compliance_frameworks']:
                        if fw not in existing:
                            existing.append(fw)
                    comp.properties['compliance_frameworks'] = existing
        
        # 10. Parse known issues
        known_issues = self.parse_known_issues(text)
        
        return SystemArchitecture(
            components=list(components.values()),
            flows=flows,
            metadata={
                'known_issues': known_issues,
                'nlp_enhanced': NLP_AVAILABLE and nlp_entities is not None
            }
        )
    
    def _extract_microservices(self, text: str) -> List[Dict]:
        """
        Extract individual microservices from numbered lists or bullet points.
        Patterns:
        - "1. User Service (Node.js + Express):"
        - "- Payment Service (Java Spring Boot):"
        - "User Service: Handles authentication"
        """
        services = []
        text_lower = text.lower()
        
        # Pattern 1: Numbered lists with service descriptions
        # Matches: "1. User Service (Node.js + Express):"
        pattern1 = r'(?:^|\n)\s*\d+\.\s+([A-Z][A-Za-z\s]+Service)\s*\(([^)]+)\):\s*([^\n]+)'
        matches = re.finditer(pattern1, text, re.MULTILINE | re.IGNORECASE)
        
        for match in matches:
            service_name = match.group(1).strip()
            tech_stack = match.group(2).strip()
            description = match.group(3).strip()
            
            service_id = service_name.lower().replace(' ', '_').replace('-', '_')
            
            # Infer properties from tech stack and description
            props = self._infer_service_properties(tech_stack, description, text_lower)
            props['tech_stack'] = tech_stack
            props['description'] = description
            
            services.append({
                'id': service_id,
                'name': service_name,
                'properties': props
            })
        
        # Pattern 2: Bullet points
        # Matches: "- Payment Service (Java Spring Boot):"
        pattern2 = r'(?:^|\n)\s*[-•]\s+([A-Z][A-Za-z\s]+Service)\s*\(([^)]+)\):\s*([^\n]+)'
        matches = re.finditer(pattern2, text, re.MULTILINE | re.IGNORECASE)
        
        for match in matches:
            service_name = match.group(1).strip()
            tech_stack = match.group(2).strip()
            description = match.group(3).strip()
            
            service_id = service_name.lower().replace(' ', '_').replace('-', '_')
            
            # Skip if already added
            if any(s['id'] == service_id for s in services):
                continue
            
            props = self._infer_service_properties(tech_stack, description, text_lower)
            props['tech_stack'] = tech_stack
            props['description'] = description
            
            services.append({
                'id': service_id,
                'name': service_name,
                'properties': props
            })
        
        return services
    
    def _extract_databases(self, text: str) -> List[Dict]:
        """
        Extract individual database instances.
        Detects: PostgreSQL, MongoDB, MySQL, Redis, Elasticsearch, etc.
        """
        databases = []
        text_lower = text.lower()
        
        # Database type mappings
        db_types = {
            'postgresql': ['postgresql', 'postgres'],
            'mongodb': ['mongodb', 'mongo'],
            'mysql': ['mysql', 'mariadb'],
            'redis': ['redis'],
            'elasticsearch': ['elasticsearch', 'elastic search'],
            'dynamodb': ['dynamodb'],
            'cassandra': ['cassandra'],
            'redshift': ['redshift'],
            'snowflake': ['snowflake'],
            'bigquery': ['bigquery']
        }
        
        for db_name, keywords in db_types.items():
            for keyword in keywords:
                if keyword in text_lower:
                    db_id = db_name.lower()
                    
                    # Skip if already added
                    if any(db['id'] == db_id for db in databases):
                        continue
                    
                    # Extract context around the database mention
                    context = self._extract_context(text_lower, keyword, 100)
                    
                    props = {
                        'db_type': db_name,
                        'encryption_at_rest': None,
                        'backup_enabled': None,
                        'replication': None
                    }
                    
                    # Infer properties from context
                    if 'read replica' in context or 'replication' in context:
                        props['replication'] = True
                    if 'master-slave' in context:
                        props['replication'] = 'master-slave'
                    if 'cluster' in context:
                        props['clustered'] = True
                    if 'encrypted' in context or 'encryption' in context:
                        props['encryption_at_rest'] = True
                    
                    databases.append({
                        'id': db_id,
                        'name': db_name.upper() if db_name in ['mysql', 'redis'] else db_name.title(),
                        'properties': props
                    })
                    break
        
        return databases
    
    def _extract_third_party_services(self, text: str) -> List[Dict]:
        """
        Extract third-party service integrations.
        """
        services = []
        text_lower = text.lower()
        
        # Third-party service mappings
        third_party_map = {
            'stripe': {'type': 'Payment Processor', 'category': 'payment'},
            'paypal': {'type': 'Payment Processor', 'category': 'payment'},
            'square': {'type': 'Payment Processor', 'category': 'payment'},
            'sendgrid': {'type': 'Email Service', 'category': 'communication'},
            'twilio': {'type': 'SMS Service', 'category': 'communication'},
            'firebase': {'type': 'Push Notification Service', 'category': 'communication'},
            'fedex': {'type': 'Shipping API', 'category': 'logistics'},
            'ups': {'type': 'Shipping API', 'category': 'logistics'},
            'dhl': {'type': 'Shipping API', 'category': 'logistics'},
            'zendesk': {'type': 'Customer Support', 'category': 'support'},
            'sift': {'type': 'Fraud Detection', 'category': 'security'},
            'auth0': {'type': 'Identity Provider', 'category': 'authentication'},
            'okta': {'type': 'Identity Provider', 'category': 'authentication'}
        }
        
        for service_name, info in third_party_map.items():
            if service_name in text_lower:
                service_id = f"{service_name}_external"
                
                props = {
                    'external': True,
                    'third_party': True,
                    'category': info['category'],
                    'trust_boundary': 'external'
                }
                
                services.append({
                    'id': service_id,
                    'name': service_name.title(),
                    'type': info['type'],
                    'properties': props
                })
        
        return services
    
    def _infer_service_properties(self, tech_stack: str, description: str, full_text: str) -> Dict:
        """Infer service properties from tech stack and description."""
        props = self._infer_properties(full_text, 'Service')
        
        # Parse tech stack
        tech_lower = tech_stack.lower()
        if 'node' in tech_lower or 'express' in tech_lower:
            props['language'] = 'Node.js'
        elif 'python' in tech_lower or 'fastapi' in tech_lower or 'django' in tech_lower:
            props['language'] = 'Python'
        elif 'java' in tech_lower or 'spring' in tech_lower:
            props['language'] = 'Java'
        elif 'go' in tech_lower or 'golang' in tech_lower:
            props['language'] = 'Go'
        
        # Parse description for specific features
        desc_lower = description.lower()
        if 'jwt' in desc_lower:
            props['has_jwt'] = True
        if 'webhook' in desc_lower:
            props['has_webhooks'] = True
        if 'graphql' in desc_lower:
            props['has_graphql'] = True
        
        return props
    
    def _extract_context(self, text: str, keyword: str, chars: int = 100) -> str:
        """Extract surrounding context around a keyword."""
        idx = text.find(keyword)
        if idx == -1:
            return ""
        start = max(0, idx - chars)
        end = min(len(text), idx + len(keyword) + chars)
        return text[start:end]
    
    def _infer_flows(self, text: str, components: Dict[str, Component]) -> List[DataFlow]:
        """
        Infer data flows between components based on descriptions and typical patterns.
        Uses flexible type-based matching instead of hardcoded IDs.
        """
        flows = []
        text_lower = text.lower()
        
        # Get components by type
        frontend_comps = [cid for cid, c in components.items() if c.type in ['WebClient', 'Mobile App']]
        api_comps = [cid for cid, c in components.items() if c.type in ['API', 'API Gateway', 'Load Balancer']]
        service_comps = [cid for cid, c in components.items() if c.type == 'Service']
        db_comps = [cid for cid, c in components.items() if c.type == 'Database']
        storage_comps = [cid for cid, c in components.items() if c.type == 'Object Storage']
        queue_comps = [cid for cid, c in components.items() if c.type == 'Queue']
        idp_comps = [cid for cid, c in components.items() if c.type == 'Identity Provider']
        external_comps = [cid for cid, c in components.items() if c.properties.get('external', False)]
        
        # 1. Frontend → API/Gateway (typical web/mobile app pattern)
        for frontend_id in frontend_comps:
            for api_id in api_comps:
                flows.append(DataFlow(
                    source_id=frontend_id,
                    target_id=api_id,
                    protocol='HTTPS',
                    properties={'trust_boundary': 'internet', 'crosses_trust_boundary': True}
                ))
        
        # 2. API/Gateway → Services (if services exist)
        if service_comps:
            for api_id in api_comps:
                for service_id in service_comps:
                    flows.append(DataFlow(
                        source_id=api_id,
                        target_id=service_id,
                        protocol='HTTPS',
                        properties={'trust_boundary': 'internal'}
                    ))
        
        # 3. API → Database (direct connection if no services layer)
        if not service_comps and api_comps and db_comps:
            for api_id in api_comps:
                for db_id in db_comps:
                    flows.append(DataFlow(
                        source_id=api_id,
                        target_id=db_id,
                        protocol='TCP',
                        properties={'trust_boundary': 'internal'}
                    ))
        
        # 4. Services → Databases
        for service_id in service_comps:
            for db_id in db_comps:
                # Check if database is mentioned in service description or just connect all
                flows.append(DataFlow(
                    source_id=service_id,
                    target_id=db_id,
                    protocol='TCP',
                    properties={'trust_boundary': 'internal'}
                ))
        
        # 5. API/Services → Identity Provider (for authentication)
        if idp_comps:
            auth_consumers = api_comps + service_comps
            for consumer_id in auth_consumers:
                for idp_id in idp_comps:
                    flows.append(DataFlow(
                        source_id=consumer_id,
                        target_id=idp_id,
                        protocol='HTTPS',
                        properties={'trust_boundary': 'internal'}
                    ))
        
        # 6. Services → Object Storage (if storage mentioned)
        if storage_comps:
            for service_id in service_comps:
                service_desc = components[service_id].properties.get('description', '').lower()
                if 's3' in service_desc or 'upload' in service_desc or 'storage' in service_desc or 'file' in service_desc:
                    for storage_id in storage_comps:
                        flows.append(DataFlow(
                            source_id=service_id,
                            target_id=storage_id,
                            protocol='HTTPS',
                            properties={'trust_boundary': 'internal'}
                        ))
        
        # 7. Services → Queue (if queue mentioned)
        if queue_comps:
            for service_id in service_comps:
                service_desc = components[service_id].properties.get('description', '').lower()
                if 'kafka' in service_desc or 'queue' in service_desc or 'message' in service_desc or 'event' in service_desc:
                    for queue_id in queue_comps:
                        flows.append(DataFlow(
                            source_id=service_id,
                            target_id=queue_id,
                            protocol='TCP',
                            properties={'trust_boundary': 'internal'}
                        ))
        
        # 8. Services → External APIs (third-party integrations)
        for service_id in service_comps:
            service_desc = components[service_id].properties.get('description', '').lower()
            for ext_id in external_comps:
                ext_name = components[ext_id].name.lower()
                if ext_name in service_desc or ext_id in service_desc:
                    flows.append(DataFlow(
                        source_id=service_id,
                        target_id=ext_id,
                        protocol='HTTPS',
                        properties={'trust_boundary': 'external', 'crosses_trust_boundary': True}
                    ))
        
        # 9. Infer from text patterns (e.g., "A connected to B")
        connection_patterns = [
            (r'(\w+)\s+connected to\s+(\w+)', 'TCP'),
            (r'(\w+)\s+communicates with\s+(\w+)', 'HTTPS'),
            (r'(\w+)\s+sends data to\s+(\w+)', 'HTTPS'),
            (r'(\w+)\s+queries\s+(\w+)', 'TCP'),
            (r'(\w+)\s+uses\s+(\w+)', 'HTTPS'),
        ]
        
        import re
        for pattern, protocol in connection_patterns:
            matches = re.findall(pattern, text_lower)
            for source_name, target_name in matches:
                # Try to find matching components
                source_id = None
                target_id = None
                
                for cid, comp in components.items():
                    if source_name in comp.name.lower() or source_name in cid.lower():
                        source_id = cid
                    if target_name in comp.name.lower() or target_name in cid.lower():
                        target_id = cid
                
                if source_id and target_id and source_id != target_id:
                    # Avoid duplicates
                    existing = any(f.source_id == source_id and f.target_id == target_id for f in flows)
                    if not existing:
                        flows.append(DataFlow(
                            source_id=source_id,
                            target_id=target_id,
                            protocol=protocol,
                            properties={'trust_boundary': 'inferred'}
                        ))
        
        return flows


    def _infer_properties(self, text_lower: str, component_type: str) -> Dict:
        """Enhanced property inference based on text analysis."""
        # Set appropriate defaults for security properties
        # Use 'none' and False instead of None so threat rules can match
        props = {
            'auth_type': 'none',  # Default to no auth unless explicitly mentioned
            'encryption_at_rest': False,  # Default to not encrypted
            'logging_enabled': False,  # Default to no logging
            'input_validation': False,  # Default to no validation
            'rate_limiting': False,  # Default to no rate limiting
            'public_access': False,
            'compliance_frameworks': []
        }
        
        # Cloud provider detection
        if 'aws' in text_lower or 's3' in text_lower or 'ec2' in text_lower or 'lambda' in text_lower or 'rds' in text_lower or 'cognito' in text_lower:
            props['cloud_provider'] = 'aws'
        elif 'azure' in text_lower or 'blob storage' in text_lower or 'azure ad' in text_lower:
            props['cloud_provider'] = 'azure'
        elif 'gcp' in text_lower or 'google cloud' in text_lower or 'firestore' in text_lower or 'cloud storage' in text_lower:
            props['cloud_provider'] = 'gcp'
        
        # Database type detection
        if component_type == 'Database':
            if 'mongodb' in text_lower or 'mongo' in text_lower:
                props['db_type'] = 'mongodb'
            elif 'dynamodb' in text_lower:
                props['db_type'] = 'dynamodb'
            elif 'cosmosdb' in text_lower:
                props['db_type'] = 'cosmosdb'
            elif 'firestore' in text_lower:
                props['db_type'] = 'firestore'
            elif 'cassandra' in text_lower:
                props['db_type'] = 'cassandra'
            elif 'redis' in text_lower:
                props['db_type'] = 'redis'
            elif 'mysql' in text_lower:
                props['db_type'] = 'mysql'
            elif 'postgresql' in text_lower or 'postgres' in text_lower:
                props['db_type'] = 'postgresql'
            elif 'mssql' in text_lower or 'sql server' in text_lower:
                props['db_type'] = 'mssql'
            elif 'oracle' in text_lower:
                props['db_type'] = 'oracle'
        
        # Public access detection
        if component_type in ['WebClient', 'API Gateway', 'CDN']:
            props['public_access'] = True
        if 'public' in text_lower or 'internet' in text_lower:
            props['public_access'] = True
        
        # Managed Authentication Service Detection (takes precedence)
        if 'cognito' in text_lower:
            props['auth_type'] = 'cognito'
            props['idp_integration'] = True
        elif 'auth0' in text_lower:
            props['auth_type'] = 'auth0'
            props['idp_integration'] = True
        elif 'okta' in text_lower:
            props['auth_type'] = 'okta'
            props['idp_integration'] = True
        elif 'azure ad' in text_lower or 'azure active directory' in text_lower:
            props['auth_type'] = 'azure_ad'
            props['idp_integration'] = True
        elif 'google identity' in text_lower or 'firebase auth' in text_lower:
            props['auth_type'] = 'google_identity'
            props['idp_integration'] = True
        # Standard authentication methods (lower priority than managed services)
        elif 'jwt' in text_lower or 'json web token' in text_lower:
            props['auth_type'] = 'jwt'
            props['has_jwt'] = True
        elif 'oauth' in text_lower or 'oauth2' in text_lower or 'oidc' in text_lower:
            props['auth_type'] = 'oauth2'
            props['idp_integration'] = True
        elif 'basic auth' in text_lower:
            props['auth_type'] = 'basic'
        elif 'no auth' in text_lower or 'unauthenticated' in text_lower or 'without auth' in text_lower:
            props['auth_type'] = 'none'
        elif 'api key' in text_lower:
            props['auth_type'] = 'api_key'
        
        # Encryption detection
        if 'encrypted' in text_lower or 'encryption at rest' in text_lower or 'tde' in text_lower:
            props['encryption_at_rest'] = True
        if 'https' in text_lower or 'tls' in text_lower or 'ssl' in text_lower:
            props['encryption_in_transit'] = True
        if 'mtls' in text_lower or 'mutual tls' in text_lower:
            props['mtls_enabled'] = True
        if 'kms' in text_lower or 'key management' in text_lower:
            props['kms_enabled'] = True
        
        # Logging detection
        if 'logging' in text_lower or 'logs' in text_lower or 'audit' in text_lower:
            props['logging_enabled'] = True
        if 'cloudwatch' in text_lower or 'datadog' in text_lower or 'splunk' in text_lower or 'elk' in text_lower:
            props['centralized_logging'] = True
            props['logging_enabled'] = True
        if 'cloudtrail' in text_lower:
            props['audit_logging'] = True
            props['logging_enabled'] = True
        
        # Security controls
        if 'waf' in text_lower or 'web application firewall' in text_lower:
            props['waf_enabled'] = True
        if 'rate limit' in text_lower or 'throttling' in text_lower:
            props['rate_limiting'] = True
        if 'input validation' in text_lower or 'sanitization' in text_lower:
            props['input_validation'] = True
        if 'rbac' in text_lower or 'role-based' in text_lower:
            props['rbac_enabled'] = True
        if 'mfa' in text_lower or 'multi-factor' in text_lower or '2fa' in text_lower:
            props['mfa_enabled'] = True
        
        # Data sensitivity
        if 'pii' in text_lower or 'personal' in text_lower or 'phi' in text_lower:
            props['data_sensitivity'] = 'pii'
        if 'payment' in text_lower or 'credit card' in text_lower or 'financial' in text_lower:
            props['data_sensitivity'] = 'financial'
        if 'credential' in text_lower or 'password' in text_lower:
            props['data_sensitivity'] = 'credentials'
        
        # Compliance frameworks
        if 'hipaa' in text_lower or 'phi' in text_lower:
            props['compliance_frameworks'].append('HIPAA')
        if 'gdpr' in text_lower:
            props['compliance_frameworks'].append('GDPR')
        if 'pci' in text_lower or 'pci dss' in text_lower:
            props['compliance_frameworks'].append('PCI DSS')
        if 'soc 2' in text_lower:
            props['compliance_frameworks'].append('SOC 2')
        if 'fda' in text_lower or '510(k)' in text_lower:
            props['compliance_frameworks'].append('FDA')
        
        # Deployment environment
        if 'kubernetes' in text_lower or 'k8s' in text_lower:
            props['deployment'] = 'k8s'
        if 'docker' in text_lower or 'container' in text_lower:
            props['containerized'] = True
        if 'aws' in text_lower or 'azure' in text_lower or 'gcp' in text_lower or 'cloud' in text_lower:
            props['cloud_provider'] = True
        
        # IoT specific
        if component_type == 'IoT Device' or 'iot' in text_lower or 'sensor' in text_lower:
            props['is_iot_device'] = True
            if 'ota' in text_lower or 'firmware update' in text_lower:
                props['ota_updates'] = True
            if 'medical device' in text_lower:
                props['medical_device'] = True
        
        # ML/AI specific
        if 'ml' in text_lower or 'machine learning' in text_lower or 'sagemaker' in text_lower or 'model' in text_lower:
            props['ml_pipeline'] = True
            if 'training' in text_lower:
                props['model_training'] = True
            if 'anonymized' in text_lower or 'de-identified' in text_lower:
                props['data_anonymization'] = True
        
        # Mobile app specific
        if component_type == 'WebClient' and ('mobile' in text_lower or 'ios' in text_lower or 'android' in text_lower):
            props['mobile_app'] = True
            if 'offline' in text_lower:
                props['offline_capability'] = True
        
        # GraphQL detection
        if 'graphql' in text_lower:
            props['has_graphql'] = True
            # Check for depth limiting
            if 'depth limit' in text_lower or 'query depth' in text_lower:
                props['query_depth_limiting'] = True
            else:
                props['query_depth_limiting'] = False
        
        # Webhook detection
        if 'webhook' in text_lower:
            props['has_webhooks'] = True
            # Check for signature validation
            if 'signature' in text_lower and ('verif' in text_lower or 'validat' in text_lower):
                props['webhook_signature_validation'] = True
            else:
                props['webhook_signature_validation'] = False
        
        # XSS / HTML sanitization
        if any(phrase in text_lower for phrase in ['user-provided html', 'user html', 'inline javascript', 'allows javascript']):
            props['user_html_input'] = True
            if 'sanitiz' in text_lower or 'escape' in text_lower or 'csp' in text_lower:
                props['html_sanitization'] = True
            else:
                props['html_sanitization'] = False
        
        # CSV import detection
        if 'csv' in text_lower and ('import' in text_lower or 'upload' in text_lower):
            props['csv_import'] = True
            if 'sanitiz' in text_lower or 'formula' in text_lower:
                props['csv_sanitization'] = True
            else:
                props['csv_sanitization'] = False
        
        # CORS configuration
        if 'cors' in text_lower:
            if 'wildcard' in text_lower or 'cors.*\*' in text_lower or 'allow.*origin.*\*' in text_lower:
                props['cors_wildcard'] = True
            else:
                props['cors_wildcard'] = False
        
        # Environment detection
        if 'production' in text_lower or 'prod' in text_lower:
            props['environment'] = 'production'
        elif 'development' in text_lower or 'dev' in text_lower:
            props['environment'] = 'development'
        
        # Error handling
        if any(phrase in text_lower for phrase in ['stack trace', 'detailed error', 'error message', 'debug mode']):
            props['detailed_errors'] = True
        
        # Session timeout
        if 'session' in text_lower:
            if 'sliding' in text_lower:
                props['session_timeout_type'] = 'sliding'
            if 'absolute timeout' in text_lower:
                props['absolute_timeout'] = True
            else:
                props['absolute_timeout'] = False
        
        # File upload
        if 'upload' in text_lower or 'file upload' in text_lower:
            props['file_upload'] = True
            if 'content-type' in text_lower and 'validat' in text_lower:
                props['content_type_validation'] = True
            else:
                props['content_type_validation'] = False
        
        # Third-party integrations
        if 'api' in text_lower and any(vendor in text_lower for vendor in ['stripe', 'twilio', 'sendgrid', 'firebase']):
            props['third_party_integration'] = True
        if 'fhir' in text_lower or 'hl7' in text_lower:
            props['healthcare_integration'] = True
        
        # Backup and DR
        if 'backup' in text_lower or 'glacier' in text_lower:
            props['backup_enabled'] = True
        if 'multi-region' in text_lower or 'failover' in text_lower or 'replication' in text_lower:
            props['multi_region'] = True
            props['disaster_recovery'] = True
        
        # Monitoring
        if 'guardduty' in text_lower or 'threat detection' in text_lower:
            props['threat_detection'] = True
        if 'monitoring' in text_lower:
            props['monitoring_enabled'] = True
        
        return props

    def _infer_flow_properties(self, text_lower: str, source: Component, target: Component) -> Dict:
        """Infer data flow properties based on source and target components."""
        props = {
            'trust_boundary': 'internal',
            'authenticated': None
        }
        
        # Trust boundary detection
        if source.type == 'WebClient':
            props['trust_boundary'] = 'internet'
            props['protocol'] = 'http'
        elif source.type in ['API Gateway', 'Load Balancer'] and target.type in ['API', 'Service']:
            props['trust_boundary'] = 'internal'
            props['protocol'] = 'http'
        else:
            props['protocol'] = 'tcp'
        
        # Protocol override based on text
        if 'https' in text_lower:
            props['protocol'] = 'https'
        if 'grpc' in text_lower:
            props['protocol'] = 'grpc'
        if 'websocket' in text_lower or 'ws' in text_lower:
            props['protocol'] = 'websocket'
        
        return props
