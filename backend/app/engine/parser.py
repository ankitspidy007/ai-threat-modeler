import re
import uuid
import logging
from typing import List, Dict, Any, Optional
from ..models import Asset, Component, DataFlow, SystemArchitecture, TrustBoundary
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
    def _infer_trust_level(self, component_type: str, props: Dict[str, Any]) -> str:
        if props.get('external'):
            return 'external'
        if props.get('public_access') or component_type in ['WebClient', 'API Gateway', 'CDN', 'Load Balancer']:
            return 'public'
        if component_type in ['Identity Provider', 'Secrets Manager', 'Database', 'Object Storage']:
            return 'restricted'
        return 'internal'

    def _infer_data_type(self, source: Optional[Component], target: Optional[Component]) -> str:
        sensitivity = None
        if source:
            sensitivity = (source.properties or {}).get('data_sensitivity')
        if not sensitivity and target:
            sensitivity = (target.properties or {}).get('data_sensitivity')
        if sensitivity:
            return sensitivity
        if target and target.type in ['Secrets Manager']:
            return 'secrets'
        if target and target.type in ['Database', 'Object Storage']:
            return 'application_data'
        return 'application_data'

    def _extract_component_context(self, text: str, component_name: str, radius: int = 220) -> str:
        """Extract a component-local text window so properties are inferred from nearby context."""
        if not component_name:
            return text.lower()

        pattern = re.escape(component_name)
        match = re.search(pattern, text, re.IGNORECASE)
        if not match:
            normalized_name = component_name.replace("_", " ").replace("-", " ")
            match = re.search(re.escape(normalized_name), text, re.IGNORECASE)
        if not match:
            return text.lower()

        start = max(0, match.start() - radius)
        end = min(len(text), match.end() + radius)
        return text[start:end].lower()

    def _apply_security_properties(self, props: Dict[str, Any], security_props: Dict[str, Any]) -> Dict[str, Any]:
        """Merge extracted security properties into component properties conservatively."""
        if not security_props:
            return props

        for key, value in security_props.items():
            if value is None or key == 'compliance_frameworks':
                continue
            if key not in props or props[key] in (None, False, 'none', '', []):
                props[key] = value

        if 'compliance_frameworks' in security_props:
            existing = props.get('compliance_frameworks', [])
            for framework in security_props['compliance_frameworks']:
                if framework not in existing:
                    existing.append(framework)
            props['compliance_frameworks'] = existing

        return props

    def _collect_assumptions(self, components: Dict[str, Component], flows: List[DataFlow]) -> List[Dict[str, str]]:
        """Capture unknown or inferred areas so users can validate them explicitly."""
        assumptions = []

        for component in components.values():
            props = component.properties
            if props.get('auth_type') == 'none' and component.type in ['API', 'Service', 'API Gateway', 'Identity Provider']:
                assumptions.append({
                    'scope': component.id,
                    'type': 'authentication',
                    'message': f"Authentication was not clearly identified for {component.name}."
                })
            if props.get('encryption_at_rest') is False and component.type in ['Database', 'Object Storage', 'Secrets Manager']:
                assumptions.append({
                    'scope': component.id,
                    'type': 'encryption',
                    'message': f"Encryption at rest was not explicitly confirmed for {component.name}."
                })
            if not props.get('logging_enabled') and component.type in ['API', 'Service', 'Database']:
                assumptions.append({
                    'scope': component.id,
                    'type': 'logging',
                    'message': f"Audit or application logging was not clearly identified for {component.name}."
                })

        for flow in flows:
            if flow.properties.get('trust_boundary') == 'inferred':
                assumptions.append({
                    'scope': f"{flow.source_id}->{flow.target_id}",
                    'type': 'trust_boundary',
                    'message': f"Trust boundary for flow {flow.source_id} -> {flow.target_id} was inferred."
                })

        return assumptions

    def _build_trust_boundaries(self, components: Dict[str, Component], flows: List[DataFlow]) -> List[TrustBoundary]:
        """Summarize trust boundaries crossed by the modeled architecture."""
        boundaries: Dict[str, TrustBoundary] = {}

        for component in components.values():
            level = component.trust_level or 'internal'
            if level not in boundaries:
                boundary_type = 'network_zone'
                if level == 'public':
                    boundary_type = 'external'
                elif level == 'restricted':
                    boundary_type = 'sensitive'
                elif level == 'external':
                    boundary_type = 'third_party'
                boundaries[level] = TrustBoundary(
                    name=level,
                    boundary_type=boundary_type,
                    components=[]
                )
            boundaries[level].components.append(component.id)

        for flow in flows:
            boundary = flow.properties.get('trust_boundary')
            if boundary and boundary not in boundaries:
                boundaries[boundary] = TrustBoundary(
                    name=boundary,
                    boundary_type='flow_boundary',
                    components=[flow.source_id, flow.target_id],
                    description='Derived from inferred communication boundary.',
                )

        return list(boundaries.values())

    def _extract_assets(self, components: Dict[str, Component], flows: List[DataFlow]) -> List[Asset]:
        assets: List[Asset] = []
        for component in components.values():
            props = component.properties or {}
            sensitivity = props.get('data_sensitivity')
            if component.type in ['Database', 'Object Storage', 'Secrets Manager', 'Data Warehouse'] or sensitivity:
                asset_name = f"{component.name} data"
                asset_sensitivity = sensitivity or ('secrets' if component.type == 'Secrets Manager' else 'internal')
                related_flows = [
                    f"{flow.source_id}->{flow.target_id}"
                    for flow in flows
                    if flow.source_id == component.id or flow.target_id == component.id
                ]
                assets.append(Asset(
                    name=asset_name,
                    sensitivity=asset_sensitivity,
                    location=component.name,
                    asset_type='credential_store' if component.type == 'Secrets Manager' else 'data_store',
                    related_component_id=component.id,
                    related_data_flows=related_flows,
                ))
        return assets

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

        waf_patterns = [
            r'no waf',
            r'without waf',
            r'missing waf',
            r'no web application firewall',
            r'without web application firewall',
        ]
        for pattern in waf_patterns:
            if re.search(pattern, text_lower):
                negations['waf_enabled'] = False
                break
        
        return negations
    
    def parse(self, text: str) -> SystemArchitecture:
        """
        Enhanced parser with NLP integration.
        Uses the hybrid NLP pipeline when available,
        with rule-based extraction as the fallback.
        """
        text_lower = text.lower()
        components: Dict[str, Component] = {}
        flows: List[DataFlow] = []

        # ========================================
        # NLP-ENHANCED: Extract entities with NLP
        # ========================================
        nlp_entities = None
        nlp_security_props = {}
        nlp = None
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

                component_context = self._extract_component_context(text, tech_name)
                props = self._infer_properties(component_context, comp_type)
                if nlp:
                    props = self._apply_security_properties(props, nlp.extract_security_properties(component_context))
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
                    component_context = self._extract_component_context(text, svc_name)
                    props = self._infer_properties(component_context, 'Service')
                    if nlp:
                        props = self._apply_security_properties(props, nlp.extract_security_properties(component_context))
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
            for synonym in synonyms:
                if synonym in text_lower:
                    found_types.add(component_type)
                    break
        
        for c_type in found_types:
            c_id = c_type.lower().replace(" ", "_")
            if c_id in components:
                continue
            component_context = self._extract_component_context(text, c_type)
            props = self._infer_properties(component_context, c_type)
            if nlp:
                props = self._apply_security_properties(props, nlp.extract_security_properties(component_context))
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
                component_context = self._extract_component_context(text, comp.name)
                scoped_security_props = nlp.extract_security_properties(component_context) if nlp else nlp_security_props
                comp.properties = self._apply_security_properties(comp.properties, scoped_security_props)

        for comp in components.values():
            for control, value in negations.items():
                comp.properties[control] = value

        # 9.5. Normalize trust levels and enrich flow metadata for architecture modeling
        for comp in components.values():
            comp.trust_level = self._infer_trust_level(comp.type, comp.properties or {})
            comp.properties['trust_level'] = comp.trust_level

        component_map = components
        for flow in flows:
            flow.protocol = (flow.protocol or "").lower()
            source = component_map.get(flow.source_id)
            target = component_map.get(flow.target_id)
            if source and target:
                flow.data_type = self._infer_data_type(source, target)
                if not flow.properties.get('trust_boundary'):
                    if source.trust_level != target.trust_level:
                        flow.properties['trust_boundary'] = f"{source.trust_level}_to_{target.trust_level}"
                        flow.properties['crosses_trust_boundary'] = True
                    else:
                        flow.properties['trust_boundary'] = source.trust_level
                flow.properties['source_trust_level'] = source.trust_level
                flow.properties['target_trust_level'] = target.trust_level
            flow.assumed = flow.properties.get('trust_boundary') == 'inferred' or flow.properties.get('extraction_method') == 'nlp'
            flow.properties['assumed'] = flow.assumed
        
        # 10. Parse known issues
        known_issues = self.parse_known_issues(text)
        assumptions = self._collect_assumptions(components, flows)
        trust_boundaries = self._build_trust_boundaries(components, flows)
        assets = self._extract_assets(components, flows)
        
        return SystemArchitecture(
            components=list(components.values()),
            flows=flows,
            trust_boundaries=trust_boundaries,
            assets=assets,
            metadata={
                'known_issues': known_issues,
                'nlp_enhanced': NLP_AVAILABLE and nlp_entities is not None,
                'global_security_signals': nlp_security_props,
                'assumptions': assumptions,
                'trust_boundaries': [boundary.model_dump() for boundary in trust_boundaries],
                'assets': [asset.model_dump() for asset in assets],
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
            local_context = f"{service_name} {tech_stack} {description}"
            props = self._infer_service_properties(tech_stack, description, local_context)
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
            
            local_context = f"{service_name} {tech_stack} {description}"
            props = self._infer_service_properties(tech_stack, description, local_context)
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
                    props = self._apply_security_properties(props, self._infer_properties(context, 'Database'))
                    
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
                props = self._apply_security_properties(props, self._infer_properties(self._extract_context(text_lower, service_name, 120), info['type']))
                
                services.append({
                    'id': service_id,
                    'name': service_name.title(),
                    'type': info['type'],
                    'properties': props
                })
        
        return services
    
    def _infer_service_properties(self, tech_stack: str, description: str, full_text: str) -> Dict:
        """Infer service properties from tech stack and description."""
        local_context = f"{tech_stack} {description} {full_text}".lower()
        props = self._infer_properties(local_context, 'Service')
        
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
        text_lower = (text_lower or "").lower()
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
        if any(phrase in text_lower for phrase in ['no waf', 'without waf', 'missing waf', 'no web application firewall', 'without web application firewall']):
            props['waf_enabled'] = False
        elif 'waf' in text_lower or 'web application firewall' in text_lower:
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
        if ('aws' in text_lower or 'azure' in text_lower or 'gcp' in text_lower or 'cloud' in text_lower) and 'cloud_provider' not in props:
            props['deployment_model'] = 'cloud'
        
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
            if 'wildcard' in text_lower or 'cors.*\\*' in text_lower or 'allow.*origin.*\\*' in text_lower:
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
