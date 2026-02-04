import re
import uuid
from typing import List, Dict
from ..models import SystemArchitecture, Component, DataFlow

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
    def parse(self, text: str) -> SystemArchitecture:
        """
        Enhanced heuristic parser with synonym detection and improved property inference.
        """
        text_lower = text.lower()
        components: Dict[str, Component] = {}
        flows: List[DataFlow] = []

        # 1. Component Detection with Synonyms
        found_types = set()
        for component_type, synonyms in COMPONENT_SYNONYMS.items():
            for synonym in synonyms:
                if synonym in text_lower:
                    found_types.add(component_type)
                    break
        
        # Create components with enhanced property inference
        for c_type in found_types:
            c_id = c_type.lower().replace(" ", "_")
            
            # Enhanced property inference
            props = self._infer_properties(text_lower, c_type)
            
            comp = Component(
                id=c_id,
                name=c_type,
                type=c_type,
                properties=props
            )
            components[comp.id] = comp

        # 2. Flow Inference
        layers = ['webclient', 'load_balancer', 'api_gateway', 'api', 'service', 'queue', 'worker', 'database', 'object_storage']
        
        sorted_comps = []
        for layer in layers:
            for cid in components:
                if cid == layer:
                    sorted_comps.append(components[cid])
        
        # Link them sequentially
        for i in range(len(sorted_comps) - 1):
            source = sorted_comps[i]
            target = sorted_comps[i+1]
            
            # Enhanced flow properties
            flow_props = self._infer_flow_properties(text_lower, source, target)
            
            # Extract protocol from properties (it shouldn't be in both places)
            protocol = flow_props.pop('protocol', 'tcp')
            
            flows.append(DataFlow(
                source_id=source.id,
                target_id=target.id,
                protocol=protocol,
                properties=flow_props
            ))

        # Add Object Storage links
        if 'object_storage' in components:
            potential_sources = ['api', 'worker', 'service']
            for src in potential_sources:
                if src in components:
                    flows.append(DataFlow(
                        source_id=src,
                        target_id='object_storage',
                        protocol='https',
                        properties={"trust_boundary": "internal"}
                    ))

        return SystemArchitecture(
            components=list(components.values()),
            flows=flows
        )

    def _infer_properties(self, text_lower: str, component_type: str) -> Dict:
        """Enhanced property inference based on text analysis."""
        props = {
            'auth_type': None,
            'encryption_at_rest': None,
            'logging_enabled': None,
            'input_validation': None,
            'rate_limiting': None,
            'public_access': False,
            'compliance_frameworks': []
        }
        
        # Public access detection
        if component_type in ['WebClient', 'API Gateway', 'CDN']:
            props['public_access'] = True
        if 'public' in text_lower or 'internet' in text_lower:
            props['public_access'] = True
        
        # Authentication detection
        if 'jwt' in text_lower or 'json web token' in text_lower:
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
