import yaml
import logging
import re
from typing import Dict, List, Any, Optional

from app.models import Component, SystemArchitecture, DataFlow
from .iac_security import IaCSecurityAnalyzer

logger = logging.getLogger(__name__)

class IaCParser:
    """
    Parses Infrastructure-as-Code (IaC) files like Docker Compose and Kubernetes manifests.
    Extracts components, properties, and relationships to feed into the ThreatAnalyzer.
    """
    
    def __init__(self):
        self.security_analyzer = IaCSecurityAnalyzer()
        
    def parse(self, iac_content: str, format_hint: str = 'auto') -> SystemArchitecture:
        """
        Parse an IaC file and return a SystemArchitecture object.
        """
        if not iac_content or not iac_content.strip():
            raise ValueError("Empty IaC content provided")
            
        try:
            if format_hint == 'terraform' or self._looks_like_terraform(iac_content):
                architecture = self._parse_terraform(iac_content)
                return self._attach_security_findings(architecture, iac_content, 'terraform')

            # Safely parse YAML (handles multi-document streams like K8s)
            documents = list(yaml.safe_load_all(iac_content))
            
            # Determine format
            is_compose = False
            is_k8s = False
            is_cloudformation = False
            
            if format_hint == 'docker-compose':
                is_compose = True
            elif format_hint == 'kubernetes':
                is_k8s = True
            elif format_hint == 'cloudformation':
                is_cloudformation = True
            else:
                # Auto-detect
                if not documents or not documents[0]:
                    raise ValueError("Invalid YAML content")
                    
                doc = documents[0]
                if isinstance(doc, dict):
                    if 'apiVersion' in doc and 'kind' in doc:
                        is_k8s = True
                    elif 'services' in doc or 'version' in doc:
                        is_compose = True
                    elif 'Resources' in doc or 'AWSTemplateFormatVersion' in doc:
                        is_cloudformation = True
            
            if is_compose:
                architecture = self._parse_docker_compose(documents[0] if documents else {})
            elif is_k8s:
                architecture = self._parse_kubernetes(documents)
            elif is_cloudformation:
                architecture = self._parse_cloudformation(documents[0] if documents else {})
            else:
                raise ValueError("Could not determine the IaC format. Supported formats are Docker Compose, Kubernetes, Terraform, and CloudFormation.")

            return self._attach_security_findings(architecture, iac_content, format_hint, documents)
                
        except yaml.YAMLError as e:
            logger.error(f"YAML parsing error: {e}")
            raise ValueError(f"Invalid YAML format: {str(e)}")
        except Exception as e:
            logger.error(f"IaC parsing error: {e}")
            raise ValueError(f"Failed to parse IaC: {str(e)}")

    @staticmethod
    def _looks_like_terraform(iac_content: str) -> bool:
        return bool(re.search(r'^\s*(?:resource|module|provider|terraform)\s+"', iac_content, re.MULTILINE))

    def _attach_security_findings(
        self,
        architecture: SystemArchitecture,
        iac_content: str,
        format_hint: str,
        documents: Optional[List[Dict[str, Any]]] = None,
    ) -> SystemArchitecture:
        metadata = architecture.metadata or {}
        metadata['iac_findings'] = self.security_analyzer.analyze(iac_content, format_hint, documents)
        metadata['iac_findings_count'] = len(metadata['iac_findings'])
        architecture.metadata = metadata
        return architecture

    def _parse_terraform(self, content: str) -> SystemArchitecture:
        """Create architecture components from Terraform resources for report context."""
        type_map = {
            'aws_s3_bucket': 'Object Storage',
            'aws_db_instance': 'Database',
            'aws_lambda_function': 'Serverless',
            'aws_api_gateway_rest_api': 'API Gateway',
            'aws_instance': 'Service',
            'aws_eks_cluster': 'Container',
            'aws_dynamodb_table': 'Database',
            'aws_iam_role': 'IAM',
            'aws_iam_policy': 'IAM',
            'aws_kms_key': 'KMS',
        }
        components = []
        for resource_type, name, _, _ in self.security_analyzer._terraform_blocks(content):
            component_type = type_map.get(resource_type)
            if not component_type:
                continue
            components.append(Component(
                id=f'{resource_type}.{name}',
                name=name.replace('-', ' ').replace('_', ' ').title(),
                type=component_type,
                properties={
                    'iac_resource_type': resource_type,
                    'cloud_provider': 'aws' if resource_type.startswith('aws_') else None,
                    'deployment': 'terraform',
                },
            ))
        return SystemArchitecture(
            components=components,
            flows=[],
            metadata={'source': 'terraform', 'original_text': 'Terraform infrastructure configuration'},
        )

    def _parse_cloudformation(self, template: Dict[str, Any]) -> SystemArchitecture:
        """Create architecture components from CloudFormation resources."""
        type_map = {
            'AWS::S3::Bucket': 'Object Storage',
            'AWS::RDS::DBInstance': 'Database',
            'AWS::Lambda::Function': 'Serverless',
            'AWS::ApiGateway::RestApi': 'API Gateway',
            'AWS::EC2::Instance': 'Service',
            'AWS::EKS::Cluster': 'Container',
            'AWS::DynamoDB::Table': 'Database',
            'AWS::IAM::Role': 'IAM',
            'AWS::IAM::ManagedPolicy': 'IAM',
            'AWS::KMS::Key': 'KMS',
        }
        components = []
        for logical_id, resource in (template.get('Resources') or {}).items():
            if not isinstance(resource, dict):
                continue
            resource_type = resource.get('Type', '')
            component_type = type_map.get(resource_type)
            if not component_type:
                continue
            components.append(Component(
                id=logical_id,
                name=logical_id.replace('-', ' ').replace('_', ' '),
                type=component_type,
                properties={
                    'iac_resource_type': resource_type,
                    'cloud_provider': 'aws',
                    'deployment': 'cloudformation',
                },
            ))
        return SystemArchitecture(
            components=components,
            flows=[],
            metadata={'source': 'cloudformation', 'original_text': 'CloudFormation infrastructure configuration'},
        )
            
    def _parse_docker_compose(self, compose_data: Dict) -> SystemArchitecture:
        """Parse Docker Compose YAML into a SystemArchitecture"""
        components = []
        
        services = compose_data.get('services', {})
        if not services:
            logger.warning("No services found in Docker Compose file")
            return SystemArchitecture(components=[])
            
        # First pass: Create components
        for service_name, service_config in services.items():
            if not isinstance(service_config, dict):
                continue
                
            # Try to infer component type
            image = service_config.get('image', '').lower()
            comp_type = self._infer_component_type(service_name, image)
            
            # Extract properties
            properties = {}
            if 'image' in service_config:
                properties['image'] = service_config['image']
            
            if 'ports' in service_config:
                properties['public_access'] = True
            else:
                properties['public_access'] = False
                
            if 'environment' in service_config:
                env = service_config['environment']
                if isinstance(env, dict):
                    # Check for secrets passing in env
                    if any('password' in k.lower() or 'secret' in k.lower() or 'key' in k.lower() for k in env.keys()):
                        properties['secrets_in_env'] = True
                elif isinstance(env, list):
                    if any('password' in str(v).lower() or 'secret' in str(v).lower() or 'key' in str(v).lower() for v in env):
                        properties['secrets_in_env'] = True
            
            if service_config.get('privileged') is True:
                properties['privileged_container'] = True
                
            properties['containerized'] = True

            comp = Component(
                id=service_name,
                name=service_name.replace('-', ' ').title(),
                type=comp_type,
                properties=properties
            )
            components.append(comp)
            
        # Second pass: establish connections (networks and depends_on)
        flows = []
        for comp in components:
            service_config = services.get(comp.id, {})
            targets = set()
            
            # 1. depends_on 
            if 'depends_on' in service_config:
                deps = service_config['depends_on']
                if isinstance(deps, list):
                    for dep in deps:
                        targets.add(dep)
                elif isinstance(deps, dict):
                    for dep in deps.keys():
                        targets.add(dep)
            
            # 2. Extract potential database connections from environment variables
            env = service_config.get('environment', {})
            if isinstance(env, dict):
                for val in env.values():
                    val_str = str(val).lower()
                    for other_comp in components:
                        if other_comp.id != comp.id and other_comp.id.lower() in val_str:
                             targets.add(other_comp.id)
            elif isinstance(env, list):
                for val in env:
                    val_str = str(val).lower()
                    for other_comp in components:
                        if other_comp.id != comp.id and other_comp.id.lower() in val_str:
                             targets.add(other_comp.id)

            for target in targets:
                flows.append(DataFlow(source_id=comp.id, target_id=target, protocol="tcp"))
            
        # Generate a textual summary for the NLP pipeline to process
        summary = self._generate_summary_text("Docker Compose", components, flows)
        metadata = {'source': 'docker-compose', 'original_text': summary}
        
        return SystemArchitecture(components=components, flows=flows, metadata=metadata)
        
    def _parse_kubernetes(self, documents: List[Dict]) -> SystemArchitecture:
        """Parse Kubernetes YAML manifests into a SystemArchitecture"""
        components = []
        services_map = {} # map service name to selector
        deployments = []
        
        # First gather all resources
        for doc in documents:
            if not doc or not isinstance(doc, dict):
                continue
                
            kind = doc.get('kind', '')
            metadata = doc.get('metadata', {})
            name = metadata.get('name', 'unknown')
            
            if kind in ('Deployment', 'StatefulSet', 'DaemonSet', 'Pod'):
                deployments.append(doc)
            elif kind == 'Service':
                spec = doc.get('spec', {})
                selector = spec.get('selector', {})
                ports = spec.get('ports', [])
                services_map[name] = {
                    'selector': selector,
                    'type': spec.get('type', 'ClusterIP'),
                    'ports': ports
                }
        
        # Process deployments/pods into components
        for dep in deployments:
            name = dep.get('metadata', {}).get('name', 'unknown')
            kind = dep.get('kind', '')
            
            spec = dep.get('spec', {})
            template = spec.get('template', {}) if kind != 'Pod' else dep
            pod_spec = template.get('spec', {})
            pod_labels = template.get('metadata', {}).get('labels', {})
            
            containers = pod_spec.get('containers', [])
            if not containers:
                continue
                
            # Typically taking the primary container
            primary_container = containers[0]
            image = primary_container.get('image', '')
            
            comp_type = self._infer_component_type(name, image)
            
            properties = {
                'image': image,
                'containerized': True,
                'deployment': 'k8s'
            }
            
            # Security Context
            sec_context = primary_container.get('securityContext', {})
            pod_sec_context = pod_spec.get('securityContext', {})
            
            if sec_context.get('privileged'):
                properties['privileged_container'] = True
            
            if sec_context.get('allowPrivilegeEscalation') is False:
                properties['privilege_escalation_disabled'] = True
                
            if pod_sec_context.get('runAsNonRoot') or sec_context.get('runAsNonRoot'):
                properties['runs_as_non_root'] = True
            
            # Check Services exposure
            is_exposed = False
            for svc_name, svc_info in services_map.items():
                selector = svc_info.get('selector', {})
                # If pod labels match service selector
                if selector and all(pod_labels.get(k) == v for k, v in selector.items()):
                    if svc_info.get('type') in ('LoadBalancer', 'NodePort'):
                        is_exposed = True
                        properties['public_access'] = True
                    break
                    
            if not is_exposed:
                properties['public_access'] = False
                
            comp = Component(
                id=name,
                name=name.replace('-', ' ').title(),
                type=comp_type,
                properties=properties
            )
            components.append(comp)
            
        # K8s doesn't explicitly link services in YAML as cleanly as compose depends_on,
        # so connections rely heavily on env vars or are implicit
        flows = []
        
        summary = self._generate_summary_text("Kubernetes", components, flows)
        metadata = {'source': 'kubernetes', 'original_text': summary, 'deployment': 'k8s'}
        
        return SystemArchitecture(components=components, flows=flows, metadata=metadata)
        
    def _infer_component_type(self, name: str, image: str) -> str:
        """Infer type based on container image and name"""
        name_lower = name.lower()
        image_lower = image.lower()
        
        db_keywords = ['postgres', 'mysql', 'mongo', 'redis', 'db', 'mariadb', 'cassandra']
        for kw in db_keywords:
            if kw in image_lower or kw in name_lower:
                return 'Database'
                
        api_keywords = ['api', 'backend', 'server', 'node', 'python', 'java', 'go']
        for kw in api_keywords:
            if kw in image_lower or kw in name_lower:
                return 'API'
                
        web_keywords = ['ui', 'frontend', 'web', 'react', 'nginx', 'apache']
        for kw in web_keywords:
            if kw in image_lower or kw in name_lower:
                return 'WebClient'
                
        queue_keywords = ['kafka', 'rabbit', 'celery', 'worker']
        for kw in queue_keywords:
            if kw in image_lower or kw in name_lower:
                return 'Queue'
                
        return 'Service'
        
    def _generate_summary_text(self, env_type: str, components: List[Component], flows: List[DataFlow]) -> str:
        """Generate a natural language summary that the NLP engine can process for semantic matching"""
        lines = [f"This is a {env_type} architecture."]
        
        for comp in components:
            lines.append(f"{comp.name} is a {comp.type} component.")
            if comp.properties.get('image'):
                lines.append(f"It runs the {comp.properties['image']} image.")
            
            targets = [f.target_id for f in flows if f.source_id == comp.id]
            if targets:
                targets_str = ", ".join(targets)
                lines.append(f"It connects to {targets_str}.")
                
        return " ".join(lines)
