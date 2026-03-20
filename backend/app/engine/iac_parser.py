import yaml
import logging
from typing import Dict, List, Any, Optional

from app.models import Component, SystemArchitecture, DataFlow

logger = logging.getLogger(__name__)

class IaCParser:
    """
    Parses Infrastructure-as-Code (IaC) files like Docker Compose and Kubernetes manifests.
    Extracts components, properties, and relationships to feed into the ThreatAnalyzer.
    """
    
    def __init__(self):
        pass
        
    def parse(self, iac_content: str, format_hint: str = 'auto') -> SystemArchitecture:
        """
        Parse an IaC file and return a SystemArchitecture object.
        """
        if not iac_content or not iac_content.strip():
            raise ValueError("Empty IaC content provided")
            
        try:
            # Safely parse YAML (handles multi-document streams like K8s)
            documents = list(yaml.safe_load_all(iac_content))
            
            # Determine format
            is_compose = False
            is_k8s = False
            
            if format_hint == 'docker-compose':
                is_compose = True
            elif format_hint == 'kubernetes':
                is_k8s = True
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
            
            if is_compose:
                return self._parse_docker_compose(documents[0] if documents else {})
            elif is_k8s:
                return self._parse_kubernetes(documents)
            else:
                raise ValueError("Could not automatically determine IaC format. Please specify 'docker-compose' or 'kubernetes'.")
                
        except yaml.YAMLError as e:
            logger.error(f"YAML parsing error: {e}")
            raise ValueError(f"Invalid YAML format: {str(e)}")
        except Exception as e:
            logger.error(f"IaC parsing error: {e}")
            raise ValueError(f"Failed to parse IaC: {str(e)}")
            
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
