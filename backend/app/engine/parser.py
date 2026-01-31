import re
import uuid
from typing import List, Dict
from ..models import SystemArchitecture, Component, DataFlow

import re
import uuid
from typing import List, Dict
from ..models import SystemArchitecture, Component, DataFlow

class ArchitectureParser:
    def parse(self, text: str) -> SystemArchitecture:
        """
        Expanded heuristic parser to detect deeper architecture and trust boundaries.
        """
        text_lower = text.lower()
        components: Dict[str, Component] = {}
        flows: List[DataFlow] = []

        # 1. Component Detection
        # Expanded keywords
        component_keywords = {
            'database': 'Database', 'db': 'Database', 'sql': 'Database', 'mongo': 'Database', 'postgres': 'Database',
            'api': 'API', 'backend': 'API',
            'frontend': 'WebClient', 'web': 'WebClient', 'app': 'WebClient', 'react': 'WebClient', 'mobile': 'WebClient',
            'gateway': 'API Gateway', 'proxy': 'API Gateway', 'apigw': 'API Gateway',
            'load balancer': 'Load Balancer', 'lb': 'Load Balancer',
            'queue': 'Queue', 'kafka': 'Queue', 'rabbitmq': 'Queue',
            'worker': 'Service', 'job': 'Service',
            'storage': 'Object Storage', 's3': 'Object Storage', 'bucket': 'Object Storage',
            'service': 'Service', 'microservice': 'Service'
        }
        
        found_types = set()
        for word, c_type in component_keywords.items():
            if word in text_lower:
                found_types.add(c_type)
        
        # Heuristic: If "microservice" is mentioned, maybe we assume 2 services?
        # For now, stick to types.
        
        # Create components
        for c_type in found_types:
            c_id = c_type.lower().replace(" ", "_")
            
            # Default Properties
            props = {
                'auth_type': None, # Unset = Unknown -> Low confidence matching
                'encryption_at_rest': None,
                'logging_enabled': None,
                'input_validation': None,
                'rate_limiting': None,
                'public_access': False
            }
            
            # Contextual Property Inference
            if c_type in ['WebClient', 'API Gateway']:
                props['public_access'] = True
            
            if 'secure' in text_lower:
                props['encryption_at_rest'] = True
            if 'logging' in text_lower:
                props['logging_enabled'] = True
            if 'basic auth' in text_lower and c_type == 'API':
                props['auth_type'] = 'basic'
            if 'no auth' in text_lower:
                props['auth_type'] = 'none'

            comp = Component(
                id=c_id,
                name=c_type,
                type=c_type,
                properties=props
            )
            components[comp.id] = comp

        # 2. Flow Inference
        # Logic: WebClient -> Gateway -> API -> Service -> Queue -> Worker -> DB
        
        # Define layers
        layers = ['webclient', 'load_balancer', 'api_gateway', 'api', 'service', 'queue', 'worker', 'database', 'object_storage']
        
        # Connect adjacent existing layers
        params_by_id = {c.id: c.type for c in components.values()}
        
        sorted_comps = []
        for layer in layers:
            # Check if any component matches this layer (by id substring matching to be safe)
            for cid in components:
                if cid == layer: # Exact match based on our ID generation above
                    sorted_comps.append(components[cid])
        
        # Link them sequentially
        for i in range(len(sorted_comps) - 1):
            source = sorted_comps[i]
            target = sorted_comps[i+1]
            
            # Trust Boundary Logic
            trust_boundary = "internal"
            protocol = "tcp"
            
            if source.type == 'WebClient':
                trust_boundary = "internet"
                protocol = "http" # or https
            elif source.type in ['API Gateway', 'Load Balancer'] and target.type in ['API', 'Service']:
                trust_boundary = "internal" # Entering internal network
                protocol = "http" 
            
            # Explicit Protocol Inference
            if 'https' in text_lower and protocol == 'http':
                protocol = 'https'

            flows.append(DataFlow(
                source_id=source.id,
                target_id=target.id,
                protocol=protocol,
                properties={
                    "trust_boundary": trust_boundary,
                    "authenticated": None # Unknown
                }
            ))

        # Add Object Storage links (usually from API or Worker)
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
