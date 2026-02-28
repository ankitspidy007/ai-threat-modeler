"""
Comprehensive Threat Knowledge Base Loader

This module loads and manages the comprehensive threat knowledge base
from multiple modular JSON files covering cloud platforms, frameworks,
and attack patterns.
"""

import json
from pathlib import Path
from typing import List, Dict, Optional
import logging

logger = logging.getLogger(__name__)


class ThreatKnowledgeBase:
    """Loads and manages comprehensive threat knowledge base"""
    
    def __init__(self):
        self.kb_dir = Path(__file__).parent
        self.threats: List[Dict] = []
        self.threats_by_id: Dict[str, Dict] = {}
        self.threats_by_component: Dict[str, List[Dict]] = {}
        self.threats_by_cloud: Dict[str, List[Dict]] = {}
        self.load_all()
    
    def load_all(self):
        """Load all threat modules"""
        modules = [
            # Cloud platforms
            'cloud_aws_threats.json',
            'cloud_azure_threats.json',
            'cloud_gcp_threats.json',
            
            # OWASP frameworks
            'owasp_web_top10.json',
            'owasp_api_top10.json',
            'owasp_serverless_top10.json',
            
            # Architecture and components
            'container_k8s_threats.json',
            'auth_authz_threats.json',
            'infrastructure_threats.json',
            'database_threats.json',
            
            # Advanced threats
            'supply_chain_threats.json',
            'emerging_threats.json',
            
            # Legacy support
            'threats.json',  # Original threat database
            'domain_threats.json'  # Domain-specific threats
        ]
        
        for module in modules:
            self.load_module(module)
        
        # Build indexes
        self._build_indexes()
        
        logger.info(f"Loaded {len(self.threats)} threats from {len(modules)} modules")
    
    def load_module(self, filename: str):
        """Load a single threat module"""
        filepath = self.kb_dir / filename
        
        if not filepath.exists():
            logger.warning(f"Threat module not found: {filename}")
            return
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
                # Handle both array and object formats
                if isinstance(data, list):
                    threats = data
                elif isinstance(data, dict) and 'threats' in data:
                    threats = data['threats']
                else:
                    logger.warning(f"Invalid format in {filename}")
                    return
                
                self.threats.extend(threats)
                logger.debug(f"Loaded {len(threats)} threats from {filename}")
                
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing {filename}: {e}")
        except Exception as e:
            logger.error(f"Error loading {filename}: {e}")
    
    def _build_indexes(self):
        """Build lookup indexes for fast querying"""
        for threat in self.threats:
            # Index by ID
            threat_id = threat.get('threat_id') or threat.get('id')
            if threat_id:
                self.threats_by_id[threat_id] = threat
            
            # Index by component
            component = threat.get('component')
            if component:
                if component not in self.threats_by_component:
                    self.threats_by_component[component] = []
                self.threats_by_component[component].append(threat)
            
            # Index by cloud platform
            cloud_platforms = threat.get('cloud_platform', [])
            if isinstance(cloud_platforms, str):
                cloud_platforms = [cloud_platforms]
            
            for platform in cloud_platforms:
                if platform not in self.threats_by_cloud:
                    self.threats_by_cloud[platform] = []
                self.threats_by_cloud[platform].append(threat)
    
    def get_all_threats(self) -> List[Dict]:
        """Get all threats"""
        return self.threats
    
    def get_by_id(self, threat_id: str) -> Optional[Dict]:
        """Get threat by ID"""
        return self.threats_by_id.get(threat_id)
    
    def get_by_component(self, component: str) -> List[Dict]:
        """Get threats for a specific component"""
        return self.threats_by_component.get(component, [])
    
    def get_by_cloud_platform(self, platform: str) -> List[Dict]:
        """Get threats for a specific cloud platform"""
        return self.threats_by_cloud.get(platform, [])
    
    def get_by_stride_category(self, category: str) -> List[Dict]:
        """Get threats by STRIDE category"""
        return [t for t in self.threats 
                if t.get('stride_category') == category]
    
    def get_by_severity(self, min_severity: str = "Medium") -> List[Dict]:
        """Get threats above a certain severity"""
        severity_order = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        min_level = severity_order.get(min_severity, 2)
        
        return [t for t in self.threats 
                if severity_order.get(t.get('impact', 'Low'), 1) >= min_level]
    
    def search(self, query: str) -> List[Dict]:
        """Search threats by keyword"""
        query_lower = query.lower()
        results = []
        
        for threat in self.threats:
            # Search in name, description, attack vector
            searchable = [
                threat.get('threat_name', ''),
                threat.get('description', ''),
                threat.get('attack_vector', ''),
                ' '.join(threat.get('tags', []))
            ]
            
            if any(query_lower in field.lower() for field in searchable):
                results.append(threat)
        
        return results
    
    def get_statistics(self) -> Dict:
        """Get knowledge base statistics"""
        return {
            'total_threats': len(self.threats),
            'by_component': {k: len(v) for k, v in self.threats_by_component.items()},
            'by_cloud': {k: len(v) for k, v in self.threats_by_cloud.items()},
            'by_stride': {
                category: len(self.get_by_stride_category(category))
                for category in ["Spoofing", "Tampering", "Repudiation", 
                               "Information Disclosure", "Denial of Service", 
                               "Elevation of Privilege"]
            }
        }


# Global instance
_kb_instance: Optional[ThreatKnowledgeBase] = None


def get_knowledge_base() -> ThreatKnowledgeBase:
    """Get or create global knowledge base instance"""
    global _kb_instance
    if _kb_instance is None:
        _kb_instance = ThreatKnowledgeBase()
    return _kb_instance
