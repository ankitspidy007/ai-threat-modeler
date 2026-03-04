import json
import os
from typing import List, Dict, Any, Tuple, Optional
from ..models import Threat
from ..knowledge_base.loader import get_knowledge_base

from collections import namedtuple

MatchResult = namedtuple('MatchResult', ['match', 'confidence', 'evidence'])

class RuleEngine:
    def __init__(self, rules_path: str = None):
        """
        Initialize RuleEngine with comprehensive knowledge base.
        Supports both legacy threats.json and new modular knowledge base.
        """
        # Load comprehensive knowledge base
        try:
            kb = get_knowledge_base()
            comprehensive_threats = kb.get_all_threats()
            print(f"Loaded {len(comprehensive_threats)} threats from comprehensive knowledge base")
            
            # Convert comprehensive threats to legacy format for compatibility
            self.rules = self._convert_to_legacy_format(comprehensive_threats)
            
        except Exception as e:
            print(f"Warning: Could not load comprehensive knowledge base: {e}")
            print("Falling back to legacy threats.json")
            
            # Fallback to legacy loading
            if rules_path is None:
                base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                rules_path = os.path.join(base_dir, 'knowledge_base', 'threats.json')
            
            with open(rules_path, 'r') as f:
                self.rules = json.load(f)
            
            # Load domain-specific threats if available
            domain_rules_path = rules_path.replace('threats.json', 'domain_threats.json')
            if os.path.exists(domain_rules_path):
                with open(domain_rules_path, 'r') as f:
                    domain_rules = json.load(f)
                    self.rules.extend(domain_rules)
                    print(f"Loaded {len(domain_rules)} domain-specific threat rules")
        
        # Sort rules by priority (if defined) for consistent evaluation order
        self.rules.sort(key=lambda r: r.get('priority', 50))
    
    def get_all_threats(self) -> List[Dict]:
        """Return all loaded threat rules for external use (e.g., vectorization, attack chain analysis)."""
        return self.rules
    
    def _convert_to_legacy_format(self, comprehensive_threats: List[Dict]) -> List[Dict]:
        """
        Convert comprehensive threat format to legacy format for compatibility.
        This allows the existing rule engine logic to work with new threats.
        """
        legacy_rules = []
        
        for threat in comprehensive_threats:
            # If the threat already has legacy format fields (from threats.json), keep it as-is
            if 'detection' in threat and 'resource_type' in threat:
                legacy_rules.append(threat)
                continue

            # Map comprehensive format to legacy format
            legacy_rule = {
                'id': threat.get('threat_id', threat.get('id', 'UNKNOWN')),
                'category': threat.get('stride_category', 'Unknown'),
                'title': threat.get('threat_name', 'Unknown Threat'),
                'description': threat.get('attack_vector', ''),
                'severity': threat.get('impact', 'Medium'),
                'priority': self._map_severity_to_priority(threat.get('impact', 'Medium')),
                'resource_type': [threat.get('component', 'Any')],
                'threat': {
                    'title': threat.get('threat_name', 'Unknown Threat'),
                    'description': threat.get('attack_vector', '')
                },
                'risk': {
                    'severity': threat.get('impact', 'Medium'),
                    'likelihood': threat.get('likelihood', 'Medium'),
                    'impact': threat.get('impact', 'Medium'),
                    'risk_score': self._calculate_risk_score(
                        threat.get('likelihood', 'Medium'),
                        threat.get('impact', 'Medium')
                    )
                },
                'mitigation': {
                    'primary': self._extract_primary_mitigation(threat.get('mitigations', []))
                },
                'detection': self._create_detection_logic(threat),
                'negating_controls': self._extract_negating_controls(threat.get('mitigations', []))
            }

            # Extract compliance mappings from comprehensive format (references field)
            refs = threat.get('references', {})
            mapped_controls = {}
            if refs.get('owasp'):
                mapped_controls['owasp_top_10'] = refs['owasp']
            if refs.get('cwe'):
                mapped_controls['cwe'] = refs['cwe']
            if refs.get('mitre_attack'):
                mapped_controls['mitre_attack'] = refs['mitre_attack']
            if refs.get('nist'):
                mapped_controls['nist_800_53'] = refs['nist']

            if mapped_controls:
                legacy_rule['mapped_controls'] = mapped_controls
            
            legacy_rules.append(legacy_rule)
        
        return legacy_rules
    
    def _map_severity_to_priority(self, severity: str) -> int:
        """Map severity to priority number (lower = higher priority)"""
        mapping = {
            'Critical': 10,
            'High': 20,
            'Medium': 30,
            'Low': 40
        }
        return mapping.get(severity, 30)
    
    def _calculate_risk_score(self, likelihood: str, impact: str) -> int:
        """Calculate risk score from likelihood and impact"""
        scores = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}
        l_score = scores.get(likelihood, 2)
        i_score = scores.get(impact, 2)
        return l_score * i_score
    
    def _extract_primary_mitigation(self, mitigations: List[Dict]) -> str:
        """Extract primary mitigation from mitigations list"""
        if not mitigations:
            return "No specific mitigation provided"
        
        # Prefer preventive controls
        preventive = [m for m in mitigations if m.get('control_type') == 'Preventive']
        if preventive:
            return preventive[0].get('description', 'No description')
        
        return mitigations[0].get('description', 'No description')
    
    def _create_detection_logic(self, threat: Dict) -> Dict:
        """
        Create intelligent detection logic from threat data.
        Considers cloud platform, component type, database type, and security controls.
        """
        component = threat.get('component', 'Any')
        cloud_platforms = threat.get('cloud_platform', [])
        cloud_services = threat.get('cloud_services', [])
        threat_id = threat.get('threat_id', '')
        
        conditions = []
        
        # Base condition: Component type match
        conditions.append({
            'field': 'type',
            'op': '==',
            'value': component
        })
        
        # Cloud platform specific threats
        if cloud_platforms and cloud_platforms != ['On-Premise']:
            # For AWS-specific threats
            if 'AWS' in threat_id or any('AWS' in svc for svc in cloud_services):
                conditions.append({
                    'field': 'cloud_provider',
                    'op': '==',
                    'value': 'aws'
                })
            
            # For Azure-specific threats  
            elif 'AZURE' in threat_id or any('Azure' in svc for svc in cloud_services):
                conditions.append({
                    'field': 'cloud_provider',
                    'op': '==',
                    'value': 'azure'
                })
            
            # For GCP-specific threats
            elif 'GCP' in threat_id or any('GCP' in svc for svc in cloud_services):
                conditions.append({
                    'field': 'cloud_provider',
                    'op': '==',
                    'value': 'gcp'
                })
        
        # Database-specific logic
        if component == 'Database':
            # SQL-specific threats (RDS, Azure SQL, Cloud SQL)
            if any(keyword in threat_id or keyword in str(cloud_services) 
                   for keyword in ['RDS', 'SQL', 'TDE']):
                # Only match SQL databases
                conditions.append({
                    'field': 'db_type',
                    'op': 'in',
                    'value': ['mysql', 'postgresql', 'mssql', 'oracle', 'sql']
                })
            
            # NoSQL-specific threats
            elif 'NoSQL' in threat.get('attack_vector', ''):
                conditions.append({
                    'field': 'db_type',
                    'op': 'in',
                    'value': ['mongodb', 'dynamodb', 'cosmosdb', 'firestore', 'nosql']
                })
        
        # Authentication-specific logic
        if component == 'API':
            # JWT threats - only if NOT using managed auth
            if 'JWT' in threat_id:
                conditions.append({
                    'field': 'auth_type',
                    'op': 'in',
                    'value': ['jwt', 'custom', 'none']
                })
            
            # OAuth threats - only if using OAuth
            elif 'OAuth' in threat_id or 'OAuth' in threat.get('threat_name', ''):
                conditions.append({
                    'field': 'auth_type',
                    'op': 'in',
                    'value': ['oauth', 'oauth2', 'custom']
                })
            
            # API Key threats - only if using API keys
            elif 'API Key' in threat.get('threat_name', ''):
                conditions.append({
                    'field': 'auth_type',
                    'op': 'in',
                    'value': ['api_key', 'none']
                })
            
            # API Gateway threats - only if NOT using managed auth services
            elif 'API Gateway' in threat.get('threat_name', ''):
                conditions.append({
                    'field': 'auth_type',
                    'op': 'not_in',
                    'value': ['cognito', 'auth0', 'okta', 'azure_ad', 'google_identity']
                })
        
        # Serverless-specific logic
        if component == 'Serverless':
            if 'Lambda' in str(cloud_services):
                conditions.append({
                    'field': 'cloud_provider',
                    'op': '==',
                    'value': 'aws'
                })
            elif 'Functions' in str(cloud_services) and 'Azure' in str(cloud_services):
                conditions.append({
                    'field': 'cloud_provider',
                    'op': '==',
                    'value': 'azure'
                })
            elif 'Functions' in str(cloud_services) and 'GCP' in str(cloud_services):
                conditions.append({
                    'field': 'cloud_provider',
                    'op': '==',
                    'value': 'gcp'
                })
        
        # Use AND logic for all conditions
        return {
            'logic': {
                'operator': 'AND',
                'conditions': conditions
            }
        }
    
    def _extract_negating_controls(self, mitigations: List[Dict]) -> List[str]:
        """Extract negating controls from mitigations"""
        controls = []
        for mitigation in mitigations:
            tools = mitigation.get('tools', [])
            # Map common tools to negating controls
            for tool in tools:
                if 'WAF' in tool:
                    controls.append('waf_enabled')
                elif 'API Gateway' in tool:
                    controls.append('api_gateway')
                elif 'TLS' in tool or 'SSL' in tool:
                    controls.append('tls_termination')
                elif 'Encryption' in tool:
                    controls.append('encryption_at_rest')
        return list(set(controls))  # Remove duplicates


    def evaluate_component(self, component_id: str, component_data: Dict[str, Any]) -> List[Threat]:
        threats = []
        for rule in self.rules:
            r_types = rule.get('resource_type')
            if isinstance(r_types, str):
                r_types = [r_types]
            
            # Check if applied to component (not DataFlow)
            if 'DataFlow' in r_types and len(r_types) == 1:
                continue

            # Check if component match
            if not any(rt == component_data.get('type') or rt == 'Any' for rt in r_types):
                # Allow generic 'Service' rules to apply to specific service types
                if not ('Service' in r_types and component_data.get('type') in ['API', 'Worker', 'Service', 'Microservice']):
                    continue

            detection = rule.get('detection', {})
            logic = detection.get('logic')
            
            match_res = self._evaluate_logic(logic, component_data)
            if match_res.match:
                # Check for negating controls before adding threat
                negated, negating_control = self._check_negating_controls(rule, component_data)
                
                if negated:
                    # Add as informational finding instead of threat
                    continue
                
                threats.append(self._create_threat_object(
                    rule, 
                    component_id=component_id, 
                    confidence=match_res.confidence,
                    evidence=match_res.evidence
                ))
        return threats

    def evaluate_flow(self, source: str, target: str, flow_data: Dict[str, Any]) -> List[Threat]:
        threats = []
        for rule in self.rules:
            r_types = rule.get('resource_type')
            if isinstance(r_types, str):
                r_types = [r_types]

            if 'DataFlow' not in r_types:
                continue

            detection = rule.get('detection', {})
            logic = detection.get('logic')

            match_res = self._evaluate_logic(logic, flow_data)
            if match_res.match:
                # Check for negating controls before adding threat
                negated, negating_control = self._check_negating_controls(rule, flow_data)
                
                if negated:
                    # Negating control present - skip this threat
                    continue
                
                threats.append(self._create_threat_object(
                    rule, 
                    source=source, 
                    target=target,
                    confidence=match_res.confidence,
                    evidence=match_res.evidence
                ))
        return threats

    def _check_negating_controls(self, rule: Dict, context: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """
        Check if any negating controls are present that would mitigate/negate this threat.
        Returns (is_negated, control_name) tuple.
        """
        negating_controls = rule.get('negating_controls', [])
        
        if not negating_controls:
            return False, None
        
        # Map control names to context field checks
        control_mappings = {
            'api_gateway': lambda ctx: ctx.get('has_api_gateway', False),
            'waf_enabled': lambda ctx: ctx.get('waf_enabled', False),
            'idp_integration': lambda ctx: ctx.get('idp_integration', False),
            'zero_trust_network': lambda ctx: ctx.get('zero_trust', False),
            'mutual_tls': lambda ctx: ctx.get('mtls_enabled', False),
            'mTLS': lambda ctx: ctx.get('mtls_enabled', False),
            'service_mesh': lambda ctx: ctx.get('service_mesh', False),
            'network_segmentation': lambda ctx: ctx.get('network_segmentation', False),
            'tls_termination': lambda ctx: ctx.get('tls_termination', False) or ctx.get('protocol') == 'https',
            'vpn': lambda ctx: ctx.get('vpn_enabled', False),
            'backup_policy': lambda ctx: ctx.get('backup_enabled', False),
            'strict_dto_mapping': lambda ctx: ctx.get('dto_validation', False),
            'centralized_logging': lambda ctx: ctx.get('centralized_logging', False),
            'siem': lambda ctx: ctx.get('siem_integration', False),
            'csrf_tokens': lambda ctx: ctx.get('csrf_protection', False),
            'api_gateway_validation': lambda ctx: ctx.get('gateway_validation', False),
            'encryption_at_rest': lambda ctx: ctx.get('encryption_at_rest', False),
            'field_level_encryption': lambda ctx: ctx.get('field_level_encryption', False),
            'hsm': lambda ctx: ctx.get('hsm_enabled', False),
            'key_rotation': lambda ctx: ctx.get('key_rotation', False),
            'rbac': lambda ctx: ctx.get('rbac_enabled', False),
            'abac': lambda ctx: ctx.get('abac_enabled', False),
            'private_subnet': lambda ctx: ctx.get('private_subnet', False),
            'threat_intel_feeds': lambda ctx: ctx.get('threat_intel', False),
            'waf': lambda ctx: ctx.get('waf_enabled', False),
            'ddos_protection': lambda ctx: ctx.get('ddos_protection', False),
        }
        
        for control in negating_controls:
            check_func = control_mappings.get(control.lower())
            if check_func and check_func(context):
                return True, control
        
        return False, None

    def _evaluate_logic(self, logic: Dict, context: Dict[str, Any]) -> MatchResult:
        """
        Evaluates a structured logic block. Returns MatchResult(bool, confidence, [reasons]).
        """
        if not logic:
            return MatchResult(False, "Low", [])

        operator = logic.get('operator', 'AND').upper()
        conditions = logic.get('conditions', [])
        
        results = []
        for cond in conditions:
            if 'operator' in cond and 'conditions' in cond:
                results.append(self._evaluate_logic(cond, context))
            else:
                results.append(self._evaluate_leaf(cond, context))
        
        if not results:
            return MatchResult(False, "Low", [])

        if operator == 'AND':
            # All must match.
            all_match = all(r.match for r in results)
            if all_match:
                # Aggregate confidence: Lowest confidence in the chain?
                # or if one is Low, total is Low.
                conf = "High"
                if any(r.confidence == "Low" for r in results):
                    conf = "Low"
                elif any(r.confidence == "Medium" for r in results):
                    conf = "Medium"
                
                # Aggregate evidence
                ev = [e for r in results for e in r.evidence]
                return MatchResult(True, conf, ev)
            else:
                return MatchResult(False, "Low", [])

        elif operator == 'OR':
            # Any match.
            matching = [r for r in results if r.match]
            if matching:
                # Best confidence match?
                # If we have High confidence match, use it.
                # Prioritize High > Medium > Low
                best_match = max(matching, key=lambda x: {"High": 3, "Medium": 2, "Low": 1}.get(x.confidence, 1))
                return best_match
            else:
                return MatchResult(False, "Low", [])
        
        return MatchResult(False, "Low", [])

    def _evaluate_leaf(self, leaf: Dict, context: Dict) -> MatchResult:
        field = leaf.get('field')
        op = leaf.get('op')
        val = leaf.get('value')
        
        # Resolve field value from context
        context_val = context.get(field)
        
        # Missing Data Handling
        if context_val is None:
            # NEW BEHAVIOR: Do NOT fire rules speculatively
            # Require at least one positive architectural signal
            # If field is missing, return NO MATCH (False)
            # This prevents "Property X is not defined" spam
            
            if op == 'exists':
                # Checking if field exists - it doesn't, so return True for 'exists == False' check
                if val == False:
                    return MatchResult(True, "Medium", [f"Field '{field}' is not defined (no positive signal)."])
                return MatchResult(False, "High", [f"Field '{field}' not found."])
            
            # For all other ops: Missing data = No match
            # Move to "Assumptions" section instead of firing
            return MatchResult(False, "Low", [])

        # Actual Comparison
        matched = False
        if op == '==': matched = (context_val == val)
        if op == '!=': matched = (context_val != val)
        if op == 'in': matched = (val is not None and context_val in val)
        if op == 'not_in': matched = (val is not None and context_val not in val)
        if op == 'exists': matched = (context_val is not None)
        if op == 'contains': matched = (val is not None and val in str(context_val))
        if op == 'regex': 
            import re
            matched = bool(re.search(val, str(context_val))) if val else False
        
        # Legacy/Fallback
        if op == '>': matched = (context_val > val) if context_val is not None else False
        if op == '<': matched = (context_val < val) if context_val is not None else False
        
        if matched:
            return MatchResult(True, "High", [f"Verified '{field}' is '{context_val}' (Matched condition: {op} {val})"])
        else:
            return MatchResult(False, "High", [])

    def _create_threat_object(self, rule: Dict, component_id: str = None, source: str = None, target: str = None, confidence: str = "Medium", evidence: List[str] = None) -> Threat:
        threat_info = rule.get('threat', {})
        risk_info = rule.get('risk', {})
        mitigation_info = rule.get('mitigation', {})
        
        mitigation_text = mitigation_info.get('primary', '')
        if isinstance(mitigation_info, str):
             mitigation_text = mitigation_info

        # Conditionally adjust title if Low confidence
        title = threat_info.get('title', rule.get('title', 'Unknown Threat'))
        if confidence == "Low":
            title = f"[Conditional] {title}"

        # Extract compliance/framework mappings
        mapped = rule.get('mapped_controls', {})
        owasp_top_10 = mapped.get('owasp_top_10', [])
        cwe = mapped.get('cwe', [])
        mitre_attack = mapped.get('mitre_attack', mapped.get('mitre', []))
        nist_800_53 = mapped.get('nist_800_53', [])

        return Threat(
            id=rule['id'],
            category=rule['category'],
            title=title,
            description=threat_info.get('description', rule.get('description', '')),
            severity=risk_info.get('severity', rule.get('severity', 'Medium')),
            likelihood=risk_info.get('likelihood', 'Unknown'),
            impact=risk_info.get('impact', 'Unknown'),
            risk_score=int(risk_info.get('risk_score', 0)),
            mitigation=mitigation_text,
            component_id=component_id,
            flow_source=source,
            flow_target=target,
            confidence=confidence,
            evidence=evidence or [],
            status="Identified",
            owasp_top_10=owasp_top_10,
            cwe=cwe,
            mitre_attack=mitre_attack,
            nist_800_53=nist_800_53,
        )
