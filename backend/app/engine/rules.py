import json
import os
from typing import List, Dict, Any, Tuple, Optional
from ..models import Threat

from collections import namedtuple

MatchResult = namedtuple('MatchResult', ['match', 'confidence', 'evidence'])

class RuleEngine:
    def __init__(self, rules_path: str = None):
        if rules_path is None:
            # Default to knowledge_base/threats.json relative to this file
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
            status="Identified"
        )
