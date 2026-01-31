import json
import os

def add_rules():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    threats_path = os.path.join(base_dir, 'backend', 'app', 'knowledge_base', 'threats.json')
    
    with open(threats_path, 'r') as f:
        threats = json.load(f)
    
    new_rules = [
        {
            "id": "LAT-001",
            "category": "Lateral Movement",
            "resource_type": ["DataFlow"],
            "detection": {
                "logic": {
                    "operator": "AND",
                    "conditions": [
                        { "field": "trust_boundary", "op": "==", "value": "internal" },
                        { 
                            "operator": "OR",
                            "conditions": [
                                { "field": "authenticated", "op": "==", "value": False },
                                { "field": "authenticated", "op": "exists", "value": False }
                            ]
                        }
                    ]
                },
                "auto_detectable": True,
                "confidence": "Medium"
            },
            "threat": {
                "title": "Potential Lateral Movement (Missing Internal Auth)",
                "description": "Internal traffic between components appears to lack authentication. If one service is compromised, attackers could move laterally to others without restriction."
            },
            "risk": {
                "severity": "High",
                "likelihood": "Medium",
                "impact": "High",
                "risk_score": 75,
                "affected_assets": ["Internal Services", "Data"],
                "business_impact": ["Data Breach", "Service Disruption"]
            },
            "mitigation": {
                "primary": "Implement Service-to-Service authentication using mTLS or OIDC tokens.",
                "defense_in_depth": ["Network Segmentation", "Zero Trust Architecture"],
                "verification": "Attempt to access internal APIs from a different network segment without credentials."
            },
            "metadata": {
                "version": "2.2",
                "created": "2026-01-31",
                "author": "AI Threat Modeler Team"
            },
            "evidence": {
                "derived_from": ["trust_boundary", "authenticated"],
                "reasoning": "Flow is internal but lacks explicit authentication properties."
            },
             "signal_source": ["architecture"],
             "applicability": {
                "environment": ["production"],
                 "exposure": ["internal"]
             },
             "maturity_level": "intermediate"
        },
        {
            "id": "LAT-002",
            "category": "Eavesdropping",
            "resource_type": ["DataFlow"],
            "detection": {
                "logic": {
                    "operator": "AND",
                    "conditions": [
                        { "field": "trust_boundary", "op": "==", "value": "internal" },
                         { 
                            "operator": "OR",
                            "conditions": [
                                { "field": "protocol", "op": "==", "value": "http" },
                                { "field": "protocol", "op": "==", "value": "tcp" }
                            ]
                        }
                    ]
                },
                "auto_detectable": True,
                "confidence": "Medium"
            },
            "threat": {
                "title": "Unencrypted Internal Traffic",
                "description": "Internal communication uses cleartext protocols (HTTP/TCP), allowing compromised instances to sniff sensitive data."
            },
            "risk": {
                "severity": "Medium",
                "likelihood": "Medium",
                "impact": "Medium",
                "risk_score": 50,
                "affected_assets": ["Data in Transit"],
                "business_impact": ["Information Disclosure"]
            },
            "mitigation": {
                "primary": "Enforce TLS for all internal service communication.",
                "defense_in_depth": ["VPN", "VPC Peering"],
                "verification": "Packet capture analysis within the internal network."
            },
             "metadata": {
                "version": "2.2",
                "created": "2026-01-31",
                "author": "AI Threat Modeler Team"
            },
             "evidence": {
                "derived_from": ["trust_boundary", "protocol"],
                "reasoning": "Internal flow uses non-secure protocol."
            },
             "signal_source": ["architecture"],
              "applicability": {
                "environment": ["production"],
                 "exposure": ["internal"]
             },
             "maturity_level": "baseline"
        }
    ]
    
    # Check for duplicates
    existing_ids = {t['id'] for t in threats}
    added_count = 0
    for rule in new_rules:
        if rule['id'] not in existing_ids:
            threats.append(rule)
            added_count += 1
            
    with open(threats_path, 'w') as f:
        json.dump(threats, f, indent=4)
        
    print(f"Added {added_count} new Lateral Movement rules.")

if __name__ == "__main__":
    add_rules()
