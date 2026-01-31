import json
import os
import re

def normalize_condition(cond_str, auto_detectable=False):
    """
    Parses a simple string condition like "auth_type == 'none' or auth_type == 'basic'"
    into the new logic structure.
    """
    logic = {"operator": "AND", "conditions": []}
    
    # Simple heuristic to split by 'or' / 'and'
    if ' or ' in cond_str:
        logic["operator"] = "OR"
        parts = cond_str.split(' or ')
    elif ' and ' in cond_str:
        logic["operator"] = "AND"
        parts = cond_str.split(' and ')
    else:
        parts = [cond_str]
        
    for part in parts:
        part = part.strip()
        # Parse "field op value"
        # Supports ==, !=, in (via simpler parsing)
        
        match = re.search(r"([a-zA-Z_0-9]+)\s*(==|!=|in)\s*(.+)", part)
        if match:
            field, op, val_str = match.groups()
            val_str = val_str.strip()
            
            # clean value
            val = val_str
            if val_str == "true": val = True
            elif val_str == "false": val = False
            elif val_str.lower() == "'none'": val = "none" # keep string none
            elif val_str.startswith("'") and val_str.endswith("'"): val = val_str.strip("'")
            elif val_str.startswith("[") and val_str.endswith("]"): 
                # simple array parse
                val = [v.strip().strip("'").strip('"') for v in val_str[1:-1].split(',')]
            
            logic["conditions"].append({
                "field": field,
                "op": op,
                "value": val
            })
        elif "true" in part and len(parts) == 1:
             # Universal match
             return {"operator": "AND", "conditions": [{"field": "type", "op": "exists", "value": True}]}

    return logic

def calculate_risk_score(severity, likelihood, impact):
    scores = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    s = scores.get(severity, 1)
    l = scores.get(likelihood, 1)
    i = scores.get(impact, 1)
    # Simple calculation: (Severity + Likelihood + Impact) / 3 * 25 (scale to 100) or just sum
    # Requirement: "Use a consistent scoring approach"
    # Let's say max is 100.
    return round(((s * 3) + (l * 1.5) + (i * 1)) / 22 * 100, 1) # Weighted heavy on severity

def run():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    threats_path = os.path.join(base_dir, 'backend', 'app', 'knowledge_base', 'threats.json')
    
    with open(threats_path, 'r') as f:
        data = json.load(f)
        
    new_data = []
    
    for item in data:
        # 1. Normalize Resource Type
        if isinstance(item.get("resource_type"), str):
            item["resource_type"] = [item["resource_type"]]
            
        # 2. Normalize Detection
        detection = item.get("detection", {})
        old_condition = detection.get("condition")
        
        # If it's already an object (complex), we might need to manual fix, 
        # but existing complex ones in file (from previous turn) are compatible enough to convert?
        # Actually previous complex structure was specific. User wants specific normalized structure.
        
        new_logic = {}
        confidence = "medium"
        auto_detectable = detection.get("auto_detectable", False)
        
        if isinstance(old_condition, str):
            new_logic = normalize_condition(old_condition)
            if "==" in old_condition or "in" in old_condition:
                confidence = "high"
                auto_detectable = True
        elif isinstance(old_condition, dict):
            # Already complex, just rename operators/fields if needed or trust it
            # The prompt requested SPECIFIC structure.
            # Map old complex "conditions" to new structure
            new_logic = {
                "operator": old_condition.get("operator", "AND"),
                "conditions": []
            }
            for sub in old_condition.get("conditions", []):
                new_logic["conditions"].append({
                    "field": sub.get("field"),
                    "op": sub.get("operator"), # map '==' to 'op'
                    "value": sub.get("value")
                })
            confidence = "high"
            auto_detectable = True
            
        item["detection"] = {
            "logic": new_logic,
            "auto_detectable": auto_detectable,
            "confidence": confidence
        }

        # 3. Risk consistency
        risk = item.get("risk", {})
        severity = risk.get("severity", "Medium")
        likelihood = risk.get("likelihood", "Low")
        impact = risk.get("impact", "Low")
        
        item["risk"] = {
            "severity": severity,
            "likelihood": likelihood,
            "impact": impact,
            "risk_score": calculate_risk_score(severity, likelihood, impact),
            "affected_assets": ["Data"], # Default
            "business_impact": ["Data Loss", "Reputation Damage"] # Defaults
        }
        
        # 4. Mitigation Expansion
        mitigation = item.get("mitigation", {})
        primary = mitigation.get("primary", "Mitigate this vulnerability.")
        alternatives = mitigation.get("alternatives", [])
        
        item["mitigation"] = {
            "primary": primary,
            "defense_in_depth": alternatives if alternatives else ["Implement defense in depth."],
            "verification": "Verify using automated security scanning or manual penetration testing."
        }

        # 5. Terminology Fixes
        if "XS" in item["threat"]["title"]:
            item["threat"]["title"] = item["threat"]["title"].replace("XS", "XSS")
            
        new_data.append(item)
        
    with open(threats_path, 'w') as f:
        json.dump(new_data, f, indent=4)
        print(f"Updated {len(new_data)} threats.")

if __name__ == "__main__":
    run()
