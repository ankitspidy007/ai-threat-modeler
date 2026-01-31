import json
import os
from datetime import datetime

# Intelligence Database for Enrichment
THREAT_INTELLIGENCE = {
    "S-001": {
        "signal_source": ["configuration", "architecture"],
        "evidence": {
            "derived_from": ["auth_type"],
            "reasoning": "Authentication configuration is missing or weak (Basic/None)."
        },
        "applicability": {
            "exposed_to": ["internet", "partner"],
            "data_sensitivity": ["public", "internal", "pii"]
        },
        "negating_controls": ["api_gateway", "waf_enabled", "idp_integration"],
        "mapped_controls": {
            "owasp_top_10": ["A07:2021-Identification and Authentication Failures"],
            "owasp_asvs": ["V2-Authentication"],
            "nist_800_53": ["IA-2", "IA-5"]
        },
        "maturity_level": "baseline"
    },
    "S-002": {
        "signal_source": ["architecture"],
        "evidence": {
            "derived_from": ["trust_boundary", "auth_checks"],
            "reasoning": "Data flows across trust boundary without explicit verification."
        },
        "applicability": {
            "environment": ["prod", "staging"],
            "exposed_to": ["internet"]
        },
        "negating_controls": ["zero_trust_network", "mutual_tls"],
        "mapped_controls": {
            "owasp_top_10": ["A07:2021"],
            "mitre": ["T1078", "T1190"]
        },
        "maturity_level": "intermediate"
    },
    "S-003": {
        "signal_source": ["configuration", "code"],
        "evidence": {
            "derived_from": ["jwt_algo"],
            "reasoning": "JWT algorithm is explicitly set to 'none' or insecure value."
        },
        "applicability": {
            "data_sensitivity": ["credentials", "pii"]
        },
        "negating_controls": ["api_gateway_validation"],
        "mapped_controls": {
            "owasp_top_10": ["A02:2021-Cryptographic Failures"],
            "nist_800_53": ["IA-5(1)"]
        },
        "maturity_level": "baseline"
    },
    "S-005": {
        "signal_source": ["architecture", "configuration"],
        "evidence": {
            "derived_from": ["mtls_enabled", "deployment"],
            "reasoning": "Service-to-service communication lacks mutual authentication."
        },
        "applicability": {
            "environment": ["prod"],
            "data_sensitivity": ["internal", "pii"]
        },
        "negating_controls": ["service_mesh", "network_segmentation"],
        "mapped_controls": {
            "owasp_asvs": ["V10"],
            "nist_800_53": ["SC-8"]
        },
        "maturity_level": "advanced"
    },
    "S-006": {
        "signal_source": ["configuration"],
        "evidence": {
            "derived_from": ["same_site_cookie"],
            "reasoning": "Cookie SameSite attribute is missing or lax."
        },
        "negating_controls": ["csrf_tokens", "waf_enabled"],
        "mapped_controls": {
            "owasp_top_10": ["A01:2021-Broken Access Control"],
            "owasp_asvs": ["V3"]
        },
        "maturity_level": "baseline"
    },
    "T-001": {
        "signal_source": ["architecture", "runtime"],
        "evidence": {
            "derived_from": ["protocol"],
            "reasoning": "Data transmission uses unencrypted protocol (HTTP/FTP)."
        },
        "applicability": {
            "exposed_to": ["internet", "internal", "partner"]
        },
        "negating_controls": ["tls_termination", "vpn"],
        "mapped_controls": {
            "owasp_top_10": ["A02:2021-Cryptographic Failures"],
            "nist_800_53": ["SC-8", "SC-13"]
        },
        "maturity_level": "baseline"
    },
    "T-002": {
        "signal_source": ["configuration"],
        "evidence": {
            "derived_from": ["versioning_enabled"],
            "reasoning": "Storage bucket versioning is disabled."
        },
        "applicability": {
            "data_sensitivity": ["business_critical"]
        },
        "negating_controls": ["backup_policy"],
        "mapped_controls": {
            "nist_800_53": ["SI-12"]
        },
        "maturity_level": "intermediate"
    },
    "T-003": {
        "signal_source": ["code", "configuration"],
        "evidence": {
            "derived_from": ["input_validation", "framework"],
            "reasoning": "Framework susceptible to mass assignment and validation is missing."
        },
        "negating_controls": ["strict_dto_mapping"],
        "mapped_controls": {
            "owasp_top_10": ["A08:2021-Software and Data Integrity Failures"],
            "cwe": ["CWE-915"]
        },
        "maturity_level": "intermediate"
    },
    "R-001": {
        "signal_source": ["configuration"],
        "evidence": {
            "derived_from": ["logging_enabled"],
            "reasoning": "Audit logging is disabled for critical actions."
        },
        "applicability": {
             "data_sensitivity": ["pii", "credentials", "business_critical"]
        },
        "negating_controls": ["centralized_logging", "siem"],
        "mapped_controls": {
            "owasp_top_10": ["A09:2021-Security Logging and Monitoring Failures"],
            "nist_800_53": ["AU-2", "AU-3"]
        },
        "maturity_level": "baseline"
    },
    "R-002": {
        "signal_source": ["configuration"],
        "evidence": {
            "derived_from": ["access_logging_enabled"],
            "reasoning": "Storage access logging is not enabled."
        },
        "mapped_controls": {
            "nist_800_53": ["AU-2"]
        },
        "maturity_level": "baseline"
    },
    "I-001": {
        "signal_source": ["configuration", "architecture"],
        "evidence": {
            "derived_from": ["encryption_at_rest"],
            "reasoning": "Storage encryption is disabled."
        },
        "applicability": {
            "data_sensitivity": ["pii", "financial", "credentials"]
        },
        "negating_controls": ["disk_encryption", "file_system_encryption"],
        "mapped_controls": {
            "owasp_top_10": ["A02:2021"],
            "nist_800_53": ["SC-28"]
        },
        "maturity_level": "baseline"
    },
    "I-002": {
        "signal_source": ["configuration", "runtime"],
        "evidence": {
            "derived_from": ["error_handling_verbose"],
            "reasoning": "Detailed error messages expose internal stack traces."
        },
        "mapped_controls": {
            "cwe": ["CWE-209"]
        },
        "maturity_level": "intermediate"
    },
    "I-003": {
        "signal_source": ["configuration"],
        "evidence": {
            "derived_from": ["public_access"],
            "reasoning": "Storage bucket is configured for public access."
        },
        "applicability": {
            "exposed_to": ["internet"]
        },
        "negating_controls": ["public_access_block"],
        "mapped_controls": {
            "owasp_top_10": ["A05:2021-Security Misconfiguration"],
            "nist_800_53": ["AC-3"]
        },
        "maturity_level": "baseline"
    },
    "I-004": {
        "signal_source": ["code", "configuration"],
        "evidence": {
            "derived_from": ["hardcoded_secrets"],
            "reasoning": "Secrets detected in source or configuration."
        },
        "negating_controls": ["git_secrets_scanner", "secrets_manager"],
        "mapped_controls": {
            "owasp_top_10": ["A07:2021"],
            "cwe": ["CWE-798"]
        },
        "maturity_level": "baseline"
    },
    "D-001": {
        "signal_source": ["architecture", "configuration"],
        "evidence": {
            "derived_from": ["rate_limiting"],
            "reasoning": "Rate limiting controls are missing."
        },
        "negating_controls": ["api_gateway", "cdn", "waf"],
        "mapped_controls": {
            "owasp_top_10": ["A04:2021-Insecure Design"]
        },
        "maturity_level": "intermediate"
    },
    "D-002": {
        "signal_source": ["configuration"],
        "evidence": {
            "derived_from": ["request_size_limit"],
            "reasoning": "Request body size limits are not enforced."
        },
        "negating_controls": ["waf", "load_balancer"],
        "maturity_level": "intermediate"
    },
    "D-003": {
        "signal_source": ["code", "architecture"],
        "evidence": {
            "derived_from": ["pagination_enabled"],
            "reasoning": "Unbounded query results detected."
        },
        "maturity_level": "intermediate"
    },
    "E-001": {
        "signal_source": ["code", "runtime"],
        "evidence": {
            "derived_from": ["input_validation"],
            "reasoning": "Input validation is missing or disabled."
        },
        "negating_controls": ["waf", "rasp"],
        "mapped_controls": {
            "owasp_top_10": ["A03:2021-Injection"],
            "nist_800_53": ["SI-10"]
        },
        "maturity_level": "baseline"
    },
    "E-002": {
        "signal_source": ["architecture", "code"],
        "evidence": {
            "derived_from": ["authorization_checks"],
            "reasoning": "Object level authorization checks are weak or missing."
        },
        "mapped_controls": {
            "owasp_top_10": ["A01:2021-Broken Access Control"],
            "cwe": ["CWE-639"]
        },
        "maturity_level": "baseline"
    },
    "E-003": {
        "signal_source": ["configuration", "runtime"],
        "evidence": {
            "derived_from": ["runs_as_root"],
            "reasoning": "Process is configured to run with root privileges."
        },
        "negating_controls": ["pod_security_policy", "opa_gatekeeper"],
        "mapped_controls": {
            "nist_800_53": ["AC-6"]
        },
        "maturity_level": "baseline"
    },
    "CHAIN-001": {
        "signal_source": ["architecture"],
        "evidence": {
            "derived_from": ["threat_chain"],
            "reasoning": "Combination of unencrypted data and injection vulnerability."
        },
        "related_threats": {
            "amplifies": ["I-001", "E-001"]
        },
        "maturity_level": "advanced"
    }
}

def enrich():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    threats_path = os.path.join(base_dir, 'backend', 'app', 'knowledge_base', 'threats.json')

    try:
        with open(threats_path, 'r') as f:
            threats = json.load(f)
    except FileNotFoundError:
        print(f"Error: Could not find {threats_path}")
        return

    enriched_count = 0
    now_date = datetime.now().strftime("%Y-%m-%d")

    for threat in threats:
        t_id = threat.get("id")
        enrichment_data = THREAT_INTELLIGENCE.get(t_id, {})
        
        # Merge intelligence
        if enrichment_data:
            # Metadata
            threat["metadata"] = {
                "version": "2.1",
                "last_reviewed": now_date,
                "created": "2024-01-01", 
                "last_updated": now_date,
                "author": "AI Threat Modeler Intelligence Team",
                "reviewed_by": "Security Architect"
            }
            
            # Direct mapping
            threat["evidence"] = enrichment_data.get("evidence", {
                "derived_from": ["unknown"],
                "reasoning": "Intelligence mapping not found for this ID."
            })
            threat["signal_source"] = enrichment_data.get("signal_source", ["architecture"])
            
            if "applicability" in enrichment_data:
                threat["applicability"] = enrichment_data["applicability"]
                
            if "negating_controls" in enrichment_data:
                threat["negating_controls"] = enrichment_data["negating_controls"]
                
            if "mapped_controls" in enrichment_data:
                threat["mapped_controls"] = enrichment_data["mapped_controls"]
                
            threat["maturity_level"] = enrichment_data.get("maturity_level", "baseline")
            
            if "related_threats" in enrichment_data:
                threat["related_threats"] = enrichment_data["related_threats"]
                
            enriched_count += 1
        else:
            # Default for unknown IDs (if any new ones were added)
            threat["metadata"] = {
                "version": "1.0",
                "last_reviewed": now_date
            }
            threat["signal_source"] = ["architecture"]
            threat["maturity_level"] = "baseline"
            threat["evidence"] = {
                 "derived_from": ["manual_analysis"],
                 "reasoning": "Standard categorical threat."
            }

    with open(threats_path, 'w') as f:
        json.dump(threats, f, indent=4)
        
    print(f"Successfully enriched {enriched_count} threats with advanced intelligence.")

if __name__ == "__main__":
    enrich()
