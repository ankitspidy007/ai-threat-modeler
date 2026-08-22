"""High-signal source-code security checks used by the code analysis endpoint."""

from __future__ import annotations

import re
from typing import Any, Dict, List


class CodeSecurityAnalyzer:
    """Detect explicit dangerous source patterns without claiming full data-flow analysis."""

    RULES = [
        ("CODE-SQLI-DYNAMIC-QUERY", "High", "SQL injection through dynamic query construction", "Injection", "CWE-89", "Use parameterized queries or a safe ORM API; never concatenate request data into SQL.", [
            r"(?:execute|query|raw)\s*\(\s*(?:f?[\"'][^\n]*\{[^}]+\}|[\"'][^\n]*\+|`[^`]*\$\{)",
            r"(?:SELECT|INSERT|UPDATE|DELETE)\b[^\n]*(?:\+|\$\{|%s)",
        ]),
        ("CODE-NOSQL-INJECTION", "High", "NoSQL query accepts request-controlled selector", "Injection", "CWE-943", "Validate and allow-list query operators; build selectors from typed fields rather than request objects.", [
            r"(?:find|findOne|aggregate)\s*\(\s*(?:req\.(?:body|query|params)|request\.(?:json|args))",
        ]),
        ("CODE-XSS-DANGEROUS-SINK", "High", "Cross-site scripting through an unsafe HTML sink", "Tampering", "CWE-79", "Use framework-safe rendering and sanitize HTML with a maintained allow-list sanitizer before an unavoidable HTML sink.", [
            r"\.innerHTML\s*=", r"dangerouslySetInnerHTML", r"document\.write\s*\(", r"v-html\s*=",
        ]),
        ("CODE-INPUT-VALIDATION-DISABLED", "High", "Input validation is explicitly disabled", "Tampering", "CWE-20", "Validate type, format, range, length, and allow-listed values at every trust boundary before using the input.", [
            r"(?:validate|validation|schema_validation)\s*[:=]\s*false", r"skip(?:Input)?Validation\s*[:=]\s*true",
        ]),
        ("CODE-AUTHZ-CLIENT-ROLE", "Critical", "Authorization decision trusts a client-controlled role", "Elevation of Privilege", "CWE-639", "Derive roles and ownership from a verified server-side identity and enforce object-level authorization on every request.", [
            r"(?:isAdmin|role|permission)\s*=\s*(?:req\.(?:body|query|params)|request\.(?:json|args))",
            r"(?:req\.(?:body|query|params)|request\.(?:json|args))\.(?:isAdmin|role|permission)",
        ]),
        ("CODE-SESSION-INSECURE-COOKIE", "High", "Session cookie lacks a required security flag", "Spoofing", "CWE-614", "Set Secure, HttpOnly, and an appropriate SameSite value; rotate session identifiers after authentication.", [
            r"(?:httpOnly|httponly)\s*[:=]\s*false", r"\bsecure\s*[:=]\s*false", r"sameSite\s*[:=]\s*[\"']none[\"']",
        ]),
        ("CODE-CSRF-DISABLED", "High", "CSRF protection is explicitly disabled", "Tampering", "CWE-352", "Enable CSRF tokens or a same-site request strategy for every cookie-authenticated state-changing endpoint.", [
            r"csrf(?:Protection)?\s*[:=]\s*false", r"\.disable\s*\(\s*[\"']csrf[\"']\s*\)",
        ]),
        ("CODE-JWT-UNVERIFIED", "Critical", "JWT is decoded or accepted without signature verification", "Spoofing", "CWE-347", "Verify signatures with an algorithm allow-list, validate issuer/audience/expiry, and reject unsigned tokens.", [
            r"jwt\.decode\s*\([^\n;]*(?:verify\s*[:=]\s*false|algorithms?\s*[:=]\s*\[[^\]]*[\"']none)",
            r"verify_signature\s*[=:]\s*False",
        ]),
        ("CODE-COMMAND-INJECTION", "Critical", "Command execution receives dynamically constructed input", "Injection", "CWE-78", "Avoid shell invocation. Use fixed command arguments, allow-list input, and pass argv arrays without a shell.", [
            r"(?:exec|execSync|spawn)\s*\(\s*(?:req\.|request\.|.*\+|f?[\"'][^\n]*\{|`[^`]*\$\{)",
            r"subprocess\.(?:run|Popen|call)\([^\n]*(?:shell\s*=\s*True|request\.|\+)",
        ]),
        ("CODE-PATH-TRAVERSAL", "High", "File path is built from request-controlled input", "Information Disclosure", "CWE-22", "Normalize and allow-list paths, resolve them against a fixed base directory, and reject traversal sequences.", [
            r"(?:sendFile|readFile|open)\s*\(\s*(?:req\.(?:params|query|body)|request\.(?:args|json)|.*\+)",
            r"(?:path\.join|os\.path\.join)\([^\n]*(?:req\.|request\.)",
        ]),
        ("CODE-UNSAFE-DESERIALIZATION", "Critical", "Unsafe deserialization of untrusted data", "Tampering", "CWE-502", "Use safe serialization formats and strict schemas; never deserialize untrusted data with pickle, unsafe YAML, or native object serializers.", [
            r"pickle\.loads?\s*\(", r"yaml\.load\s*\((?![^\n]*SafeLoader)", r"ObjectInputStream",
        ]),
        ("CODE-SSRF-REQUEST-URL", "High", "Server-side request uses a request-controlled URL", "Information Disclosure", "CWE-918", "Allow-list destination hosts, resolve and block private/link-local addresses, and disable unsafe redirects.", [
            r"(?:requests\.(?:get|post)|axios\.(?:get|post)|fetch)\s*\(\s*(?:req\.|request\.)",
        ]),
        ("CODE-OPEN-REDIRECT", "Medium", "Redirect target is request controlled", "Spoofing", "CWE-601", "Allow-list redirect destinations or use server-side route identifiers rather than arbitrary URLs.", [
            r"(?:redirect|location\.assign)\s*\(\s*(?:req\.|request\.)",
        ]),
        ("CODE-WEAK-CRYPTO", "High", "Weak or obsolete cryptography is used", "Information Disclosure", "CWE-327", "Use modern authenticated encryption and SHA-256 or stronger hashing. Do not use ECB mode, MD5, DES, or RC4 for security decisions.", [
            r"(?:md5|sha1|des|rc4)\s*\(", r"AES(?:/|_)ECB", r"MODE_ECB",
        ]),
        ("CODE-HARDCODED-SECRET", "High", "Likely hard-coded secret in source", "Information Disclosure", "CWE-798", "Move credentials to a managed secret store, rotate the exposed value, and prevent secrets from entering source control.", [
            r"(?:api[_-]?key|secret|password|access[_-]?token)\s*[:=]\s*[\"'][^\"'\s]{8,}[\"']",
            r"AKIA[0-9A-Z]{16}",
        ]),
        ("CODE-PERMISSIVE-CORS", "Medium", "CORS permits arbitrary origins with credentials", "Information Disclosure", "CWE-942", "Use an explicit origin allow-list and never combine credentials with a wildcard origin.", [
            r"(?:origin\s*[:=]\s*[\"']\*[\"'].*credentials\s*[:=]\s*true|allow_origins\s*=\s*\[[\"']\*[\"']\].*allow_credentials\s*=\s*True)",
        ]),
    ]

    # Every occurrence is a separate defect to fix, so all of them are reported
    # rather than only the first. The cap keeps a pathological file from
    # producing thousands of findings, and truncation is stated on the finding.
    MAX_FINDINGS_PER_RULE = 25

    def analyze(self, content: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for rule_id, severity, title, category, cwe, mitigation, patterns in self.RULES:
            occurrences: Dict[int, str] = {}
            for pattern in patterns:
                for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                    line = content.count("\n", 0, match.start()) + 1
                    occurrences.setdefault(
                        line, match.group(0).strip().replace("\n", " ")[:180]
                    )
            if not occurrences:
                continue
            reported = sorted(occurrences)[: self.MAX_FINDINGS_PER_RULE]
            omitted = len(occurrences) - len(reported)
            for line in reported:
                evidence = occurrences[line]
                finding = {
                    "id": f"{rule_id}:{line}",
                    "rule_id": rule_id,
                    "resource_id": f"source line {line}",
                    "line": line,
                    "severity": severity,
                    "title": title,
                    "description": f"Matched unsafe source pattern near line {line}: {evidence}",
                    "mitigation": mitigation,
                    "category": category,
                    "cwe": [cwe],
                    "evidence": [f"Source line {line}: {evidence}"],
                    "rule_match_count": len(occurrences),
                }
                if omitted and line == reported[0]:
                    finding["truncated_matches"] = omitted
                    finding["evidence"].append(
                        f"{omitted} further matches for {rule_id} were not listed individually."
                    )
                findings.append(finding)
        return findings
