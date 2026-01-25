// Simulate AI processing delay and response
export const analyzeSystem = async (systemDescription) => {
    return new Promise((resolve) => {
        setTimeout(() => {
            resolve(generateMockResponse(systemDescription));
        }, 2000);
    });
};

const generateMockResponse = (text) => {
    const threats = [];
    const lowerText = text.toLowerCase();

    // 1. Trust Boundary Violations (Lateral Movement)
    // Logic: If there are internal services/microservices but no explicit mention of Zero Trust/segmentation.
    if ((lowerText.includes('microservice') || lowerText.includes('internal') || lowerText.includes('backend')) &&
        !lowerText.includes('zero trust') && !lowerText.includes('segmentation')) {
        threats.push({
            id: 1,
            category: 'Trust Boundary Violation',
            title: 'Implicit Trust in Internal Network',
            severity: 'High',
            likelihood: 'High',
            compliance: { owasp: 'A01: Broken Access Control', nist: 'AC-4' },
            explanation: 'The architecture appears to rely on network location for security. If one internal service is compromised, attackers may have unrestricted access to other internal services (Lateral Movement).',
            triggerConditions: ['Internal services mapped', 'No Zero Trust controls mentioned'],
            violatedAssumption: 'The internal network is a trusted safe haven.',
            impact: 'Full compromise of the internal environment. An attacker breaching one container or service can pivot to databases or other sensitive workloads without further authentication.',
            mitigation: 'Implement Mutual TLS (mTLS) between services. Enforce service-to-service authentication and least-privilege authorization policies (Zero Trust).',
            attackSimulation: [
                { step: 1, action: 'Attacker compromises a low-priority public-facing service (e.g., image resizer).', component: 'Public Service', control: 'Perimeter Firewall' },
                { step: 2, action: 'Attacker scans the internal network from the compromised container.', component: 'Internal Network', control: 'Network Segmentation' },
                { step: 3, action: 'Attacker connects directly to the internal Backend API which accepts all internal IPs.', component: 'Backend API', control: 'Service Auth' },
                { step: 4, action: 'Attacker exfiltrates sensitive data from the backend.', component: 'Database', control: 'Data Access Policy' }
            ]
        });
    }

    // 2. Single Point of Failure (Blast Radius)
    // Logic: Centralized DB or Monolith mentioned.
    if (lowerText.includes('monolith') || lowerText.includes('single database') || lowerText.includes('centralized db')) {
        threats.push({
            id: 2,
            category: 'Resilience',
            title: 'Excessive Blast Radius (Single Point of Failure)',
            severity: 'Medium',
            likelihood: 'Medium',
            compliance: { owasp: 'A04: Insecure Design', nist: 'CP-2' },
            explanation: 'The system relies on a single monolithic component or centralized database. A failure or compromise of this component impairs the entire system.',
            triggerConditions: ['Monolithic architecture', 'Centralized data store'],
            violatedAssumption: 'The centralized component is 100% reliable and secure.',
            impact: 'Total System Outage or Complete Data Loss. Logic flaws in the monolith affect all features simultaneously.',
            mitigation: 'Decouple components using event-driven architecture. Implement read replicas and failover strategies for the database. Break down the monolith where feasible.',
            attackSimulation: [
                { step: 1, action: 'Attacker triggers a resource-intensive operation on the monolith.', component: 'Monolith Core', control: 'Resource Isolation' },
                { step: 2, action: 'The shared database connection pool is exhausted.', component: 'Central Database', control: 'Connection Limits' },
                { step: 3, action: 'All application features (Auth, Billing, Core) become unresponsive.', component: 'System-wide', control: 'Redundancy' }
            ]
        });
    }

    // 3. Public Exposure (Attack Surface)
    // Logic: Public API/Internet facing.
    if (lowerText.includes('public api') || lowerText.includes('internet') || lowerText.includes('external')) {
        threats.push({
            id: 3,
            category: 'Exposure',
            title: 'Uncontrolled Public Attack Surface',
            severity: 'High',
            likelihood: 'High',
            compliance: { owasp: 'A05: Security Misconfiguration', nist: 'SC-7' },
            explanation: 'Critical system components are exposed to the public internet. Without rigorous perimeter controls, this increases the attack surface for automated scanners and botnets.',
            triggerConditions: ['Publicly accessible endpoints', 'Direct internet exposure'],
            violatedAssumption: 'The perimeter Gateway/WAF will catch 100% of malicious traffic.',
            impact: 'Service disruption via DDoS or exploitation of unpatched vulnerabilities in the exposed layer.',
            mitigation: 'Place all public endpoints behind a managed WAF and CDN. Minimize the list of public IPs. Use an API Gateway to handle ingress traffic.',
            attackSimulation: [
                { step: 1, action: 'Attacker uses Shodan or mass-scanners to identify the open API port.', component: 'Public API', control: 'Obscurity' },
                { step: 2, action: 'Attacker launches a volumetric DDoS attack against the endpoint.', component: 'Network Ingress', control: 'DDoS Protection' },
                { step: 3, action: 'The service is overwhelmed and legitimate traffic is dropped.', component: 'System Availability', control: 'Auto-scaling' }
            ]
        });
    }

    // 4. Tenant Isolation (SaaS/Multi-tenant)
    // Logic: Multi-tenant mentions.
    if (lowerText.includes('multi-tenant') || lowerText.includes('saas') || lowerText.includes('tenant')) {
        threats.push({
            id: 4,
            category: 'Isolation',
            title: 'Cross-Tenant Data Leakage',
            severity: 'Critical',
            likelihood: 'Medium',
            compliance: { owasp: 'A01: Broken Access Control', nist: 'AC-3' },
            explanation: 'In a shared resource environment, logical separation of tenant data is complex. A simple code error in a query could return data belonging to another tenant.',
            triggerConditions: ['Multi-tenant architecture', 'Shared database resources'],
            violatedAssumption: 'Application logic perfectly enforces tenant isolation at every query.',
            impact: 'Massive Data Breach. Accessing one tenant\'s environment allows viewing or modifying data of other tenants, destroying trust in the platform.',
            mitigation: 'Implement Row-Level Security (RLS) in the database. Use separate schemas or keyspaces for sensitive tenants. Mandate tenant_id in all API contexts.',
            attackSimulation: [
                { step: 1, action: 'Attacker logs in as a valid Tenant A user.', component: 'Auth Layer', control: 'Identity Check' },
                { step: 2, action: 'Attacker modifies the ID parameter in a URL to access Tenant B\'s resource.', component: 'API Endpoint', control: 'Authorization Check' },
                { step: 3, action: 'The system retrieves the record without verifying tenant ownership.', component: 'Data Access Layer', control: 'Tenant Scoping' },
                { step: 4, action: 'Attacker dumps sensitive reports belonging to a competitor.', component: 'Database', control: 'Row Level Security' }
            ]
        });
    }

    // Default Fallback (Architectural)
    if (threats.length === 0) {
        threats.push({
            id: 99,
            category: 'Design',
            title: 'Undefined Security Architecture',
            severity: 'Low',
            likelihood: 'Low',
            compliance: { owasp: 'A04: Insecure Design', nist: 'PL-8' },
            explanation: 'The provided description is too vague to infer specific architectural risks. However, generic risks regarding modularity and maintainability may apply.',
            triggerConditions: ['Vague system description', 'Lack of architectural keywords'],
            violatedAssumption: 'Security can be bolted on later.',
            impact: 'Technical Debt. Lack of clear security boundaries makes future hardening expensive and difficult.',
            mitigation: 'Define clear trust boundaries (e.g., Public vs Private, User vs Admin). Document data flow diagrams.',
            attackSimulation: null
        });
    }

    // Generate Architecture Diagram Syntax
    let diagram = "graph LR;\n    User((User)) --> Internet[Internet];\n    Internet --> App[Application];";
    if (lowerText.includes('database') || lowerText.includes('monolith')) {
        diagram += "\n    App --> DB[(Database)];";
    }
    if (lowerText.includes('api') || lowerText.includes('microservice')) {
        diagram += "\n    App --> API[API Gateway];\n    API --> Service[Internal Services];";
    }
    if (lowerText.includes('tenant')) {
        diagram += "\n    Service --> TenantA[(Tenant A DB)];\n    Service --> TenantB[(Tenant B DB)];";
    }

    return {
        summary: `Architectural Analysis for: "${text.substring(0, 50)}..."`,
        timestamp: new Date().toLocaleString(),
        threats: threats,
        diagram: diagram,
    };
};

