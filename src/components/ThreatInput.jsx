import React, { useState } from 'react';
import { Send, Cpu, ChevronDown } from 'lucide-react';

const TEMPLATES = {
    'e-commerce': {
        name: 'E-Commerce Platform',
        description: `E-commerce platform with:
- React frontend (public-facing)
- API Gateway with WAF and rate limiting
- Node.js REST API with JWT authentication
- PostgreSQL database with encryption at rest for user/product data
- MongoDB for order storage
- Redis cluster for session management and caching
- S3 bucket for product images
- Stripe integration for payment processing
- SendGrid for transactional emails
- Deployed on Kubernetes with centralized logging

KNOWN ISSUES:
- No query depth limiting on product search GraphQL endpoint
- Session tokens don't expire on password change`
    },
    'saas': {
        name: 'SaaS Platform',
        description: `Multi-tenant SaaS platform with:
- React SPA frontend hosted on CloudFront CDN
- API Gateway with OAuth2/OIDC authentication via Auth0
- Python FastAPI microservices:
  1. Auth Service: Handles user management and RBAC
  2. Tenant Service: Multi-tenant data isolation
  3. Billing Service: Integrates with Stripe for subscriptions
  4. Notification Service: Email (SendGrid) and push notifications
- PostgreSQL with row-level security for tenant isolation
- Redis for rate limiting and caching
- Elasticsearch for full-text search and audit logs
- RabbitMQ for async job processing
- Deployed on AWS ECS with CloudWatch monitoring

KNOWN ISSUES:
- CORS allows wildcard origins in staging environment
- API rate limiting not enforced on internal service-to-service calls`
    },
    'iot': {
        name: 'IoT Platform',
        description: `IoT device management platform with:
- Angular dashboard for device management
- MQTT broker (Mosquitto) for device communication
- Node.js REST API for device provisioning
- AWS IoT Core for device registry and shadows
- DynamoDB for time-series telemetry data
- S3 for firmware storage and OTA updates
- Lambda functions for real-time data processing
- SNS for alerting and notifications
- X.509 certificate-based device authentication
- VPC with private subnets for backend services

KNOWN ISSUES:
- Firmware updates not signed
- No rate limiting on MQTT message publishing
- Device certificates don't have expiration dates`
    },
    'healthcare': {
        name: 'Healthcare System',
        description: `Healthcare records management system with:
- React frontend with role-based access (Doctor, Nurse, Admin)
- .NET Core REST API with OAuth2 + MFA authentication
- PostgreSQL for patient records (PHI/PII data)
- Redis for session management
- Azure Blob Storage for medical imaging (DICOM files)
- HL7 FHIR API for interoperability
- Azure AD for identity management
- Encryption at rest (AES-256) and in transit (TLS 1.3)
- Audit logging for all data access
- HIPAA-compliant infrastructure on Azure

KNOWN ISSUES:
- Break-the-glass access procedure not audited separately
- No data loss prevention (DLP) on file downloads
- Session timeout set to 8 hours (too long for PHI access)`
    }
};

const ThreatInput = ({ onAnalyze, isAnalyzing }) => {
    const [description, setDescription] = useState('');
    const [projectName, setProjectName] = useState('My Security Audit');
    const [showTemplates, setShowTemplates] = useState(false);

    const handleSubmit = (e) => {
        e.preventDefault();
        if (description.trim()) {
            onAnalyze(description, projectName);
        }
    };

    const handleKeyDown = (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
            e.preventDefault();
            if (description.trim() && !isAnalyzing) {
                onAnalyze(description, projectName);
            }
        }
    };

    const applyTemplate = (key) => {
        const template = TEMPLATES[key];
        setProjectName(template.name);
        setDescription(template.description);
        setShowTemplates(false);
    };

    return (
        <div className="w-full max-w-3xl mx-auto mb-10">
            <div className="glass-panel rounded-xl p-6 border-l-4 border-l-brand-primary dark:bg-brand-800 dark:border-brand-700">
                <div className="flex items-center justify-between mb-4">
                    <h2 className="text-xl font-bold flex items-center gap-2 text-brand-primary">
                        <Cpu className="w-6 h-6" />
                        System Architecture Description
                    </h2>
                    <div className="relative">
                        <button
                            type="button"
                            onClick={() => setShowTemplates(!showTemplates)}
                            className="text-sm flex items-center gap-1 px-3 py-1.5 border border-brand-300 dark:border-brand-600 rounded-lg hover:bg-brand-100 dark:hover:bg-brand-700 transition-colors text-brand-600 dark:text-brand-300"
                        >
                            Use Template
                            <ChevronDown className={`w-4 h-4 transition-transform ${showTemplates ? 'rotate-180' : ''}`} />
                        </button>
                        {showTemplates && (
                            <div className="absolute right-0 top-full mt-1 w-56 bg-white dark:bg-brand-800 border border-brand-200 dark:border-brand-600 rounded-lg shadow-xl z-20">
                                {Object.entries(TEMPLATES).map(([key, tmpl]) => (
                                    <button
                                        key={key}
                                        onClick={() => applyTemplate(key)}
                                        className="block w-full text-left px-4 py-2.5 text-sm hover:bg-brand-100 dark:hover:bg-brand-700 first:rounded-t-lg last:rounded-b-lg text-brand-700 dark:text-brand-300"
                                    >
                                        {tmpl.name}
                                    </button>
                                ))}
                            </div>
                        )}
                    </div>
                </div>
                <div className="mb-4">
                    <label className="block text-xs font-mono text-brand-500 mb-1">Project Name</label>
                    <input
                        type="text"
                        value={projectName}
                        onChange={(e) => setProjectName(e.target.value)}
                        className="input-brand w-full font-mono"
                        placeholder="e.g. Payment Gateway V2"
                    />
                </div>
                <p className="text-brand-600 dark:text-brand-400 text-sm mb-4">
                    Describe your system architecture, or choose a template above to get started quickly.
                </p>
                <form onSubmit={handleSubmit} className="relative">
                    <textarea
                        className="input-brand w-full h-40 resize-none font-mono text-sm leading-relaxed"
                        placeholder="// Describe your stack here... (Ctrl+Enter to submit)"
                        value={description}
                        onChange={(e) => setDescription(e.target.value)}
                        onKeyDown={handleKeyDown}
                        disabled={isAnalyzing}
                    />
                    <div className="flex items-center justify-between mt-4">
                        <span className="text-xs text-brand-400 font-mono">Ctrl+Enter to submit</span>
                        <button
                            type="submit"
                            disabled={isAnalyzing || !description.trim()}
                            className={`btn-brand flex items-center gap-2 ${isAnalyzing ? 'opacity-50 cursor-not-allowed' : ''}`}
                        >
                            {isAnalyzing ? (
                                <>Analyzing...</>
                            ) : (
                                <>
                                    <Send className="w-4 h-4" />
                                    Analyze Threats
                                </>
                            )}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
};

export default ThreatInput;
