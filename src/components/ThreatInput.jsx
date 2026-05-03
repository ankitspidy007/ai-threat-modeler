import React, { useState } from 'react';
import { Send, Cpu, ChevronDown, Upload, FileText } from 'lucide-react';

const DOMAIN_OPTIONS = [
    { value: 'general', label: 'General Software' },
    { value: 'saas', label: 'SaaS / Multi-tenant' },
    { value: 'fintech', label: 'Fintech / Payments' },
    { value: 'healthcare', label: 'Healthcare / PHI' },
    { value: 'ai', label: 'AI / LLM App' },
    { value: 'platform', label: 'Platform / Kubernetes' },
];

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
    const [useLocalSlm, setUseLocalSlm] = useState(true);
    const [domainProfile, setDomainProfile] = useState('general');
    const [uploadedFiles, setUploadedFiles] = useState([]);

    const canSubmit = description.trim() || uploadedFiles.length > 0;

    const handleSubmit = (e) => {
        e.preventDefault();
        if (canSubmit) {
            onAnalyze(description, projectName, useLocalSlm, {
                domainProfile,
                files: uploadedFiles,
                contextText: description,
            });
        }
    };

    const handleKeyDown = (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
            e.preventDefault();
            if (canSubmit && !isAnalyzing) {
                onAnalyze(description, projectName, useLocalSlm, {
                    domainProfile,
                    files: uploadedFiles,
                    contextText: description,
                });
            }
        }
    };

    const handleFileUpload = (e) => {
        const files = Array.from(e.target.files || []);
        setUploadedFiles(files);
    };

    const applyTemplate = (key) => {
        const template = TEMPLATES[key];
        setProjectName(template.name);
        setDescription(template.description);
        setDomainProfile(key === 'saas' ? 'saas' : key === 'healthcare' ? 'healthcare' : 'general');
        setShowTemplates(false);
    };

    return (
        <div className="w-full max-w-4xl mx-auto mb-10">
            <div className="glass-panel p-7 sm:p-8">
                <div className="flex items-start justify-between gap-4 mb-6">
                    <div>
                        <div className="inline-flex items-center gap-2 rounded-full bg-brand-primary/10 px-3 py-1 text-xs font-semibold uppercase tracking-[0.18em] text-brand-primary mb-3">
                            Architecture Intake
                        </div>
                        <h2 className="text-2xl font-bold flex items-center gap-2 text-brand-950 dark:text-white">
                        <Cpu className="w-6 h-6" />
                        System Architecture And Design Intake
                        </h2>
                        <p className="text-brand-600 dark:text-brand-400 text-sm mt-2 max-w-2xl">
                            Paste architecture notes, or upload requirement docs, design specs, architecture writeups, Markdown, or PDFs. Keep the content focused on components, trust boundaries, data flows, and known issues.
                        </p>
                    </div>
                    <div className="relative">
                        <button
                            type="button"
                            onClick={() => setShowTemplates(!showTemplates)}
                            className="text-sm flex items-center gap-1 px-3 py-2 border border-brand-200 dark:border-brand-600 rounded-xl hover:bg-white dark:hover:bg-brand-700 transition-colors text-brand-600 dark:text-brand-300 shadow-sm"
                        >
                            Use Template
                            <ChevronDown className={`w-4 h-4 transition-transform ${showTemplates ? 'rotate-180' : ''}`} />
                        </button>
                        {showTemplates && (
                            <div className="absolute right-0 top-full mt-2 w-64 bg-white/95 dark:bg-brand-800/95 border border-brand-200 dark:border-brand-600 rounded-2xl shadow-2xl backdrop-blur-xl z-20 p-1">
                                {Object.entries(TEMPLATES).map(([key, tmpl]) => (
                                    <button
                                        key={key}
                                        onClick={() => applyTemplate(key)}
                                        className="block w-full text-left px-4 py-3 text-sm hover:bg-brand-50 dark:hover:bg-brand-700 rounded-xl text-brand-700 dark:text-brand-300"
                                    >
                                        {tmpl.name}
                                    </button>
                                ))}
                            </div>
                        )}
                    </div>
                </div>
                <div className="grid gap-4 sm:grid-cols-[1.1fr_0.7fr_0.8fr] mb-5">
                    <div>
                    <label className="block text-xs font-mono text-brand-500 mb-1.5 uppercase tracking-[0.2em]">Project Name</label>
                    <input
                        type="text"
                        value={projectName}
                        onChange={(e) => setProjectName(e.target.value)}
                        className="input-brand w-full font-mono"
                        placeholder="e.g. Payment Gateway V2"
                    />
                    </div>
                    <div>
                        <label className="block text-xs font-mono text-brand-500 mb-1.5 uppercase tracking-[0.2em]">Domain Profile</label>
                        <select
                            value={domainProfile}
                            onChange={(e) => setDomainProfile(e.target.value)}
                            className="input-brand w-full font-mono"
                        >
                            {DOMAIN_OPTIONS.map((option) => (
                                <option key={option.value} value={option.value}>{option.label}</option>
                            ))}
                        </select>
                    </div>
                    <div className="rounded-2xl bg-brand-50/80 dark:bg-brand-900/30 border border-brand-200/80 dark:border-brand-700/60 px-4 py-3">
                        <div className="text-[11px] font-mono uppercase tracking-[0.18em] text-brand-500 mb-1">Best Inputs</div>
                        <p className="text-sm text-brand-700 dark:text-brand-300 leading-6">
                            Requirements, architecture design, auth, data stores, external APIs, trust boundaries, deployment, and known weaknesses.
                        </p>
                    </div>
                </div>
                <form onSubmit={handleSubmit} className="relative">
                    <div className="mb-4 rounded-2xl border border-brand-200/80 bg-white/70 p-4 dark:border-brand-700/60 dark:bg-brand-900/20">
                        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                            <div>
                                <p className="text-xs font-mono uppercase tracking-[0.18em] text-brand-500">Design Documents</p>
                                <p className="mt-1 text-sm text-brand-600 dark:text-brand-400">
                                    Upload one or more `.txt`, `.md`, `.pdf`, `.docx`, `.json`, or `.yaml` files.
                                </p>
                            </div>
                            <label className="inline-flex cursor-pointer items-center gap-2 rounded-xl border border-brand-200 px-4 py-2 text-sm font-semibold text-brand-700 transition-colors hover:bg-brand-50 dark:border-brand-600 dark:text-brand-300 dark:hover:bg-brand-800">
                                <Upload className="h-4 w-4" />
                                Add Files
                                <input
                                    type="file"
                                    multiple
                                    accept=".txt,.md,.markdown,.rst,.pdf,.docx,.json,.yaml,.yml,.csv"
                                    className="hidden"
                                    onChange={handleFileUpload}
                                    disabled={isAnalyzing}
                                />
                            </label>
                        </div>
                        {uploadedFiles.length > 0 && (
                            <div className="mt-4 flex flex-wrap gap-2">
                                {uploadedFiles.map((file) => (
                                    <span
                                        key={`${file.name}-${file.size}`}
                                        className="inline-flex items-center gap-2 rounded-full bg-brand-50 px-3 py-1.5 text-xs font-medium text-brand-700 dark:bg-brand-800 dark:text-brand-300"
                                    >
                                        <FileText className="h-3.5 w-3.5" />
                                        {file.name}
                                    </span>
                                ))}
                            </div>
                        )}
                    </div>
                    <textarea
                        className="input-brand w-full h-52 resize-none font-mono text-sm leading-relaxed"
                        placeholder="// Optional: add extra context, assumptions, or questions for the uploaded design documents... (Ctrl+Enter to submit)"
                        value={description}
                        onChange={(e) => setDescription(e.target.value)}
                        onKeyDown={handleKeyDown}
                        disabled={isAnalyzing}
                    />

                    {/* Local AI Engine Toggle */}
                    <div className="flex items-start gap-3 mt-5 p-4 bg-brand-50/80 dark:bg-brand-900/30 border border-brand-200/80 dark:border-brand-700/50 rounded-2xl">
                        <input
                            type="checkbox"
                            id="useLocalSlm"
                            checked={useLocalSlm}
                            onChange={(e) => setUseLocalSlm(e.target.checked)}
                            className="w-4 h-4 text-brand-primary bg-white border-brand-300 rounded focus:ring-brand-primary dark:focus:ring-brand-primary dark:ring-offset-brand-800 dark:bg-brand-700 dark:border-brand-600"
                        />
                        <div className="flex flex-col">
                            <label htmlFor="useLocalSlm" className="text-sm font-bold text-brand-800 dark:text-brand-200 cursor-pointer">
                                Enable Local Semantic AI Engine (Small LLM)
                            </label>
                            <span className="text-xs text-brand-500 dark:text-brand-400 mt-1 leading-5">
                                Uses on-device sentence embeddings to detect hidden architectural threats trained on the KB.
                            </span>
                        </div>
                    </div>

                    <div className="flex items-center justify-between mt-5">
                        <span className="text-xs text-brand-400 font-mono uppercase tracking-[0.18em]">Ctrl+Enter to submit</span>
                        <button
                            type="submit"
                            disabled={isAnalyzing || !canSubmit}
                            className={`btn-brand flex items-center gap-2 ${isAnalyzing ? 'opacity-50 cursor-not-allowed' : ''}`}
                        >
                            {isAnalyzing ? (
                                <>Analyzing...</>
                            ) : (
                                <>
                                    <Send className="w-4 h-4" />
                                    Analyze Design
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
