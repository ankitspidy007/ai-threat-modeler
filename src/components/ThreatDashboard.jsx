import React, { useEffect, useRef, useState } from 'react';
import { ShieldAlert, AlertTriangle, CheckCircle, Download, FileText, Share2, Code, Filter, Search, X, Copy, ClipboardCheck } from 'lucide-react';
import { generateReport } from '../utils/pdfGenerator';
import { clsx } from 'clsx';
import mermaid from 'mermaid';
import RiskMatrix from './RiskMatrix';
import StrideChart from './StrideChart';
import { useToast } from './Toast';
import html2canvas from 'html2canvas';

const SeverityBadge = ({ severity }) => {
    const colors = {
        Critical: 'bg-red-50 text-red-600 border-red-500 dark:bg-red-900/30 dark:text-red-400',
        High: 'bg-orange-50 text-orange-600 border-orange-500 dark:bg-orange-900/30 dark:text-orange-400',
        Medium: 'bg-yellow-50 text-yellow-600 border-yellow-500 dark:bg-yellow-900/30 dark:text-yellow-400',
        Low: 'bg-blue-50 text-blue-600 border-blue-500 dark:bg-blue-900/30 dark:text-blue-400',
    };

    return (
        <span className={clsx('px-2 py-1 rounded text-xs font-bold border', colors[severity] || colors.Low)}>
            {severity?.toUpperCase()}
        </span>
    );
};

const ThreatCard = ({ threat }) => (
    <div className="bg-white dark:bg-brand-800 border border-brand-200 dark:border-brand-700 rounded-lg p-4 shadow-sm hover:shadow-md transition-shadow">
        <div className="flex justify-between items-start mb-2">
            <div>
                <div className="flex items-center gap-2 mb-1 flex-wrap">
                    <SeverityBadge severity={threat.severity} />
                    <span className={clsx(
                        'px-2 py-0.5 rounded text-[10px] font-bold',
                        threat.tier === 'Confirmed'
                            ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400'
                            : 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400'
                    )}>
                        {threat.tier}
                    </span>
                    <span className="text-xs text-brand-500 dark:text-brand-400">Confidence: {threat.confidence}</span>
                </div>
                <h4 className="font-bold text-brand-900 dark:text-white">{threat.title}</h4>
                <div className="text-xs text-brand-500 dark:text-brand-400">
                    {threat.category}
                    {threat.stride_category && threat.stride_category !== threat.category && ` → ${threat.stride_category}`}
                </div>
            </div>
        </div>

        <p className="text-sm text-brand-700 dark:text-brand-300 mb-3">{threat.description}</p>

        {/* Aggregated Affected Components */}
        {threat.affected_components && threat.affected_components.length > 0 && (
            <div className="text-xs mb-2">
                <span className="font-bold text-brand-600 dark:text-brand-400">Affected Components: </span>
                <span className="text-brand-800 dark:text-brand-300">{threat.affected_components.join(', ')}</span>
            </div>
        )}

        {threat.affected_data_flows && threat.affected_data_flows.length > 0 && (
            <div className="text-xs mb-2">
                <span className="font-bold text-brand-600 dark:text-brand-400">Affected Data Flows: </span>
                <span className="text-brand-800 dark:text-brand-300">{threat.affected_data_flows.join(', ')}</span>
            </div>
        )}

        {/* Evidence */}
        {threat.evidence && threat.evidence.length > 0 && (
            <div className="bg-brand-50 dark:bg-brand-700/50 p-2 rounded text-xs mb-3">
                <span className="font-bold text-brand-600 dark:text-brand-400">Evidence:</span>
                <ul className="list-disc list-inside mt-1">
                    {threat.evidence.map((ev, i) => <li key={i} className="text-brand-700 dark:text-brand-300">{ev}</li>)}
                </ul>
            </div>
        )}

        <div className="flex items-start gap-2 bg-green-50 dark:bg-green-900/20 p-2 rounded">
            <CheckCircle className="w-4 h-4 text-green-600 dark:text-green-400 mt-0.5 shrink-0" />
            <p className="text-sm text-green-800 dark:text-green-300">{threat.mitigation}</p>
        </div>

        {/* Compliance Framework Mappings */}
        {(threat.cwe?.length > 0 || threat.mitre_attack?.length > 0 || threat.owasp_top_10?.length > 0 || threat.nist_800_53?.length > 0) && (
            <div className="mt-3 flex flex-wrap gap-1.5">
                {threat.cwe?.map((id, i) => (
                    <a key={`cwe-${i}`} href={`https://cwe.mitre.org/data/definitions/${id.replace('CWE-', '')}.html`}
                        target="_blank" rel="noopener noreferrer"
                        className="px-2 py-0.5 rounded text-[10px] font-semibold bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400 hover:bg-red-200 transition-colors cursor-pointer">
                        {id}
                    </a>
                ))}
                {threat.mitre_attack?.map((id, i) => (
                    <a key={`mitre-${i}`} href={`https://attack.mitre.org/techniques/${id.replace('.', '/')}`}
                        target="_blank" rel="noopener noreferrer"
                        className="px-2 py-0.5 rounded text-[10px] font-semibold bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400 hover:bg-purple-200 transition-colors cursor-pointer">
                        MITRE {id}
                    </a>
                ))}
                {threat.owasp_top_10?.map((id, i) => (
                    <span key={`owasp-${i}`}
                        className="px-2 py-0.5 rounded text-[10px] font-semibold bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400">
                        OWASP {id}
                    </span>
                ))}
                {threat.nist_800_53?.map((id, i) => (
                    <span key={`nist-${i}`}
                        className="px-2 py-0.5 rounded text-[10px] font-semibold bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400">
                        NIST {id}
                    </span>
                ))}
            </div>
        )}
    </div>
);

const ThreatDashboard = ({ data, projectName }) => {
    const mermaidRef = useRef(null);
    const toast = useToast();
    const [copiedDiagram, setCopiedDiagram] = useState(false);

    // Filter states
    const [filters, setFilters] = useState({
        severity: 'all',
        category: 'all',
        tier: 'all',
        search: ''
    });
    const [showFilters, setShowFilters] = useState(false);

    useEffect(() => {
        const renderDiagram = async () => {
            if (!data?.diagram || !mermaidRef.current) return;

            try {
                const isDark = document.documentElement.classList.contains('dark');
                mermaid.initialize({
                    startOnLoad: false,
                    theme: isDark ? 'dark' : 'default',
                    securityLevel: 'loose',
                    fontFamily: 'Arial, sans-serif'
                });

                mermaidRef.current.innerHTML = '';
                const diagramId = `mermaid-diagram-${Date.now()}`;
                const { svg } = await mermaid.render(diagramId, data.diagram);
                mermaidRef.current.innerHTML = svg;
            } catch (error) {
                console.error('Mermaid rendering error:', error);
                mermaidRef.current.innerHTML = `
                    <div class="text-center p-4">
                        <p class="text-red-600 dark:text-red-400 font-semibold mb-2">Failed to render architecture diagram</p>
                        <p class="text-sm text-gray-600 dark:text-gray-400">Error: ${error.message}</p>
                    </div>
                `;
            }
        };

        renderDiagram();
    }, [data]);

    if (!data) return null;

    // Get unique values for filters
    const severities = ['all', ...new Set(data.threats?.map(t => t.severity) || [])];
    const categories = ['all', ...new Set(data.threats?.map(t => t.category) || [])];
    const tiers = ['all', 'Confirmed', 'Potential'];

    // Apply filters
    const filteredThreats = (data.threats || []).filter(threat => {
        if (filters.severity !== 'all' && threat.severity !== filters.severity) return false;
        if (filters.category !== 'all' && threat.category !== filters.category) return false;
        if (filters.tier !== 'all' && threat.tier !== filters.tier) return false;
        if (filters.search && !threat.title.toLowerCase().includes(filters.search.toLowerCase()) &&
            !threat.description.toLowerCase().includes(filters.search.toLowerCase())) return false;
        return true;
    });

    // Separate threats by tier
    const confirmed = filteredThreats.filter(t => t.tier === 'Confirmed');
    const potential = filteredThreats.filter(t => t.tier === 'Potential');

    const handleRiskMatrixClick = (impact, likelihood) => {
        // Map matrix click to severity filter — 'High' impact includes 'Critical'
        const severityValues = impact === 'High' ? ['High', 'Critical'] : [impact];
        // For simplicity, filter by the impact level as severity
        setFilters(prev => ({
            ...prev,
            severity: impact === 'High' ? 'all' : impact, // 'all' if High to capture Criticals too
        }));
        setShowFilters(true);
        toast.success(`Filtering by ${impact} severity × ${likelihood} likelihood`);
    };

    const copyDiagramCode = async () => {
        if (!data?.diagram) return;
        try {
            await navigator.clipboard.writeText(data.diagram);
            setCopiedDiagram(true);
            toast.success('Diagram code copied to clipboard!');
            setTimeout(() => setCopiedDiagram(false), 2000);
        } catch {
            toast.error('Failed to copy diagram code');
        }
    };

    const downloadJSON = () => {
        try {
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${projectName.replace(/\s+/g, '_')}_threat_model.json`;
            a.click();
            toast.success('JSON file downloaded successfully!');
        } catch (error) {
            toast.error('Failed to download JSON file');
        }
    };

    const downloadCSV = () => {
        try {
            const headers = ['ID', 'Tier', 'Severity', 'Confidence', 'Category', 'Title', 'Description', 'Mitigation'];
            const rows = data.threats.map(t => [
                t.id, t.tier, t.severity, t.confidence, t.category, t.title, t.description, t.mitigation
            ].map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(','));

            const csv = [headers.join(','), ...rows].join('\n');
            const blob = new Blob([csv], { type: 'text/csv' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${projectName.replace(/\s+/g, '_')}_threat_model.csv`;
            a.click();
            toast.success('CSV file downloaded successfully!');
        } catch (error) {
            toast.error('Failed to download CSV file');
        }
    };

    const downloadMarkdown = () => {
        try {
            const blob = new Blob([data.report_markdown], { type: 'text/markdown' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${projectName.replace(/\s+/g, '_')}_Threat_Report.md`;
            a.click();
            toast.success('Markdown report downloaded successfully!');
        } catch (error) {
            toast.error('Failed to download markdown file');
        }
    };

    const exportDiagramAsPNG = async () => {
        try {
            const element = mermaidRef.current;
            if (!element) {
                toast.error('Diagram not available');
                return;
            }
            const canvas = await html2canvas(element);
            const link = document.createElement('a');
            link.download = `${projectName.replace(/\s+/g, '_')}_architecture.png`;
            link.href = canvas.toDataURL();
            link.click();
            toast.success('Diagram exported as PNG!');
        } catch (error) {
            toast.error('Failed to export diagram');
        }
    };

    const handlePDFExport = () => {
        try {
            generateReport(data, projectName);
            toast.success('PDF report generated successfully!');
        } catch (error) {
            toast.error('Failed to generate PDF report');
        }
    };

    const clearFilters = () => {
        setFilters({ severity: 'all', category: 'all', tier: 'all', search: '' });
    };

    const hasActiveFilters = filters.severity !== 'all' || filters.category !== 'all' ||
        filters.tier !== 'all' || filters.search !== '';

    // Remediation stats
    const totalThreats = data.threats?.length || 0;
    const mitigatedThreats = (data.threats || []).filter(t => t.status === 'Mitigated' || t.status === 'Accepted').length;
    const remediationPercent = totalThreats > 0 ? Math.round((mitigatedThreats / totalThreats) * 100) : 0;

    return (
        <div className="w-full max-w-6xl mx-auto animate-fade-in-up pb-20">
            <div className="flex justify-between items-center mb-6 flex-wrap gap-4">
                <h2 className="text-2xl font-bold flex items-center gap-2 text-brand-900 dark:text-white">
                    <ShieldAlert className="w-8 h-8 text-brand-success" />
                    Threat Analysis Report
                </h2>
                <div className="flex gap-2 flex-wrap">
                    <button
                        onClick={() => setShowFilters(!showFilters)}
                        className="flex items-center gap-2 bg-brand-100 dark:bg-brand-700 hover:bg-brand-200 dark:hover:bg-brand-600 text-brand-700 dark:text-brand-200 px-3 py-2 rounded border border-brand-300 dark:border-brand-600 text-sm transition-colors shadow-sm"
                    >
                        <Filter className="w-4 h-4" />
                        Filters {hasActiveFilters && `(${filteredThreats.length})`}
                    </button>
                    <button onClick={downloadJSON} className="flex items-center gap-2 bg-white dark:bg-brand-800 hover:bg-brand-50 dark:hover:bg-brand-700 text-brand-700 dark:text-brand-300 px-3 py-2 rounded border border-brand-200 dark:border-brand-600 text-sm transition-colors shadow-sm">
                        <Code className="w-4 h-4" /> JSON
                    </button>
                    <button onClick={downloadCSV} className="flex items-center gap-2 bg-white dark:bg-brand-800 hover:bg-brand-50 dark:hover:bg-brand-700 text-brand-700 dark:text-brand-300 px-3 py-2 rounded border border-brand-200 dark:border-brand-600 text-sm transition-colors shadow-sm">
                        <Share2 className="w-4 h-4" /> CSV
                    </button>
                    {data.report_markdown && (
                        <button
                            onClick={downloadMarkdown}
                            className="flex items-center gap-2 bg-purple-50 dark:bg-purple-900/30 hover:bg-purple-100 dark:hover:bg-purple-900/50 text-purple-700 dark:text-purple-300 px-3 py-2 rounded border border-purple-200 dark:border-purple-800 text-sm transition-colors shadow-sm"
                        >
                            <FileText className="w-4 h-4" /> MD
                        </button>
                    )}
                    <button
                        onClick={handlePDFExport}
                        className="flex items-center gap-2 bg-brand-primary hover:bg-brand-primary/90 text-white px-4 py-2 rounded transition-colors shadow-md"
                    >
                        <Download className="w-4 h-4" />
                        Export PDF
                    </button>
                </div>
            </div>

            {/* Filter Panel */}
            {showFilters && (
                <div className="bg-white dark:bg-brand-800 border border-brand-200 dark:border-brand-700 rounded-lg p-4 mb-6 shadow-sm">
                    <div className="flex items-center justify-between mb-4">
                        <h3 className="font-bold text-brand-900 dark:text-white">Filter Threats</h3>
                        {hasActiveFilters && (
                            <button
                                onClick={clearFilters}
                                className="text-sm text-brand-600 dark:text-brand-400 hover:text-brand-800 dark:hover:text-white flex items-center gap-1"
                            >
                                <X className="w-4 h-4" /> Clear All
                            </button>
                        )}
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                        <div>
                            <label className="block text-sm font-medium text-brand-700 dark:text-brand-300 mb-1">Search</label>
                            <div className="relative">
                                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-brand-400" />
                                <input
                                    type="text"
                                    value={filters.search}
                                    onChange={(e) => setFilters({ ...filters, search: e.target.value })}
                                    placeholder="Search threats..."
                                    className="w-full pl-9 pr-3 py-2 border border-brand-300 dark:border-brand-600 dark:bg-brand-700 dark:text-white rounded focus:outline-none focus:ring-2 focus:ring-brand-primary text-sm"
                                />
                            </div>
                        </div>
                        <div>
                            <label className="block text-sm font-medium text-brand-700 dark:text-brand-300 mb-1">Severity</label>
                            <select
                                value={filters.severity}
                                onChange={(e) => setFilters({ ...filters, severity: e.target.value })}
                                className="w-full px-3 py-2 border border-brand-300 dark:border-brand-600 dark:bg-brand-700 dark:text-white rounded focus:outline-none focus:ring-2 focus:ring-brand-primary text-sm"
                            >
                                {severities.map(s => (
                                    <option key={s} value={s}>{s === 'all' ? 'All Severities' : s}</option>
                                ))}
                            </select>
                        </div>
                        <div>
                            <label className="block text-sm font-medium text-brand-700 dark:text-brand-300 mb-1">Category</label>
                            <select
                                value={filters.category}
                                onChange={(e) => setFilters({ ...filters, category: e.target.value })}
                                className="w-full px-3 py-2 border border-brand-300 dark:border-brand-600 dark:bg-brand-700 dark:text-white rounded focus:outline-none focus:ring-2 focus:ring-brand-primary text-sm"
                            >
                                {categories.map(c => (
                                    <option key={c} value={c}>{c === 'all' ? 'All Categories' : c}</option>
                                ))}
                            </select>
                        </div>
                        <div>
                            <label className="block text-sm font-medium text-brand-700 dark:text-brand-300 mb-1">Tier</label>
                            <select
                                value={filters.tier}
                                onChange={(e) => setFilters({ ...filters, tier: e.target.value })}
                                className="w-full px-3 py-2 border border-brand-300 dark:border-brand-600 dark:bg-brand-700 dark:text-white rounded focus:outline-none focus:ring-2 focus:ring-brand-primary text-sm"
                            >
                                {tiers.map(t => (
                                    <option key={t} value={t}>{t === 'all' ? 'All Tiers' : t}</option>
                                ))}
                            </select>
                        </div>
                    </div>
                </div>
            )}

            <div id="report-content" className="space-y-6 p-8 bg-white dark:bg-brand-800 text-brand-900 dark:text-brand-100 rounded-xl shadow-lg border border-brand-100 dark:border-brand-700">
                {/* Header Info */}
                <div className="border-b-2 border-brand-100 dark:border-brand-700 pb-4 mb-6 flex justify-between items-end">
                    <div>
                        <div className="flex items-center gap-2 mb-2 text-brand-primary">
                            <FileText className="w-6 h-6" />
                            <h1 className="text-2xl font-bold uppercase tracking-wider">Analysis Summary</h1>
                        </div>
                        <h2 className="text-xl font-bold text-brand-900 dark:text-white mb-2">{projectName}</h2>
                        <p className="text-lg font-medium mb-1 text-brand-700 dark:text-brand-300">{data.summary}</p>
                        <p className="text-xs text-brand-400">Generated at: {data.timestamp || new Date().toLocaleString()}</p>
                    </div>
                    <div className="text-right">
                        <h3 className="text-sm font-bold text-brand-400 uppercase">Security Score</h3>
                        <div className={clsx(
                            "text-4xl font-black",
                            data.score >= 70 ? "text-green-600 dark:text-green-400" : data.score >= 40 ? "text-yellow-600 dark:text-yellow-400" : "text-red-600 dark:text-red-400"
                        )}>
                            {data.score}/100
                        </div>
                        <div className="text-xs text-brand-500 dark:text-brand-400">
                            {confirmed.length} confirmed, {potential.length} potential
                        </div>
                    </div>
                </div>

                {/* Remediation Progress */}
                {totalThreats > 0 && (
                    <div className="bg-brand-50 dark:bg-brand-700/50 rounded-lg p-4 mb-2">
                        <div className="flex items-center justify-between mb-2">
                            <span className="text-sm font-bold text-brand-700 dark:text-brand-300">Remediation Progress</span>
                            <span className="text-sm font-mono text-brand-600 dark:text-brand-400">{mitigatedThreats}/{totalThreats} addressed</span>
                        </div>
                        <div className="w-full bg-brand-200 dark:bg-brand-600 rounded-full h-2.5">
                            <div
                                className="bg-brand-primary h-2.5 rounded-full transition-all duration-500"
                                style={{ width: `${remediationPercent}%` }}
                            />
                        </div>
                    </div>
                )}

                {/* Charts Row: Risk Matrix + STRIDE Chart */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
                    <RiskMatrix threats={data.threats} onCellClick={handleRiskMatrixClick} />
                    <StrideChart threats={data.threats || []} />
                </div>

                {/* Architecture Diagram */}
                <div className="bg-brand-50 dark:bg-brand-700/30 border border-brand-200 dark:border-brand-600 rounded-lg p-4 mb-8">
                    <div className="flex items-center justify-between mb-2">
                        <h3 className="font-bold text-lg text-brand-800 dark:text-white flex-1">
                            Inferred Architecture
                        </h3>
                        <div className="flex items-center gap-2">
                            <button
                                onClick={copyDiagramCode}
                                className="text-xs text-brand-600 dark:text-brand-400 hover:text-brand-800 dark:hover:text-white flex items-center gap-1 px-2 py-1 rounded hover:bg-brand-100 dark:hover:bg-brand-600 transition-colors"
                                title="Copy Mermaid code"
                            >
                                {copiedDiagram ? <ClipboardCheck className="w-3.5 h-3.5 text-green-600" /> : <Copy className="w-3.5 h-3.5" />}
                                {copiedDiagram ? 'Copied!' : 'Copy Code'}
                            </button>
                            <button
                                onClick={exportDiagramAsPNG}
                                className="text-xs text-brand-600 dark:text-brand-400 hover:text-brand-800 dark:hover:text-white flex items-center gap-1 px-2 py-1 rounded hover:bg-brand-100 dark:hover:bg-brand-600 transition-colors"
                                title="Export as PNG"
                            >
                                <Download className="w-3 h-3" /> PNG
                            </button>
                        </div>
                    </div>
                    <div ref={mermaidRef} className="flex justify-center items-center overflow-x-auto"></div>
                </div>

                {/* TWO-TIER OUTPUT */}
                <div className="mb-8">
                    <h3 className="font-bold text-lg mb-4 border-b-2 border-green-600 dark:border-green-500 pb-1 text-green-700 dark:text-green-400 flex items-center gap-2">
                        <CheckCircle className="w-5 h-5" />
                        Confirmed Risks ({confirmed.length})
                    </h3>
                    {confirmed.length === 0 ? (
                        <p className="text-brand-500 dark:text-brand-400 italic p-4">No confirmed risks detected.</p>
                    ) : (
                        <div className="space-y-4">
                            {confirmed.map(threat => (
                                <ThreatCard key={threat.id} threat={threat} />
                            ))}
                        </div>
                    )}
                </div>

                <div className="mb-8">
                    <h3 className="font-bold text-lg mb-4 border-b-2 border-yellow-500 dark:border-yellow-400 pb-1 text-yellow-700 dark:text-yellow-400 flex items-center gap-2">
                        <AlertTriangle className="w-5 h-5" />
                        Potential Risks ({potential.length})
                    </h3>
                    {potential.length === 0 ? (
                        <p className="text-brand-500 dark:text-brand-400 italic p-4">No potential risks detected.</p>
                    ) : (
                        <div className="space-y-4">
                            {potential.map(threat => (
                                <ThreatCard key={threat.id} threat={threat} />
                            ))}
                        </div>
                    )}
                </div>

                {hasActiveFilters && filteredThreats.length === 0 && (
                    <div className="text-center py-8">
                        <p className="text-brand-500 dark:text-brand-400">No threats match the current filters.</p>
                        <button
                            onClick={clearFilters}
                            className="mt-2 text-brand-primary hover:underline"
                        >
                            Clear filters
                        </button>
                    </div>
                )}
            </div>
        </div>
    );
};

export default ThreatDashboard;
