import { useEffect, useMemo, useRef, useState } from 'react';
import {
    Download,
    FileText,
    Filter,
    Search,
    X,
    Copy,
    ClipboardCheck,
    ShieldCheck,
    ZoomIn,
    ZoomOut,
    RotateCcw,
} from 'lucide-react';
import { generateReport } from '../utils/pdfGenerator';
import { clsx } from 'clsx';
import mermaid from 'mermaid';
import RiskMatrix from './RiskMatrix';
import StrideChart from './StrideChart';
import ArchitectureModelEditor from './dashboard/ArchitectureModelEditor';
import EvidenceRequests from './dashboard/EvidenceRequests';
import ReanalysisDiff from './dashboard/ReanalysisDiff';
import {
    AISecurityLensCard,
    DetailSection,
    EmptyInsight,
    MetricCard,
    PriorityActionCard,
    SeverityBadge,
} from './dashboard/InsightCards';
import { RiskDetailsModal, ThreatSection } from './dashboard/RiskRegister';
import { insightCardBase, reviewStateMeta, severityOrder, severityTheme } from './dashboard/theme';
import { useToast } from '../hooks/useToast';
import { loadAnnotations, saveAnnotations } from '../utils/annotations';
import html2canvas from 'html2canvas';
import AnalystWorkbench from './AnalystWorkbench';

const resizeDiagramSvg = (svgElement, zoom) => {
    if (!svgElement?.dataset.baseWidth || !svgElement?.dataset.baseHeight) return;
    svgElement.style.width = `${Number(svgElement.dataset.baseWidth) * zoom}px`;
    svgElement.style.height = `${Number(svgElement.dataset.baseHeight) * zoom}px`;
    svgElement.style.maxWidth = 'none';
    svgElement.style.maxHeight = 'none';
};

export default function ThreatDashboard({ data, projectName, onReanalyze, isAnalyzing, darkMode = false }) {
    const mermaidRef = useRef(null);
    const diagramViewportRef = useRef(null);
    const toast = useToast();
    const [copiedDiagram, setCopiedDiagram] = useState(false);
    const [reviewStates, setReviewStates] = useState({});
    const [selectedThreat, setSelectedThreat] = useState(null);
    const [diagramZoom, setDiagramZoom] = useState(1);
    const [filters, setFilters] = useState({
        severity: 'all',
        category: 'all',
        tier: 'all',
        search: '',
    });
    const [showFilters, setShowFilters] = useState(false);

    useEffect(() => {
        const renderDiagram = async () => {
            if (!data?.diagram || !mermaidRef.current) return;

            try {
                mermaid.initialize({
                    startOnLoad: false,
                    theme: darkMode ? 'dark' : 'default',
                    securityLevel: 'loose',
                    fontFamily: 'Inter, sans-serif',
                });

                mermaidRef.current.innerHTML = '';
                const diagramId = `mermaid-diagram-${Date.now()}`;
                const { svg } = await mermaid.render(diagramId, data.diagram);
                mermaidRef.current.innerHTML = svg;

                const svgElement = mermaidRef.current.querySelector('svg');
                if (svgElement) {
                    const viewBox = (svgElement.getAttribute('viewBox') || '').split(/\s+/).map(Number);
                    const viewWidth = viewBox[2] || 900;
                    const viewHeight = viewBox[3] || 560;
                    const fitScale = Math.min(1020 / viewWidth, 560 / viewHeight, 1);
                    svgElement.dataset.baseWidth = String(Math.round(viewWidth * fitScale));
                    svgElement.dataset.baseHeight = String(Math.round(viewHeight * fitScale));
                    svgElement.removeAttribute('width');
                    svgElement.removeAttribute('height');
                    resizeDiagramSvg(svgElement, 1);
                }
            } catch (error) {
                console.error('Mermaid rendering error:', error);
                mermaidRef.current.innerHTML = `
                    <div class="text-center p-8">
                        <p class="text-red-600 dark:text-red-400 font-semibold mb-2">Failed to render architecture diagram</p>
                        <p class="text-sm text-gray-600 dark:text-gray-400">${error.message}</p>
                    </div>
                `;
            }
        };

        renderDiagram();
    }, [data, darkMode]);

    useEffect(() => {
        resizeDiagramSvg(mermaidRef.current?.querySelector('svg'), diagramZoom);
    }, [diagramZoom]);

    useEffect(() => {
        // A reviewer's decision outranks the engine's default. Re-analysis
        // reports every finding as open again, and without this a finding
        // already accepted or marked a false positive would come back demanding
        // the same judgement after every edit to the model.
        const stored = loadAnnotations(projectName).reviewStates;
        const nextStates = {};
        (data?.threats || []).forEach((threat) => {
            nextStates[threat.id] = stored[threat.id] || threat.review_state || 'open';
        });
        queueMicrotask(() => setReviewStates(nextStates));
    }, [data, projectName]);

    const updateReviewState = (threatId, state) => {
        setReviewStates((prev) => {
            const next = { ...prev, [threatId]: state };
            saveAnnotations(projectName, { reviewStates: next });
            return next;
        });
    };

    const severities = ['all', ...new Set(data?.threats?.map((t) => t.severity) || [])];
    const categories = ['all', ...new Set(data?.threats?.map((t) => t.category) || [])];
    const tiers = ['all', 'Confirmed', 'Potential'];

    const filteredThreats = useMemo(() => {
        return (data?.threats || []).filter((threat) => {
            if (filters.severity !== 'all' && threat.severity !== filters.severity) return false;
            if (filters.category !== 'all' && threat.category !== filters.category) return false;
            if (filters.tier !== 'all' && threat.tier !== filters.tier) return false;
            if (
                filters.search &&
                !`${threat.title} ${threat.description}`.toLowerCase().includes(filters.search.toLowerCase())
            ) {
                return false;
            }
            return true;
        });
    }, [data, filters]);

    const sortedFilteredThreats = useMemo(() => [...filteredThreats].sort((a, b) => {
        const severityDelta = (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0);
        if (severityDelta !== 0) return severityDelta;
        return (b.risk_score || 0) - (a.risk_score || 0);
    }), [filteredThreats]);

    if (!data) return null;

    const systemModel = data.system_model || {};
    const strideCoverage = data.stride_coverage || {};
    const engineStatus = data.engine_status || {};
    const qualityGate = engineStatus.quality_gate || {};
    const publicationBlocked = qualityGate.publication_status === 'blocked' || qualityGate.status === 'blocked';
    const publicationLabel = publicationBlocked
        ? 'Draft - model integrity check failed'
        : qualityGate.publication_status === 'ready'
            ? 'Publication ready'
            : 'Technical review';
    const integrityViolations = qualityGate.integrity_violations || [];
    const completenessWarnings = qualityGate.completeness_warnings || [];
    const diagramCoverage = engineStatus.diagram_coverage;
    const assumptions = data.coverage?.assumptions || [];
    const diffSummary = data.diff_summary;
    const followUpQuestions = data.follow_up_questions || [];
    const evidenceRequests = data.evidence_requests || null;
    const aiSecurityLens = data.ai_security_lens || { enabled: false, overview: '', items: [] };
    const aiLensGridClass = aiSecurityLens.items?.length === 1
        ? 'grid-cols-1'
        : aiSecurityLens.items?.length === 2
            ? 'md:grid-cols-2'
            : 'md:grid-cols-2 xl:grid-cols-3';
    const priorityActions = data.priority_actions || [];
    // The header counted follow-up questions while the body showed evidence
    // requests as well, so the two disagreed about how much was outstanding.
    const openQuestionCount = followUpQuestions.length + (evidenceRequests?.requests?.length || 0);

    const allThreatsSorted = [...(data.threats || [])].sort((a, b) => {
        const severityDelta = (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0);
        if (severityDelta !== 0) return severityDelta;
        return (b.risk_score || 0) - (a.risk_score || 0);
    });

    const topStory = allThreatsSorted[0];
    const confirmedThreats = (data.threats || []).filter((threat) => threat.tier === 'Confirmed');
    const confirmedCount = confirmedThreats.length;
    // Counted across every finding, these read as a breakdown of the confirmed
    // total they sit under and so could exceed it. They describe the same set.
    const criticalCount = confirmedThreats.filter((t) => t.severity === 'Critical').length;
    const highCount = confirmedThreats.filter((t) => t.severity === 'High').length;
    const mitigatedThreats = Object.values(reviewStates).filter((state) => state === 'mitigated' || state === 'accepted').length;
    const remediationPercent = data.threats?.length ? Math.round((mitigatedThreats / data.threats.length) * 100) : 0;
    const reviewSummary = (data.threats || []).reduce((summary, threat) => {
        const state = reviewStates[threat.id] || 'open';
        summary[state] = (summary[state] || 0) + 1;
        return summary;
    }, { open: 0, mitigated: 0, accepted: 0, false_positive: 0 });
    const hasActiveFilters = filters.severity !== 'all' || filters.category !== 'all' || filters.tier !== 'all' || filters.search !== '';

    const handleRiskMatrixClick = (impact, likelihood) => {
        setFilters((prev) => ({
            ...prev,
            severity: impact === 'High' ? 'all' : impact,
        }));
        setShowFilters(true);
        toast.success(`Filtering by ${impact} severity x ${likelihood} likelihood`);
    };

    const changeDiagramZoom = (delta) => {
        setDiagramZoom((current) => Math.min(2.5, Math.max(0.5, Number((current + delta).toFixed(2)))));
    };

    const handleDiagramWheel = (event) => {
        event.preventDefault();
        changeDiagramZoom(event.deltaY < 0 ? 0.1 : -0.1);
    };

    const copyDiagramCode = async () => {
        if (!data?.diagram) return;
        try {
            await navigator.clipboard.writeText(data.diagram);
            setCopiedDiagram(true);
            toast.success('Diagram code copied to clipboard');
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
            toast.success('JSON file downloaded');
        } catch {
            toast.error('Failed to download JSON file');
        }
    };

    const downloadCSV = () => {
        try {
            const headers = ['ID', 'Tier', 'Severity', 'Confidence', 'Category', 'Title', 'Description', 'Mitigation'];
            const rows = data.threats.map((t) => [
                t.id,
                t.tier,
                t.severity,
                t.confidence,
                t.category,
                t.title,
                t.description,
                t.mitigation,
            ].map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(','));

            const csv = [headers.join(','), ...rows].join('\n');
            const blob = new Blob([csv], { type: 'text/csv' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${projectName.replace(/\s+/g, '_')}_threat_model.csv`;
            a.click();
            toast.success('CSV file downloaded');
        } catch {
            toast.error('Failed to download CSV file');
        }
    };

    const downloadMarkdown = () => {
        if (publicationBlocked) {
            toast.error('Final report export is blocked until quality-gate failures are resolved.');
            return;
        }
        try {
            const blob = new Blob([data.report_markdown], { type: 'text/markdown' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${projectName.replace(/\s+/g, '_')}_Threat_Report.md`;
            a.click();
            toast.success('Markdown report downloaded');
        } catch {
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
            toast.success('Diagram exported as PNG');
        } catch {
            toast.error('Failed to export diagram');
        }
    };

    const handlePDFExport = async () => {
        if (publicationBlocked) {
            toast.error('Final report export is blocked until quality-gate failures are resolved.');
            return;
        }
        try {
            await generateReport(data, projectName);
            toast.success('PDF report generated');
        } catch {
            toast.error('Failed to generate PDF report');
        }
    };

    const clearFilters = () => {
        setFilters({ severity: 'all', category: 'all', tier: 'all', search: '' });
    };

    return (
        <div className="technical-report mx-auto w-full max-w-6xl animate-fade-in-up bg-white px-2 pb-24 text-slate-900 transition-colors dark:bg-brand-900 dark:text-brand-100 sm:px-4">
            <section className={clsx(insightCardBase, 'relative overflow-hidden p-6')}>

                <div className="relative flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
                    <div className="max-w-3xl">
                        <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">Technical threat model</p>
                        <h1 className="mt-2 text-2xl font-semibold text-slate-950 dark:text-white md:text-3xl">
                            {projectName}
                        </h1>
                        <p className="mt-3 max-w-3xl text-sm leading-7 text-brand-600 dark:text-brand-300">
                            {data.summary}
                        </p>
                        <div className="mt-5 flex flex-wrap items-center gap-3 text-sm text-brand-500 dark:text-brand-400">
                            <span className={clsx('border px-2 py-1 text-xs font-semibold uppercase', publicationBlocked ? 'border-red-300 text-red-700' : 'border-emerald-300 text-emerald-700')}>
                                {publicationLabel}
                            </span>
                            <span>Generated {data.timestamp || new Date().toLocaleString()}</span>
                            <span className="h-1 w-1 rounded-full bg-brand-300 dark:bg-brand-500" />
                            <span>{data.coverage?.analysis_mode || 'standard'} mode</span>
                            <span className="h-1 w-1 rounded-full bg-brand-300 dark:bg-brand-500" />
                            <span>{data.threats?.length || 0} findings</span>
                        </div>
                    </div>

                    <div className="flex flex-wrap items-center gap-2 lg:justify-end">
                        <button
                            onClick={() => setShowFilters(!showFilters)}
                            className="ui-button-secondary"
                        >
                            <span className="inline-flex items-center gap-2">
                                <Filter className="h-4 w-4" />
                                Filters {hasActiveFilters && `(${filteredThreats.length})`}
                            </span>
                        </button>
                        <button onClick={handlePDFExport} disabled={publicationBlocked} className="btn-brand disabled:cursor-not-allowed disabled:opacity-45" title={publicationBlocked ? 'Resolve quality-gate failures before final export' : 'Export final PDF'}>
                            <span className="inline-flex items-center gap-2"><Download className="h-4 w-4" /> Export PDF</span>
                        </button>
                        <details className="relative">
                            <summary className="ui-button-secondary cursor-pointer marker:content-none">
                                <span className="inline-flex items-center gap-2"><FileText className="h-4 w-4" /> Other formats</span>
                            </summary>
                            <div className="absolute right-0 z-20 mt-2 flex w-44 flex-col gap-1 rounded-md border border-slate-200 bg-white p-2 shadow-lg dark:border-brand-700 dark:bg-brand-800">
                                <button onClick={downloadJSON} className="rounded px-3 py-2 text-left text-sm text-brand-700 hover:bg-brand-50 dark:text-brand-200 dark:hover:bg-brand-700">JSON</button>
                                <button onClick={downloadCSV} className="rounded px-3 py-2 text-left text-sm text-brand-700 hover:bg-brand-50 dark:text-brand-200 dark:hover:bg-brand-700">CSV</button>
                                {data.report_markdown && (
                                    <button onClick={downloadMarkdown} disabled={publicationBlocked} className="rounded px-3 py-2 text-left text-sm text-brand-700 hover:bg-brand-50 disabled:cursor-not-allowed disabled:opacity-45 dark:text-brand-200 dark:hover:bg-brand-700">Markdown</button>
                                )}
                            </div>
                        </details>
                    </div>
                </div>

                <div className="relative mt-8 grid gap-4 md:grid-cols-3">
                    <MetricCard label="Security score" value={`${data.score}/100`} tone={data.score < 40 ? 'danger' : data.score < 70 ? 'warning' : 'success'} detail={data.score < 40 ? 'Immediate response recommended' : data.score < 70 ? 'Address top findings next' : 'Strong baseline with focused follow-up'} />
                    <MetricCard label="Confirmed risks" value={confirmedCount} tone={criticalCount > 0 ? 'danger' : 'accent'} detail={`${criticalCount} critical, ${highCount} high`} />
                    <MetricCard label="Open questions" value={openQuestionCount} tone="warning" detail={openQuestionCount ? 'Answering these sharpens the model' : 'Architecture detail looks well covered'} />
                </div>
            </section>

            {showFilters && (
                <section className={clsx(insightCardBase, 'mt-6 p-5')}>
                    <div className="flex items-center justify-between gap-4">
                        <div>
                            <h3 className="text-lg font-bold text-brand-950 dark:text-white">Filter findings</h3>
                            <p className="mt-1 text-sm text-brand-600 dark:text-brand-400">Narrow the list below by severity, category, tier, or wording.</p>
                        </div>
                        {hasActiveFilters && (
                            <button onClick={clearFilters} className="inline-flex items-center gap-1 text-sm font-semibold text-brand-600 hover:text-brand-800 dark:text-brand-400 dark:hover:text-white">
                                <X className="h-4 w-4" />
                                Clear all
                            </button>
                        )}
                    </div>
                    <div className="mt-5 grid gap-4 md:grid-cols-4">
                        <div>
                            <label className="mb-1.5 block text-sm font-medium text-brand-700 dark:text-brand-300">Search</label>
                            <div className="relative">
                                <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-brand-400" />
                                <input
                                    type="text"
                                    value={filters.search}
                                    onChange={(e) => setFilters({ ...filters, search: e.target.value })}
                                    placeholder="Search findings..."
                                    className="input-brand w-full pl-9 text-sm"
                                />
                            </div>
                        </div>
                        <div>
                            <label className="mb-1.5 block text-sm font-medium text-brand-700 dark:text-brand-300">Severity</label>
                            <select value={filters.severity} onChange={(e) => setFilters({ ...filters, severity: e.target.value })} className="input-brand w-full text-sm">
                                {severities.map((s) => <option key={s} value={s}>{s === 'all' ? 'All severities' : s}</option>)}
                            </select>
                        </div>
                        <div>
                            <label className="mb-1.5 block text-sm font-medium text-brand-700 dark:text-brand-300">Category</label>
                            <select value={filters.category} onChange={(e) => setFilters({ ...filters, category: e.target.value })} className="input-brand w-full text-sm">
                                {categories.map((c) => <option key={c} value={c}>{c === 'all' ? 'All categories' : c}</option>)}
                            </select>
                        </div>
                        <div>
                            <label className="mb-1.5 block text-sm font-medium text-brand-700 dark:text-brand-300">Tier</label>
                            <select value={filters.tier} onChange={(e) => setFilters({ ...filters, tier: e.target.value })} className="input-brand w-full text-sm">
                                {tiers.map((t) => <option key={t} value={t}>{t === 'all' ? 'All tiers' : t}</option>)}
                            </select>
                        </div>
                    </div>
                </section>
            )}

            {(publicationBlocked || integrityViolations.length > 0) && (
                <div className="mt-6 border-l-4 border-red-600 bg-white px-4 py-3 text-sm text-slate-700 dark:bg-red-950/20 dark:text-red-200">
                    <p className="font-semibold text-red-700 dark:text-red-300">This report contradicts itself and cannot be published as final.</p>
                    <ul className="mt-1 list-disc space-y-0.5 pl-5">
                        {integrityViolations.map((violation) => (
                            <li key={violation.check}>{violation.detail} ({violation.count})</li>
                        ))}
                    </ul>
                </div>
            )}

            {!publicationBlocked && completenessWarnings.length > 0 && (
                <div className="mt-6 border-l-4 border-amber-500 bg-white px-4 py-3 text-sm text-slate-700 dark:bg-amber-950/20 dark:text-amber-200">
                    <p className="font-semibold text-amber-700 dark:text-amber-300">The findings stand; these gaps need a reviewer's eye before sign-off.</p>
                    <ul className="mt-1 list-disc space-y-0.5 pl-5">
                        {completenessWarnings.map((warning) => (
                            <li key={warning.check}>{warning.detail} ({warning.count})</li>
                        ))}
                    </ul>
                </div>
            )}

            <section className="mt-6">
                <div className={clsx(insightCardBase, 'p-6')}>
                    <h2 className="text-lg font-bold text-brand-950 dark:text-white">What to fix first</h2>
                    <p className="mt-1 text-sm text-brand-600 dark:text-brand-400">
                        Ordered by severity, evidence, and how much of the system each issue exposes.
                    </p>

                    {topStory ? (
                        <div className={clsx('mt-5 rounded-lg border p-5', severityTheme[topStory.severity]?.surface, severityTheme[topStory.severity]?.border)}>
                            <div className="flex flex-wrap items-center gap-3">
                                <SeverityBadge severity={topStory.severity} />
                                <span className="text-sm font-semibold text-brand-700 dark:text-brand-300">{topStory.tier}</span>
                            </div>
                            <h3 className="mt-4 text-xl font-bold tracking-tight text-brand-950 dark:text-white">{topStory.title}</h3>
                            <p className="mt-3 text-sm leading-7 text-brand-700 dark:text-brand-300">
                                {topStory.explanation?.why_flagged || topStory.description}
                            </p>
                        </div>
                    ) : (
                        <EmptyInsight
                            icon={ShieldCheck}
                            title="No immediate threats detected"
                            description="This run did not surface any findings. Add more architecture detail if you want a deeper assessment."
                        />
                    )}

                    {priorityActions.length > 0 && (
                        <div className="mt-5 space-y-4">
                            {priorityActions.slice(0, 3).map((action, index) => (
                                <PriorityActionCard key={`${action.title}-${index}`} action={action} index={index} />
                            ))}
                        </div>
                    )}
                </div>
            </section>

            <section className="mt-6">
                <div className={clsx(insightCardBase, 'mx-auto w-full max-w-6xl p-6')}>
                    <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                        <div className="text-center lg:text-left">
                            <h3 className="text-lg font-bold text-brand-950 dark:text-white">Architecture view</h3>
                            <p className="mt-1 text-sm text-brand-600 dark:text-brand-400">Trust boundaries and boundary-crossing flows are highlighted directly on the modeled system map.</p>
                        </div>
                        <div className="flex items-center justify-center gap-2">
                            <div className="flex items-center rounded-md border border-brand-200 bg-white dark:border-brand-700 dark:bg-brand-800">
                                <button
                                    type="button"
                                    onClick={() => changeDiagramZoom(-0.1)}
                                    disabled={diagramZoom <= 0.5}
                                    className="inline-flex h-9 w-9 items-center justify-center text-brand-600 hover:text-brand-primary disabled:cursor-not-allowed disabled:opacity-35 dark:text-brand-300"
                                    aria-label="Zoom out architecture diagram"
                                    title="Zoom out"
                                >
                                    <ZoomOut className="h-4 w-4" />
                                </button>
                                <span className="w-12 text-center text-xs font-semibold text-brand-600 dark:text-brand-300">{Math.round(diagramZoom * 100)}%</span>
                                <button
                                    type="button"
                                    onClick={() => changeDiagramZoom(0.1)}
                                    disabled={diagramZoom >= 2.5}
                                    className="inline-flex h-9 w-9 items-center justify-center text-brand-600 hover:text-brand-primary disabled:cursor-not-allowed disabled:opacity-35 dark:text-brand-300"
                                    aria-label="Zoom in architecture diagram"
                                    title="Zoom in"
                                >
                                    <ZoomIn className="h-4 w-4" />
                                </button>
                                <button
                                    type="button"
                                    onClick={() => setDiagramZoom(1)}
                                    className="inline-flex h-9 w-9 items-center justify-center border-l border-brand-200 text-brand-600 hover:text-brand-primary dark:border-brand-700 dark:text-brand-300"
                                    aria-label="Reset architecture diagram zoom"
                                    title="Reset zoom"
                                >
                                    <RotateCcw className="h-4 w-4" />
                                </button>
                            </div>
                            <button
                                onClick={copyDiagramCode}
                                className="ui-button-secondary px-3 py-2 text-xs"
                            >
                                <span className="inline-flex items-center gap-1.5">
                                    {copiedDiagram ? <ClipboardCheck className="h-3.5 w-3.5 text-green-600" /> : <Copy className="h-3.5 w-3.5" />}
                                    {copiedDiagram ? 'Copied' : 'Code'}
                                </span>
                            </button>
                            <button
                                onClick={exportDiagramAsPNG}
                                className="ui-button-secondary px-3 py-2 text-xs"
                            >
                                <span className="inline-flex items-center gap-1.5"><Download className="h-3.5 w-3.5" /> PNG</span>
                            </button>
                        </div>
                    </div>
                    <div
                        ref={diagramViewportRef}
                        onWheel={handleDiagramWheel}
                        className="architecture-diagram mt-5 flex min-h-[320px] w-full items-center justify-center overflow-auto rounded-md border border-slate-200 bg-white p-4 dark:border-brand-700 dark:bg-brand-900/55 sm:min-h-[400px] sm:p-6"
                        aria-label="Architecture diagram. Use the mouse wheel or zoom controls to change scale."
                    >
                        <div ref={mermaidRef} className="flex h-full min-w-full w-max shrink-0 items-center justify-center" />
                    </div>
                </div>

                {diagramCoverage && (
                    <p className="mt-3 text-xs text-slate-500 dark:text-slate-400">
                        {diagramCoverage.components_drawn} of {diagramCoverage.components_in_model} components and{' '}
                        {diagramCoverage.flows_drawn} of {diagramCoverage.flows_in_model} data flows are drawn.
                        {diagramCoverage.components_hidden_for_readability > 0 &&
                            ` ${diagramCoverage.components_hidden_for_readability} components are summarised for readability.`}
                        {diagramCoverage.components_excluded_as_non_flow > 0 &&
                            ` ${diagramCoverage.components_excluded_as_non_flow} components take no part in a data flow.`}
                        {' '}A dotted flow was assumed from component types rather than described; a bold red
                        outline marks a component with a confirmed finding.
                    </p>
                )}

            </section>

            <section className="mt-8">
                <ThreatSection threats={sortedFilteredThreats} onSelectThreat={setSelectedThreat} />
            </section>

            <section className="mt-8 space-y-4">
                <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">Supporting detail</h2>

                {(evidenceRequests || followUpQuestions.length > 0) && (
                    <DetailSection
                        title="Open questions for the team"
                        summary={openQuestionCount ? `${openQuestionCount} answers would sharpen this model` : undefined}
                    >
                        <EvidenceRequests evidenceRequests={evidenceRequests} cardClassName="" />
                        {followUpQuestions.length > 0 && (
                            <div className="mt-4 space-y-3">
                                {followUpQuestions.slice(0, 4).map((item) => (
                                    <div key={item.id} className="rounded-lg border border-brand-200 bg-brand-50 p-4 dark:border-brand-700 dark:bg-brand-900/35">
                                        <div className="flex items-center gap-2">
                                            <span className={clsx(
                                                'rounded-full px-2 py-1 text-[10px] font-bold uppercase',
                                                item.priority === 'high'
                                                    ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300'
                                                    : 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300'
                                            )}>
                                                {item.priority}
                                            </span>
                                            {item.related_threat_count > 0 && (
                                                <span className="text-xs text-brand-500 dark:text-brand-400">{item.related_threat_count} linked findings</span>
                                            )}
                                        </div>
                                        <p className="mt-3 text-sm font-semibold text-brand-950 dark:text-white">{item.question}</p>
                                        <p className="mt-2 text-sm leading-6 text-brand-600 dark:text-brand-400">{item.rationale}</p>
                                    </div>
                                ))}
                            </div>
                        )}
                    </DetailSection>
                )}

                <DetailSection title="Risk distribution" summary="Where severity and STRIDE categories concentrate">
                    <div className="grid gap-6 lg:grid-cols-2">
                        <RiskMatrix threats={data.threats} onCellClick={handleRiskMatrixClick} />
                        <StrideChart threats={data.threats || []} />
                    </div>
                </DetailSection>

                <DetailSection
                    title="What was modeled and assessed"
                    summary={`${data.coverage?.components_analyzed ?? 0} components, ${strideCoverage.assessment_percent ?? 100}% STRIDE assessed`}
                >
                    <div className="grid grid-cols-2 gap-4 text-sm md:grid-cols-3">
                        {[
                            ['Components', data.coverage?.components_analyzed ?? 0],
                            ['Data flows', data.coverage?.flows_analyzed ?? 0],
                            // The key here was trust_boundary_count, which the backend
                            // never emitted, so this read zero while the diagram drew
                            // the boundaries it had found.
                            ['Trust boundaries', data.coverage?.trust_boundaries_modeled ?? 0],
                            ['Public entry points', systemModel.public_entry_points?.length ?? 0],
                            ['Boundary crossings', systemModel.boundary_crossings?.length ?? 0],
                            ['Cloud resources', systemModel.cloud_resources?.length ?? 0],
                        ].map(([label, value]) => (
                            <div key={label} className="rounded-lg border border-brand-200 px-4 py-3 dark:border-brand-700">
                                <p className="text-xs text-brand-500 dark:text-brand-400">{label}</p>
                                <p className="mt-1 text-2xl font-black text-brand-950 dark:text-white">{value}</p>
                            </div>
                        ))}
                    </div>
                    <p className="mt-5 text-sm text-brand-600 dark:text-brand-400">
                        Every modeled element is assessed against all six STRIDE categories.
                        {' '}{strideCoverage.unknown_cells ?? 0} cells are unresolved for lack of architecture evidence.
                    </p>
                    <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                        {(strideCoverage.categories || []).map((category) => {
                            const summary = strideCoverage.category_summary?.[category] || {};
                            return (
                                <div key={category} className="border-b border-brand-200 pb-3 dark:border-brand-700">
                                    <p className="text-sm font-semibold text-brand-950 dark:text-white">{category}</p>
                                    <p className="mt-1 text-xs leading-5 text-brand-500 dark:text-brand-400">
                                        {summary.finding || 0} findings · {summary.control_present || 0} controlled · {summary.unknown || 0} unknown
                                    </p>
                                </div>
                            );
                        })}
                    </div>
                </DetailSection>

                {aiSecurityLens.items?.length > 0 && (
                    <DetailSection title="AI-specific risk" summary={aiSecurityLens.overview || undefined}>
                        <div className={clsx('grid gap-4', aiLensGridClass)}>
                            {aiSecurityLens.items.map((item) => (
                                <AISecurityLensCard key={item.id} item={item} />
                            ))}
                        </div>
                    </DetailSection>
                )}

                <DetailSection
                    title="Review progress and changes"
                    summary={`${mitigatedThreats} of ${data.threats?.length || 0} findings triaged (${remediationPercent}%)`}
                >
                    <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
                        {Object.entries(reviewStateMeta).map(([state, meta]) => (
                            <div key={state} className="rounded-lg border border-brand-200 px-4 py-3 dark:border-brand-700">
                                <div className={clsx('inline-flex rounded-full px-2 py-1 text-[10px] font-semibold', meta.className)}>{meta.label}</div>
                                <div className="mt-2 text-2xl font-black text-brand-950 dark:text-white">{reviewSummary[state] || 0}</div>
                            </div>
                        ))}
                    </div>
                    <div className="mt-5">
                        <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-brand-500 dark:text-brand-400">Since the last run</p>
                        <ReanalysisDiff diff={diffSummary} />
                    </div>
                </DetailSection>

                {assumptions.length > 0 && (
                    <DetailSection title="Assumptions still shaping the model" summary={`${assumptions.length} assumption${assumptions.length === 1 ? '' : 's'} in force`}>
                        <div className="grid gap-3 md:grid-cols-2">
                            {assumptions.slice(0, 4).map((assumption, index) => (
                                <div key={`${assumption.scope}-${index}`} className="rounded-lg border border-yellow-200 bg-yellow-50 px-4 py-3 dark:border-yellow-900/40 dark:bg-yellow-950/20">
                                    <p className="text-sm leading-6 text-yellow-900 dark:text-yellow-300">{assumption.message}</p>
                                </div>
                            ))}
                        </div>
                    </DetailSection>
                )}
            </section>

            <AnalystWorkbench
                data={data}
                projectName={projectName}
                reviewStates={reviewStates}
            />

            {onReanalyze && (
                <section className="mt-8">
                    <ArchitectureModelEditor
                        document={data.architecture_document}
                        onReanalyze={onReanalyze}
                        isAnalyzing={isAnalyzing}
                    />
                </section>
            )}
            <RiskDetailsModal
                threat={selectedThreat}
                reviewState={selectedThreat ? reviewStates[selectedThreat.id] || 'open' : 'open'}
                onReviewStateChange={updateReviewState}
                onClose={() => setSelectedThreat(null)}
            />
        </div>
    );
}
