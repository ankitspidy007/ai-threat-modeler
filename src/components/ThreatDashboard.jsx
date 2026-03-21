import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
    ShieldAlert,
    AlertTriangle,
    Download,
    FileText,
    Share2,
    Code,
    Filter,
    Search,
    X,
    Copy,
    ClipboardCheck,
    HelpCircle,
    ListChecks,
    TrendingUp,
    Sparkles,
    ShieldCheck,
    ArrowUpRight,
} from 'lucide-react';
import { generateReport } from '../utils/pdfGenerator';
import { clsx } from 'clsx';
import mermaid from 'mermaid';
import RiskMatrix from './RiskMatrix';
import StrideChart from './StrideChart';
import { useToast } from './Toast';
import html2canvas from 'html2canvas';
import AnalystWorkbench from './AnalystWorkbench';

const severityOrder = { Critical: 4, High: 3, Medium: 2, Low: 1 };

const severityTheme = {
    Critical: {
        badge: 'bg-red-50 text-red-700 border-red-400 dark:bg-red-900/30 dark:text-red-300',
        accent: 'from-red-500 to-rose-500',
        border: 'border-red-200 dark:border-red-900/50',
        surface: 'bg-red-50/80 dark:bg-red-950/20',
        label: 'Critical exposure',
    },
    High: {
        badge: 'bg-orange-50 text-orange-700 border-orange-400 dark:bg-orange-900/30 dark:text-orange-300',
        accent: 'from-orange-500 to-amber-500',
        border: 'border-orange-200 dark:border-orange-900/50',
        surface: 'bg-orange-50/80 dark:bg-orange-950/20',
        label: 'High priority',
    },
    Medium: {
        badge: 'bg-yellow-50 text-yellow-700 border-yellow-400 dark:bg-yellow-900/30 dark:text-yellow-300',
        accent: 'from-yellow-400 to-amber-400',
        border: 'border-yellow-200 dark:border-yellow-900/50',
        surface: 'bg-yellow-50/80 dark:bg-yellow-950/20',
        label: 'Needs planning',
    },
    Low: {
        badge: 'bg-sky-50 text-sky-700 border-sky-400 dark:bg-sky-900/30 dark:text-sky-300',
        accent: 'from-sky-400 to-cyan-400',
        border: 'border-sky-200 dark:border-sky-900/50',
        surface: 'bg-sky-50/80 dark:bg-sky-950/20',
        label: 'Monitor',
    },
};

const reviewStateMeta = {
    open: {
        label: 'Open',
        className: 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300',
    },
    mitigated: {
        label: 'Mitigated',
        className: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300',
    },
    accepted: {
        label: 'Accepted',
        className: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
    },
    false_positive: {
        label: 'False Positive',
        className: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300',
    },
};

const insightCardBase = 'rounded-[28px] border shadow-[0_24px_70px_-40px_rgba(15,23,42,0.28)]';

const SeverityBadge = ({ severity }) => {
    const theme = severityTheme[severity] || severityTheme.Low;
    return (
        <span className={clsx('inline-flex items-center rounded-full border px-2.5 py-1 text-[11px] font-bold uppercase tracking-[0.18em]', theme.badge)}>
            {severity}
        </span>
    );
};

const EmptyInsight = ({ icon: Icon, title, description }) => (
    <div className="rounded-[24px] border border-dashed border-brand-200 bg-white/55 px-5 py-8 text-center shadow-[0_20px_50px_-42px_rgba(15,23,42,0.32)] dark:border-brand-700 dark:bg-brand-900/20">
        <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-2xl bg-brand-100 text-brand-600 dark:bg-brand-800 dark:text-brand-300">
            <Icon className="h-5 w-5" />
        </div>
        <h4 className="text-base font-semibold text-brand-900 dark:text-white">{title}</h4>
        <p className="mt-2 text-sm leading-6 text-brand-600 dark:text-brand-400">{description}</p>
    </div>
);

const MetricCard = ({ label, value, tone = 'default', detail }) => {
    const toneMap = {
        default: 'from-white to-brand-50/80 dark:from-brand-800 dark:to-brand-800/70',
        danger: 'from-red-50 to-rose-50 dark:from-red-950/20 dark:to-rose-950/10',
        warning: 'from-amber-50 to-yellow-50 dark:from-amber-950/20 dark:to-yellow-950/10',
        success: 'from-emerald-50 to-green-50 dark:from-emerald-950/20 dark:to-green-950/10',
        accent: 'from-brand-50 to-sky-50 dark:from-brand-900/40 dark:to-sky-950/10',
    };

    return (
        <div className={clsx('rounded-[24px] border border-white/70 bg-gradient-to-br p-5 shadow-[0_18px_45px_-34px_rgba(15,23,42,0.28)] dark:border-brand-700/60', toneMap[tone] || toneMap.default)}>
            <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-brand-500 dark:text-brand-400">{label}</p>
            <div className="mt-3 flex items-end justify-between gap-3">
                <div className="text-3xl font-black tracking-tight text-brand-950 dark:text-white">{value}</div>
                {detail && <div className="max-w-[8rem] text-right text-xs leading-5 text-brand-500 dark:text-brand-400">{detail}</div>}
            </div>
        </div>
    );
};

const ThreatCard = ({ threat, reviewState = 'open', onReviewStateChange }) => {
    const theme = severityTheme[threat.severity] || severityTheme.Low;
    const evidencePreview = threat.explanation?.evidence_summary?.length
        ? threat.explanation.evidence_summary
        : (threat.evidence || []).slice(0, 2);

    return (
        <article className={clsx('relative overflow-hidden rounded-[30px] border bg-white/82 p-6 shadow-[0_28px_80px_-42px_rgba(15,23,42,0.34)] backdrop-blur-xl transition-all duration-200 hover:-translate-y-0.5 dark:bg-brand-800/72', theme.border)}>
            <div className={clsx('absolute inset-x-0 top-0 h-1.5 bg-gradient-to-r', theme.accent)} />

            <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
                <div className="max-w-3xl">
                    <div className="flex flex-wrap items-center gap-2">
                        <SeverityBadge severity={threat.severity} />
                        <span className={clsx(
                            'inline-flex items-center rounded-full px-2.5 py-1 text-[11px] font-bold uppercase tracking-[0.14em]',
                            threat.tier === 'Confirmed'
                                ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300'
                                : 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300'
                        )}>
                            {threat.tier}
                        </span>
                        <span className="text-xs font-medium text-brand-500 dark:text-brand-400">Confidence {threat.confidence}</span>
                        <span className={clsx('rounded-full px-2.5 py-1 text-[11px] font-semibold', reviewStateMeta[reviewState]?.className || reviewStateMeta.open.className)}>
                            {reviewStateMeta[reviewState]?.label || 'Open'}
                        </span>
                    </div>

                    <h4 className="mt-4 text-xl font-bold tracking-tight text-brand-950 dark:text-white">{threat.title}</h4>
                    <p className="mt-2 text-sm font-medium text-brand-500 dark:text-brand-400">
                        {threat.category}
                        {threat.stride_category && threat.stride_category !== threat.category && ` -> ${threat.stride_category}`}
                    </p>
                    <p className="mt-4 max-w-3xl text-[15px] leading-7 text-brand-700 dark:text-brand-300">{threat.description}</p>
                </div>

                <div className={clsx('min-w-[220px] rounded-[24px] border p-4', theme.surface, theme.border)}>
                    <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-brand-500 dark:text-brand-400">Narrative</p>
                    <p className="mt-3 text-sm leading-6 text-brand-700 dark:text-brand-300">
                        {threat.explanation?.why_flagged || 'This finding was raised from the current architecture signals and rule matches.'}
                    </p>
                    {threat.explanation?.remediation_priority && (
                        <div className="mt-4 flex items-center gap-2 text-sm font-semibold text-brand-900 dark:text-white">
                            <ArrowUpRight className="h-4 w-4 text-brand-primary" />
                            {threat.explanation.remediation_priority}
                        </div>
                    )}
                </div>
            </div>

            <div className="mt-5 grid gap-4 lg:grid-cols-[1.3fr_0.9fr]">
                <div className="rounded-[24px] border border-brand-100 bg-brand-50/75 p-4 dark:border-brand-700 dark:bg-brand-900/25">
                    <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-brand-500 dark:text-brand-400">Signals</p>
                    <div className="mt-3 grid gap-3 md:grid-cols-2">
                        <div>
                            <p className="text-xs font-semibold text-brand-600 dark:text-brand-400">Evidence highlights</p>
                            {evidencePreview.length > 0 ? (
                                <ul className="mt-2 space-y-2 text-sm leading-6 text-brand-700 dark:text-brand-300">
                                    {evidencePreview.map((ev, i) => (
                                        <li key={i} className="rounded-2xl bg-white/80 px-3 py-2 dark:bg-brand-800/60">{ev}</li>
                                    ))}
                                </ul>
                            ) : (
                                <p className="mt-2 text-sm text-brand-500 dark:text-brand-400">No explicit evidence captured for this finding.</p>
                            )}
                        </div>
                        <div className="space-y-3">
                            <div>
                                <p className="text-xs font-semibold text-brand-600 dark:text-brand-400">Impacted components</p>
                                <p className="mt-2 text-sm leading-6 text-brand-700 dark:text-brand-300">
                                    {threat.explanation?.impacted_components?.length
                                        ? threat.explanation.impacted_components.join(', ')
                                        : threat.affected_components?.join(', ') || 'Not specified'}
                                </p>
                            </div>
                            <div>
                                <p className="text-xs font-semibold text-brand-600 dark:text-brand-400">Data flows</p>
                                <p className="mt-2 text-sm leading-6 text-brand-700 dark:text-brand-300">
                                    {threat.affected_data_flows?.length ? threat.affected_data_flows.join(', ') : 'No flow-specific impact noted'}
                                </p>
                            </div>
                        </div>
                    </div>
                </div>

                <div className="rounded-[24px] border border-emerald-100 bg-emerald-50/80 p-4 dark:border-emerald-900/40 dark:bg-emerald-950/20">
                    <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-emerald-600 dark:text-emerald-400">Recommended next move</p>
                    <p className="mt-3 text-sm leading-6 text-emerald-900 dark:text-emerald-300">{threat.mitigation}</p>
                    <div className="mt-4 flex flex-wrap gap-2">
                        {Object.entries(reviewStateMeta).map(([state, meta]) => (
                            <button
                                key={state}
                                onClick={() => onReviewStateChange?.(threat.id, state)}
                                className={clsx(
                                    'rounded-full px-3 py-1.5 text-[11px] font-semibold transition-colors',
                                    reviewState === state
                                        ? meta.className
                                        : 'bg-white text-brand-600 hover:bg-brand-100 dark:bg-brand-800 dark:text-brand-300 dark:hover:bg-brand-700'
                                )}
                            >
                                {meta.label}
                            </button>
                        ))}
                    </div>
                </div>
            </div>
        </article>
    );
};

const ThreatSection = ({ title, description, icon: Icon, threats, emptyTitle, emptyDescription, reviewStates, onReviewStateChange }) => (
    <section className="space-y-5">
        <div className="flex items-end justify-between gap-4 border-b border-brand-200/80 pb-4 dark:border-brand-700/80">
            <div>
                <div className="flex items-center gap-2 text-brand-primary">
                    <Icon className="h-5 w-5" />
                    <h3 className="text-xl font-bold tracking-tight text-brand-950 dark:text-white">{title}</h3>
                </div>
                <p className="mt-2 text-sm leading-6 text-brand-600 dark:text-brand-400">{description}</p>
            </div>
            <div className="rounded-full bg-brand-100 px-3 py-1 text-sm font-semibold text-brand-700 dark:bg-brand-700 dark:text-brand-200">
                {threats.length}
            </div>
        </div>

        {threats.length === 0 ? (
            <EmptyInsight icon={Icon} title={emptyTitle} description={emptyDescription} />
        ) : (
            <div className="space-y-5">
                {threats.map((threat) => (
                    <ThreatCard
                        key={threat.id}
                        threat={threat}
                        reviewState={reviewStates[threat.id] || 'open'}
                        onReviewStateChange={onReviewStateChange}
                    />
                ))}
            </div>
        )}
    </section>
);

export default function ThreatDashboard({ data, projectName }) {
    const mermaidRef = useRef(null);
    const toast = useToast();
    const [copiedDiagram, setCopiedDiagram] = useState(false);
    const [reviewStates, setReviewStates] = useState({});
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
                const isDark = document.documentElement.classList.contains('dark');
                mermaid.initialize({
                    startOnLoad: false,
                    theme: isDark ? 'dark' : 'default',
                    securityLevel: 'loose',
                    fontFamily: 'Inter, sans-serif',
                });

                mermaidRef.current.innerHTML = '';
                const diagramId = `mermaid-diagram-${Date.now()}`;
                const { svg } = await mermaid.render(diagramId, data.diagram);
                mermaidRef.current.innerHTML = svg;
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
    }, [data]);

    useEffect(() => {
        const nextStates = {};
        (data?.threats || []).forEach((threat) => {
            nextStates[threat.id] = threat.review_state || 'open';
        });
        setReviewStates(nextStates);
    }, [data]);

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

    if (!data) return null;

    const confirmed = filteredThreats.filter((t) => t.tier === 'Confirmed');
    const potential = filteredThreats.filter((t) => t.tier === 'Potential');
    const assumptions = data.coverage?.assumptions || [];
    const diffSummary = data.diff_summary;
    const followUpQuestions = data.follow_up_questions || [];

    const allThreatsSorted = [...(data.threats || [])].sort((a, b) => {
        const severityDelta = (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0);
        if (severityDelta !== 0) return severityDelta;
        return (b.risk_score || 0) - (a.risk_score || 0);
    });

    const topStory = allThreatsSorted[0];
    const criticalCount = (data.threats || []).filter((t) => t.severity === 'Critical').length;
    const highCount = (data.threats || []).filter((t) => t.severity === 'High').length;
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

    const handlePDFExport = () => {
        try {
            generateReport(data, projectName);
            toast.success('PDF report generated');
        } catch {
            toast.error('Failed to generate PDF report');
        }
    };

    const clearFilters = () => {
        setFilters({ severity: 'all', category: 'all', tier: 'all', search: '' });
    };

    const updateReviewState = (threatId, state) => {
        setReviewStates((prev) => ({ ...prev, [threatId]: state }));
    };

    return (
        <div className="mx-auto w-full max-w-[1180px] animate-fade-in-up pb-24">
            <section className={clsx(insightCardBase, 'relative overflow-hidden bg-white/82 p-8 backdrop-blur-xl dark:bg-brand-800/72')}>
                <div className="absolute inset-x-0 top-0 h-1.5 bg-gradient-to-r from-brand-primary via-sky-400 to-emerald-400" />
                <div className="absolute right-0 top-0 h-44 w-44 rounded-full bg-brand-primary/10 blur-3xl dark:bg-brand-primary/20" />

                <div className="relative flex flex-col gap-8 lg:flex-row lg:items-end lg:justify-between">
                    <div className="max-w-3xl">
                        <div className="inline-flex items-center gap-2 rounded-full bg-brand-100 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.22em] text-brand-700 dark:bg-brand-700/60 dark:text-brand-200">
                            <Sparkles className="h-3.5 w-3.5" />
                            Security narrative
                        </div>
                        <h1 className="mt-5 text-4xl font-black tracking-tight text-brand-950 dark:text-white md:text-5xl">
                            {projectName}
                        </h1>
                        <p className="mt-4 max-w-2xl text-base leading-8 text-brand-600 dark:text-brand-300">
                            {data.summary}
                        </p>
                        <div className="mt-5 flex flex-wrap items-center gap-3 text-sm text-brand-500 dark:text-brand-400">
                            <span>Generated {data.timestamp || new Date().toLocaleString()}</span>
                            <span className="h-1 w-1 rounded-full bg-brand-300 dark:bg-brand-500" />
                            <span>{data.coverage?.analysis_mode || 'standard'} mode</span>
                            <span className="h-1 w-1 rounded-full bg-brand-300 dark:bg-brand-500" />
                            <span>{data.threats?.length || 0} findings</span>
                        </div>
                    </div>

                    <div className="flex flex-wrap gap-2 lg:justify-end">
                        <button
                            onClick={() => setShowFilters(!showFilters)}
                            className="rounded-xl border border-brand-200 bg-white/90 px-4 py-2 text-sm font-semibold text-brand-700 shadow-sm transition-colors hover:bg-brand-50 dark:border-brand-700 dark:bg-brand-800 dark:text-brand-200 dark:hover:bg-brand-700"
                        >
                            <span className="inline-flex items-center gap-2">
                                <Filter className="h-4 w-4" />
                                Filters {hasActiveFilters && `(${filteredThreats.length})`}
                            </span>
                        </button>
                        <button onClick={downloadJSON} className="rounded-xl border border-brand-200 bg-white/90 px-4 py-2 text-sm font-semibold text-brand-700 shadow-sm transition-colors hover:bg-brand-50 dark:border-brand-700 dark:bg-brand-800 dark:text-brand-200 dark:hover:bg-brand-700">
                            <span className="inline-flex items-center gap-2"><Code className="h-4 w-4" /> JSON</span>
                        </button>
                        <button onClick={downloadCSV} className="rounded-xl border border-brand-200 bg-white/90 px-4 py-2 text-sm font-semibold text-brand-700 shadow-sm transition-colors hover:bg-brand-50 dark:border-brand-700 dark:bg-brand-800 dark:text-brand-200 dark:hover:bg-brand-700">
                            <span className="inline-flex items-center gap-2"><Share2 className="h-4 w-4" /> CSV</span>
                        </button>
                        {data.report_markdown && (
                            <button onClick={downloadMarkdown} className="rounded-xl border border-brand-200 bg-white/90 px-4 py-2 text-sm font-semibold text-brand-700 shadow-sm transition-colors hover:bg-brand-50 dark:border-brand-700 dark:bg-brand-800 dark:text-brand-200 dark:hover:bg-brand-700">
                                <span className="inline-flex items-center gap-2"><FileText className="h-4 w-4" /> Markdown</span>
                            </button>
                        )}
                        <button onClick={handlePDFExport} className="rounded-xl bg-brand-primary px-4 py-2 text-sm font-semibold text-white shadow-[0_18px_40px_-24px_rgba(79,70,229,0.8)] transition-all hover:-translate-y-0.5 hover:bg-brand-primary/90">
                            <span className="inline-flex items-center gap-2"><Download className="h-4 w-4" /> Export PDF</span>
                        </button>
                    </div>
                </div>

                <div className="relative mt-8 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                    <MetricCard label="Security score" value={`${data.score}/100`} tone={data.score < 40 ? 'danger' : data.score < 70 ? 'warning' : 'success'} detail={data.score < 40 ? 'Immediate response recommended' : data.score < 70 ? 'Address top findings next' : 'Strong baseline with focused follow-up'} />
                    <MetricCard label="Confirmed risks" value={confirmed.length} tone={criticalCount > 0 ? 'danger' : 'accent'} detail={`${criticalCount} critical, ${highCount} high`} />
                    <MetricCard label="Review progress" value={`${remediationPercent}%`} tone="success" detail={`${mitigatedThreats}/${data.threats?.length || 0} findings triaged`} />
                    <MetricCard label="Questions for team" value={followUpQuestions.length} tone="warning" detail={followUpQuestions.length ? 'Answer these to sharpen the model' : 'Architecture detail looks well covered'} />
                </div>
            </section>

            {showFilters && (
                <section className={clsx(insightCardBase, 'mt-6 bg-white/78 p-5 backdrop-blur-xl dark:bg-brand-800/70')}>
                    <div className="flex items-center justify-between gap-4">
                        <div>
                            <h3 className="text-lg font-bold text-brand-950 dark:text-white">Focus the story</h3>
                            <p className="mt-1 text-sm text-brand-600 dark:text-brand-400">Trim the report to the exact severity, category, tier, or wording you want to review.</p>
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

            <section className="mt-6 grid gap-6 xl:grid-cols-[1.35fr_0.95fr]">
                <div className={clsx(insightCardBase, 'bg-white/80 p-6 backdrop-blur-xl dark:bg-brand-800/70')}>
                    <div className="flex items-center gap-2">
                        <TrendingUp className="h-5 w-5 text-brand-primary" />
                        <h3 className="text-lg font-bold text-brand-950 dark:text-white">Executive readout</h3>
                    </div>

                    {topStory ? (
                        <div className="mt-5 space-y-5">
                            <div className={clsx('rounded-[26px] border p-5', severityTheme[topStory.severity]?.surface, severityTheme[topStory.severity]?.border)}>
                                <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-brand-500 dark:text-brand-400">What matters most</p>
                                <div className="mt-3 flex flex-wrap items-center gap-3">
                                    <SeverityBadge severity={topStory.severity} />
                                    <span className="text-sm font-semibold text-brand-700 dark:text-brand-300">{topStory.tier}</span>
                                </div>
                                <h4 className="mt-4 text-2xl font-bold tracking-tight text-brand-950 dark:text-white">{topStory.title}</h4>
                                <p className="mt-3 text-sm leading-7 text-brand-700 dark:text-brand-300">
                                    {topStory.explanation?.why_flagged || topStory.description}
                                </p>
                            </div>

                            <div className="grid gap-4 md:grid-cols-2">
                                <div className="rounded-[24px] border border-brand-100 bg-brand-50/75 p-5 dark:border-brand-700 dark:bg-brand-900/25">
                                    <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-brand-500 dark:text-brand-400">Severity story</p>
                                    <div className="mt-4 space-y-3">
                                        {['Critical', 'High', 'Medium', 'Low'].map((severity) => {
                                            const count = (data.threats || []).filter((t) => t.severity === severity).length;
                                            return (
                                                <div key={severity} className="flex items-center justify-between gap-3">
                                                    <div className="flex items-center gap-2">
                                                        <div className={clsx('h-2.5 w-10 rounded-full bg-gradient-to-r', severityTheme[severity].accent)} />
                                                        <span className="text-sm font-medium text-brand-700 dark:text-brand-300">{severityTheme[severity].label}</span>
                                                    </div>
                                                    <span className="text-sm font-bold text-brand-950 dark:text-white">{count}</span>
                                                </div>
                                            );
                                        })}
                                    </div>
                                </div>

                                <div className="rounded-[24px] border border-brand-100 bg-brand-50/75 p-5 dark:border-brand-700 dark:bg-brand-900/25">
                                    <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-brand-500 dark:text-brand-400">Review posture</p>
                                    <div className="mt-4 grid grid-cols-2 gap-3">
                                        {Object.entries(reviewStateMeta).map(([state, meta]) => (
                                            <div key={state} className="rounded-2xl bg-white/80 px-4 py-3 dark:bg-brand-800/60">
                                                <div className={clsx('inline-flex rounded-full px-2 py-1 text-[10px] font-semibold', meta.className)}>{meta.label}</div>
                                                <div className="mt-2 text-2xl font-black text-brand-950 dark:text-white">{reviewSummary[state] || 0}</div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            </div>
                        </div>
                    ) : (
                        <EmptyInsight
                            icon={ShieldCheck}
                            title="No immediate threats detected"
                            description="This run did not surface any findings. Use the follow-up prompts or add more architecture detail if you want a deeper assessment."
                        />
                    )}
                </div>

                <div className="space-y-6">
                    <div className={clsx(insightCardBase, 'bg-white/80 p-6 backdrop-blur-xl dark:bg-brand-800/70')}>
                        <div className="flex items-center gap-2">
                            <HelpCircle className="h-5 w-5 text-brand-primary" />
                            <h3 className="text-lg font-bold text-brand-950 dark:text-white">Questions to tighten confidence</h3>
                        </div>
                        {followUpQuestions.length ? (
                            <div className="mt-4 space-y-3">
                                {followUpQuestions.slice(0, 4).map((item) => (
                                    <div key={item.id} className="rounded-[22px] border border-brand-100 bg-brand-50/70 p-4 dark:border-brand-700 dark:bg-brand-900/25">
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
                        ) : (
                            <EmptyInsight
                                icon={HelpCircle}
                                title="No follow-up gaps right now"
                                description="The current model has enough architectural detail that the analyzer did not generate targeted clarification prompts."
                            />
                        )}
                    </div>

                    <div className={clsx(insightCardBase, 'bg-white/80 p-6 backdrop-blur-xl dark:bg-brand-800/70')}>
                        <div className="flex items-center gap-2">
                            <ListChecks className="h-5 w-5 text-brand-primary" />
                            <h3 className="text-lg font-bold text-brand-950 dark:text-white">Change and review signal</h3>
                        </div>
                        <div className="mt-4 space-y-3">
                            <div className="rounded-[22px] border border-brand-100 bg-brand-50/70 p-4 dark:border-brand-700 dark:bg-brand-900/25">
                                <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-brand-500 dark:text-brand-400">Diff summary</p>
                                {diffSummary ? (
                                    diffSummary.changed ? (
                                        <div className="mt-3 grid gap-3 sm:grid-cols-2">
                                            <div className="rounded-2xl bg-white/85 px-4 py-3 dark:bg-brand-800/60">
                                                <p className="text-xs text-brand-500 dark:text-brand-400">Score movement</p>
                                                <p className="mt-1 text-2xl font-black text-brand-950 dark:text-white">
                                                    {diffSummary.score_delta > 0 ? '+' : ''}{diffSummary.score_delta || 0}
                                                </p>
                                            </div>
                                            <div className="rounded-2xl bg-white/85 px-4 py-3 dark:bg-brand-800/60">
                                                <p className="text-xs text-brand-500 dark:text-brand-400">Architecture delta</p>
                                                <p className="mt-1 text-sm font-semibold text-brand-950 dark:text-white">
                                                    {diffSummary.component_delta > 0 ? '+' : ''}{diffSummary.component_delta || 0} components, {diffSummary.flow_delta > 0 ? '+' : ''}{diffSummary.flow_delta || 0} flows
                                                </p>
                                            </div>
                                        </div>
                                    ) : (
                                        <p className="mt-3 text-sm leading-6 text-brand-600 dark:text-brand-400">No meaningful delta was detected compared with the previous analysis of this project.</p>
                                    )
                                ) : (
                                    <p className="mt-3 text-sm leading-6 text-brand-600 dark:text-brand-400">Run this project again after a design change to unlock version-to-version deltas.</p>
                                )}
                            </div>

                            <div className="rounded-[22px] border border-brand-100 bg-brand-50/70 p-4 dark:border-brand-700 dark:bg-brand-900/25">
                                <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-brand-500 dark:text-brand-400">Coverage</p>
                                <div className="mt-3 grid grid-cols-2 gap-3">
                                    <div className="rounded-2xl bg-white/85 px-4 py-3 dark:bg-brand-800/60">
                                        <p className="text-xs text-brand-500 dark:text-brand-400">Components</p>
                                        <p className="mt-1 text-2xl font-black text-brand-950 dark:text-white">{data.coverage?.components_analyzed ?? 0}</p>
                                    </div>
                                    <div className="rounded-2xl bg-white/85 px-4 py-3 dark:bg-brand-800/60">
                                        <p className="text-xs text-brand-500 dark:text-brand-400">Trust boundaries</p>
                                        <p className="mt-1 text-2xl font-black text-brand-950 dark:text-white">{data.coverage?.trust_boundary_count ?? 0}</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            <section className="mt-6 grid gap-6 xl:grid-cols-[1.05fr_0.95fr]">
                <div className={clsx(insightCardBase, 'bg-white/80 p-6 backdrop-blur-xl dark:bg-brand-800/70')}>
                    <div className="flex items-center justify-between gap-4">
                        <div>
                            <h3 className="text-lg font-bold text-brand-950 dark:text-white">Risk landscape</h3>
                            <p className="mt-1 text-sm text-brand-600 dark:text-brand-400">Scan where the current architecture concentrates the most likely and most damaging issues.</p>
                        </div>
                    </div>
                    <div className="mt-5 grid gap-6 lg:grid-cols-2">
                        <RiskMatrix threats={data.threats} onCellClick={handleRiskMatrixClick} />
                        <StrideChart threats={data.threats || []} />
                    </div>
                </div>

                <div className={clsx(insightCardBase, 'bg-white/80 p-6 backdrop-blur-xl dark:bg-brand-800/70')}>
                    <div className="flex items-center justify-between gap-3">
                        <div>
                            <h3 className="text-lg font-bold text-brand-950 dark:text-white">Architecture view</h3>
                            <p className="mt-1 text-sm text-brand-600 dark:text-brand-400">A fast visual map of the modeled system and the flows the engine reasoned about.</p>
                        </div>
                        <div className="flex items-center gap-2">
                            <button
                                onClick={copyDiagramCode}
                                className="rounded-xl border border-brand-200 bg-white px-3 py-2 text-xs font-semibold text-brand-700 transition-colors hover:bg-brand-50 dark:border-brand-700 dark:bg-brand-800 dark:text-brand-300 dark:hover:bg-brand-700"
                            >
                                <span className="inline-flex items-center gap-1.5">
                                    {copiedDiagram ? <ClipboardCheck className="h-3.5 w-3.5 text-green-600" /> : <Copy className="h-3.5 w-3.5" />}
                                    {copiedDiagram ? 'Copied' : 'Code'}
                                </span>
                            </button>
                            <button
                                onClick={exportDiagramAsPNG}
                                className="rounded-xl border border-brand-200 bg-white px-3 py-2 text-xs font-semibold text-brand-700 transition-colors hover:bg-brand-50 dark:border-brand-700 dark:bg-brand-800 dark:text-brand-300 dark:hover:bg-brand-700"
                            >
                                <span className="inline-flex items-center gap-1.5"><Download className="h-3.5 w-3.5" /> PNG</span>
                            </button>
                        </div>
                    </div>
                    <div className="mt-5 rounded-[26px] border border-brand-100 bg-brand-50/70 p-4 dark:border-brand-700 dark:bg-brand-900/25">
                        <div ref={mermaidRef} className="flex min-h-[280px] items-center justify-center overflow-x-auto" />
                    </div>
                </div>
            </section>

            <section className="mt-8 space-y-10">
                <ThreatSection
                    title="Confirmed risks"
                    description="These findings have the strongest supporting signals and should drive the next round of design or control changes."
                    icon={ShieldAlert}
                    threats={confirmed}
                    emptyTitle="No confirmed risks"
                    emptyDescription="Nothing crossed the threshold for a confirmed finding in this view. That usually means the architecture is either fairly solid or the remaining issues are still conditional."
                    reviewStates={reviewStates}
                    onReviewStateChange={updateReviewState}
                />

                <ThreatSection
                    title="Potential risks"
                    description="These are weaker or assumption-sensitive findings. They are best used as design review prompts rather than immediate action items."
                    icon={AlertTriangle}
                    threats={potential}
                    emptyTitle="No potential risks"
                    emptyDescription="This slice is clear right now. If you add more architecture detail later, the analyzer may surface lower-confidence follow-up findings here."
                    reviewStates={reviewStates}
                    onReviewStateChange={updateReviewState}
                />
            </section>

            <AnalystWorkbench
                data={data}
                projectName={projectName}
                reviewStates={reviewStates}
            />

            {hasActiveFilters && filteredThreats.length === 0 && (
                <section className="mt-8">
                    <EmptyInsight
                        icon={Search}
                        title="No findings match this filter set"
                        description="Try widening the severity or tier filter, or clear the search term to bring the full narrative back."
                    />
                    <div className="mt-4 text-center">
                        <button onClick={clearFilters} className="rounded-xl bg-brand-primary px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-brand-primary/90">
                            Reset filters
                        </button>
                    </div>
                </section>
            )}

            {assumptions.length > 0 && (
                <section className={clsx(insightCardBase, 'mt-8 bg-white/78 p-6 backdrop-blur-xl dark:bg-brand-800/68')}>
                    <div className="flex items-center gap-2">
                        <Sparkles className="h-5 w-5 text-brand-primary" />
                        <h3 className="text-lg font-bold text-brand-950 dark:text-white">Assumptions still shaping the model</h3>
                    </div>
                    <div className="mt-4 grid gap-3 md:grid-cols-2">
                        {assumptions.slice(0, 4).map((assumption, index) => (
                            <div key={`${assumption.scope}-${index}`} className="rounded-[22px] border border-yellow-200 bg-yellow-50/80 px-4 py-3 dark:border-yellow-900/40 dark:bg-yellow-950/18">
                                <p className="text-sm leading-6 text-yellow-900 dark:text-yellow-300">{assumption.message}</p>
                            </div>
                        ))}
                    </div>
                </section>
            )}
        </div>
    );
}
