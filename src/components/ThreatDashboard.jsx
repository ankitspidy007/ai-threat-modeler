import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
    ShieldAlert,
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
    Eye,
    ZoomIn,
    ZoomOut,
    RotateCcw,
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

const resizeDiagramSvg = (svgElement, zoom) => {
    if (!svgElement?.dataset.baseWidth || !svgElement?.dataset.baseHeight) return;
    svgElement.style.width = `${Number(svgElement.dataset.baseWidth) * zoom}px`;
    svgElement.style.height = `${Number(svgElement.dataset.baseHeight) * zoom}px`;
    svgElement.style.maxWidth = 'none';
    svgElement.style.maxHeight = 'none';
};

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

const insightCardBase = 'rounded-md border border-slate-200 bg-white shadow-sm';

const SeverityBadge = ({ severity }) => {
    const theme = severityTheme[severity] || severityTheme.Low;
    return (
        <span className={clsx('inline-flex items-center rounded-full border px-2.5 py-1 text-[11px] font-bold uppercase tracking-[0.18em]', theme.badge)}>
            {severity}
        </span>
    );
};

const EmptyInsight = ({ icon, title, description }) => (
    <div className="rounded-lg border border-dashed border-brand-300 bg-brand-50 px-5 py-8 text-center dark:border-brand-700 dark:bg-brand-900/35">
        <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-lg bg-white text-brand-600 dark:bg-brand-800 dark:text-brand-300">
            {React.createElement(icon, { className: 'h-5 w-5' })}
        </div>
        <h4 className="text-base font-semibold text-brand-900 dark:text-white">{title}</h4>
        <p className="mt-2 text-sm leading-6 text-brand-600 dark:text-brand-400">{description}</p>
    </div>
);

const MetricCard = ({ label, value, tone = 'default', detail }) => {
    const toneMap = {
        default: 'bg-white border-slate-200',
        danger: 'bg-white border-red-300',
        warning: 'bg-white border-amber-300',
        success: 'bg-white border-emerald-300',
        accent: 'bg-white border-sky-300',
    };

    return (
        <div className={clsx('rounded-lg border border-brand-200 p-5 dark:border-brand-700', toneMap[tone] || toneMap.default)}>
            <p className="text-xs font-semibold uppercase tracking-wide text-brand-500 dark:text-brand-400">{label}</p>
            <div className="mt-3 flex items-end justify-between gap-3">
                <div className="text-3xl font-black tracking-tight text-brand-950 dark:text-white">{value}</div>
                {detail && <div className="max-w-[8rem] text-right text-xs leading-5 text-brand-500 dark:text-brand-400">{detail}</div>}
            </div>
        </div>
    );
};

const aiLensTone = {
    high: 'border-red-200 bg-red-50/80 text-red-900 dark:border-red-900/40 dark:bg-red-950/20 dark:text-red-200',
    medium: 'border-amber-200 bg-amber-50/80 text-amber-900 dark:border-amber-900/40 dark:bg-amber-950/20 dark:text-amber-200',
    low: 'border-emerald-200 bg-emerald-50/80 text-emerald-900 dark:border-emerald-900/40 dark:bg-emerald-950/20 dark:text-emerald-200',
};

const AISecurityLensCard = ({ item }) => (
    <div className={clsx('rounded-lg border p-4', aiLensTone[item.level] || aiLensTone.low)}>
        <div className="flex items-start justify-between gap-4">
            <div className="min-w-0">
                <p className="text-base font-semibold leading-6">{item.label}</p>
                <p className="mt-2 text-2xl font-bold tracking-tight">{item.count}</p>
            </div>
            <span className="shrink-0 rounded-full bg-white/70 px-2.5 py-1 text-[10px] font-bold uppercase tracking-wide text-current dark:bg-black/10">
                {item.level}
            </span>
        </div>
        <p className="mt-3 text-sm leading-6 opacity-90">{item.summary}</p>
    </div>
);

const PriorityActionCard = ({ action, index }) => (
    <div className="rounded-lg border border-brand-200 bg-brand-50 p-5 dark:border-brand-700 dark:bg-brand-900/35">
        <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-brand-primary text-sm font-bold text-white">
                    {index + 1}
                </div>
                <div>
                    <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-brand-500 dark:text-brand-400">Fix first</p>
                    <h4 className="mt-1 text-base font-bold text-brand-950 dark:text-white">{action.title}</h4>
                </div>
            </div>
            <SeverityBadge severity={action.priority} />
        </div>
        <p className="mt-4 text-sm leading-6 text-brand-700 dark:text-brand-300">{action.why_now}</p>
        <div className="mt-4 rounded-lg border border-brand-200 bg-white px-4 py-3 text-sm font-medium leading-6 text-brand-800 dark:border-brand-700 dark:bg-brand-800/60 dark:text-brand-200">
            {action.action}
        </div>
        {action.focus_area?.length > 0 && (
            <p className="mt-3 text-xs leading-5 text-brand-500 dark:text-brand-400">
                Focus area: {action.focus_area.join(', ')}
            </p>
        )}
    </div>
);

const ThreatCard = ({ threat, reviewState = 'open', onReviewStateChange }) => {
    const theme = severityTheme[threat.severity] || severityTheme.Low;
    const evidencePreview = threat.explanation?.evidence_summary?.length
        ? threat.explanation.evidence_summary
        : (threat.evidence || []).slice(0, 2);

    return (
        <article className={clsx('relative overflow-hidden rounded-lg border bg-white p-6 shadow-sm transition-colors dark:bg-brand-800', theme.border)}>
            <div className={clsx('absolute inset-x-0 top-0 h-1', theme.accent.replace('from-', 'bg-').split(' ')[0])} />

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
                        <span className="rounded-full bg-brand-100 px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wide text-brand-700 dark:bg-brand-700 dark:text-brand-200">{(threat.finding_type || 'architecture').replaceAll('_', ' ')}</span>
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

                <div className={clsx('min-w-[220px] rounded-lg border p-4', theme.surface, theme.border)}>
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
                <div className="rounded-lg border border-brand-200 bg-brand-50 p-4 dark:border-brand-700 dark:bg-brand-900/35">
                    <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-brand-500 dark:text-brand-400">Signals</p>
                    <div className="mt-3 grid gap-3 md:grid-cols-2">
                        <div>
                            <p className="text-xs font-semibold text-brand-600 dark:text-brand-400">Evidence highlights</p>
                            {evidencePreview.length > 0 ? (
                                <ul className="mt-2 space-y-2 text-sm leading-6 text-brand-700 dark:text-brand-300">
                                    {evidencePreview.map((ev, i) => (
                                        <li key={i} className="rounded-lg border border-brand-200 bg-white px-3 py-2 dark:border-brand-700 dark:bg-brand-800/60">{ev}</li>
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
                            <div>
                                <p className="text-xs font-semibold text-brand-600 dark:text-brand-400">Risk inputs</p>
                                <p className="mt-2 text-sm leading-6 text-brand-700 dark:text-brand-300">
                                    Exposure {threat.risk_factors?.exposure || threat.exposure || 'unspecified'}; evidence {threat.risk_factors?.evidence_confidence || threat.confidence}
                                </p>
                            </div>
                        </div>
                    </div>
                </div>

                <div className="rounded-lg border border-emerald-200 bg-emerald-50 p-4 dark:border-emerald-900/40 dark:bg-emerald-950/20">
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

const affectedComponents = (threat) => {
    const components = threat.explanation?.impacted_components?.length
        ? threat.explanation.impacted_components
        : threat.affected_components?.length
            ? threat.affected_components
            : [threat.affected_component || threat.component].filter(Boolean);
    return components.length ? components.join(', ') : 'Not specified';
};

const ThreatSection = ({ threats, onSelectThreat }) => (
    <section className={clsx(insightCardBase, 'overflow-hidden')}>
        <div className="flex items-center justify-between gap-4 border-b border-brand-200 px-5 py-4 dark:border-brand-700">
            <div>
                <h3 className="text-lg font-bold text-brand-950 dark:text-white">Risk register</h3>
                <p className="mt-1 text-sm text-brand-600 dark:text-brand-400">Technical findings ordered by severity and risk score.</p>
            </div>
            <span className="text-sm font-semibold text-brand-600 dark:text-brand-300">{threats.length} risks</span>
        </div>

        {threats.length === 0 ? (
            <div className="p-6">
                <EmptyInsight icon={ShieldCheck} title="No matching risks" description="No findings match the current filters." />
            </div>
        ) : (
            <div className="overflow-x-auto">
                <table className="w-full min-w-[820px] border-collapse text-left">
                    <thead className="bg-brand-50 text-xs font-semibold uppercase text-brand-500 dark:bg-brand-900/50 dark:text-brand-400">
                        <tr>
                            <th className="px-5 py-3">Risk name</th>
                            <th className="w-28 px-4 py-3">Severity</th>
                            <th className="w-52 px-4 py-3">Affected STRIDE</th>
                            <th className="w-64 px-4 py-3">Affected component</th>
                            <th className="w-20 px-4 py-3 text-center">Details</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-brand-200 dark:divide-brand-700">
                        {threats.map((threat) => (
                            <tr key={threat.id} className="bg-white hover:bg-brand-50/70 dark:bg-brand-800 dark:hover:bg-brand-700/45">
                                <td className="px-5 py-4">
                                    <p className="max-w-md text-sm font-semibold text-brand-950 dark:text-white">{threat.title}</p>
                                    <p className="mt-1 text-xs text-brand-500 dark:text-brand-400">{threat.tier} | {(threat.finding_type || 'architecture').replaceAll('_', ' ')}</p>
                                </td>
                                <td className="px-4 py-4"><SeverityBadge severity={threat.severity} /></td>
                                <td className="px-4 py-4 text-sm font-medium text-brand-700 dark:text-brand-300">{(threat.affected_stride_categories?.length ? threat.affected_stride_categories : [threat.stride_category || threat.category]).join(', ')}</td>
                                <td className="px-4 py-4 text-sm text-brand-600 dark:text-brand-300">{affectedComponents(threat)}</td>
                                <td className="px-4 py-4 text-center">
                                    <button
                                        type="button"
                                        onClick={() => onSelectThreat(threat)}
                                        className="inline-flex h-9 w-9 items-center justify-center rounded-md border border-brand-200 text-brand-600 hover:border-brand-primary hover:text-brand-primary dark:border-brand-600 dark:text-brand-300"
                                        aria-label={`View details for ${threat.title}`}
                                        title="View risk details"
                                    >
                                        <Eye className="h-4 w-4" />
                                    </button>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        )}
    </section>
);

const RiskDetailsModal = ({ threat, reviewState, onReviewStateChange, onClose }) => {
    useEffect(() => {
        if (!threat) return undefined;
        const handleKeyDown = (event) => {
            if (event.key === 'Escape') onClose();
        };
        const previousOverflow = document.body.style.overflow;
        document.body.style.overflow = 'hidden';
        window.addEventListener('keydown', handleKeyDown);
        return () => {
            document.body.style.overflow = previousOverflow;
            window.removeEventListener('keydown', handleKeyDown);
        };
    }, [threat, onClose]);

    if (!threat) return null;
    return (
        <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/45 p-4 pt-[6vh]" role="presentation" onMouseDown={onClose}>
            <div
                className="relative max-h-[88vh] w-full max-w-4xl overflow-y-auto rounded-lg bg-white p-2 shadow-2xl dark:bg-brand-900"
                role="dialog"
                aria-modal="true"
                aria-label={`Risk details: ${threat.title}`}
                onMouseDown={(event) => event.stopPropagation()}
            >
                <button
                    type="button"
                    onClick={onClose}
                    className="absolute right-4 top-4 z-10 inline-flex h-9 w-9 items-center justify-center rounded-md border border-brand-200 bg-white text-brand-600 hover:text-brand-950 dark:border-brand-700 dark:bg-brand-800 dark:text-brand-300 dark:hover:text-white"
                    aria-label="Close risk details"
                    title="Close"
                >
                    <X className="h-4 w-4" />
                </button>
                <ThreatCard threat={threat} reviewState={reviewState} onReviewStateChange={onReviewStateChange} />
            </div>
        </div>
    );
};

export default function ThreatDashboard({ data, projectName }) {
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
    }, [data]);

    useEffect(() => {
        resizeDiagramSvg(mermaidRef.current?.querySelector('svg'), diagramZoom);
    }, [diagramZoom]);

    useEffect(() => {
        const nextStates = {};
        (data?.threats || []).forEach((threat) => {
            nextStates[threat.id] = threat.review_state || 'open';
        });
        queueMicrotask(() => setReviewStates(nextStates));
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
    const publicationBlocked = qualityGate.publication_status === 'blocked' || qualityGate.status === 'fail';
    const publicationLabel = publicationBlocked
        ? 'Draft - quality gate failed'
        : qualityGate.publication_status === 'ready'
            ? 'Publication ready'
            : 'Technical review';
    const attackPaths = data.attack_chains?.paths || [];
    const assumptions = data.coverage?.assumptions || [];
    const diffSummary = data.diff_summary;
    const followUpQuestions = data.follow_up_questions || [];
    const aiSecurityLens = data.ai_security_lens || { enabled: false, overview: '', items: [] };
    const aiLensGridClass = aiSecurityLens.items?.length === 1
        ? 'grid-cols-1'
        : aiSecurityLens.items?.length === 2
            ? 'md:grid-cols-2'
            : 'md:grid-cols-2 xl:grid-cols-3';
    const priorityActions = data.priority_actions || [];

    const allThreatsSorted = [...(data.threats || [])].sort((a, b) => {
        const severityDelta = (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0);
        if (severityDelta !== 0) return severityDelta;
        return (b.risk_score || 0) - (a.risk_score || 0);
    });

    const topStory = allThreatsSorted[0];
    const confirmedCount = (data.threats || []).filter((threat) => threat.tier === 'Confirmed').length;
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

    const updateReviewState = (threatId, state) => {
        setReviewStates((prev) => ({ ...prev, [threatId]: state }));
    };

    return (
        <div className="technical-report mx-auto w-full max-w-6xl animate-fade-in-up bg-white px-2 pb-24 text-slate-900 sm:px-4">
            <section className={clsx(insightCardBase, 'relative overflow-hidden p-6')}>

                <div className="relative flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
                    <div className="max-w-3xl">
                        <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Technical threat model</p>
                        <h1 className="mt-2 text-2xl font-semibold text-slate-950 md:text-3xl">
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

                    <div className="flex flex-wrap gap-2 lg:justify-end">
                        <button
                            onClick={() => setShowFilters(!showFilters)}
                            className="ui-button-secondary"
                        >
                            <span className="inline-flex items-center gap-2">
                                <Filter className="h-4 w-4" />
                                Filters {hasActiveFilters && `(${filteredThreats.length})`}
                            </span>
                        </button>
                        <button onClick={downloadJSON} className="ui-button-secondary">
                            <span className="inline-flex items-center gap-2"><Code className="h-4 w-4" /> JSON</span>
                        </button>
                        <button onClick={downloadCSV} className="ui-button-secondary">
                            <span className="inline-flex items-center gap-2"><Share2 className="h-4 w-4" /> CSV</span>
                        </button>
                        {data.report_markdown && (
                            <button onClick={downloadMarkdown} disabled={publicationBlocked} className="ui-button-secondary disabled:cursor-not-allowed disabled:opacity-45" title={publicationBlocked ? 'Resolve quality-gate failures before final export' : 'Download Markdown report'}>
                                <span className="inline-flex items-center gap-2"><FileText className="h-4 w-4" /> Markdown</span>
                            </button>
                        )}
                        <button onClick={handlePDFExport} disabled={publicationBlocked} className="btn-brand disabled:cursor-not-allowed disabled:opacity-45" title={publicationBlocked ? 'Resolve quality-gate failures before final export' : 'Export final PDF'}>
                            <span className="inline-flex items-center gap-2"><Download className="h-4 w-4" /> Export PDF</span>
                        </button>
                    </div>
                </div>

                <div className="relative mt-8 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                    <MetricCard label="Security score" value={`${data.score}/100`} tone={data.score < 40 ? 'danger' : data.score < 70 ? 'warning' : 'success'} detail={data.score < 40 ? 'Immediate response recommended' : data.score < 70 ? 'Address top findings next' : 'Strong baseline with focused follow-up'} />
                    <MetricCard label="Confirmed risks" value={confirmedCount} tone={criticalCount > 0 ? 'danger' : 'accent'} detail={`${criticalCount} critical, ${highCount} high`} />
                    <MetricCard label="Review progress" value={`${remediationPercent}%`} tone="success" detail={`${mitigatedThreats}/${data.threats?.length || 0} findings triaged`} />
                    <MetricCard label="Questions for team" value={followUpQuestions.length} tone="warning" detail={followUpQuestions.length ? 'Answer these to sharpen the model' : 'Architecture detail looks well covered'} />
                </div>
            </section>

            {showFilters && (
                <section className={clsx(insightCardBase, 'mt-6 p-5')}>
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

            <section className="mt-6 space-y-6">
                <div className={clsx(insightCardBase, 'p-6')}>
                    <div className="flex items-center gap-2">
                        <TrendingUp className="h-5 w-5 text-brand-primary" />
                        <h3 className="text-lg font-bold text-brand-950 dark:text-white">Executive readout</h3>
                    </div>

                    {topStory ? (
                        <div className="mt-5 space-y-5">
                            <div className={clsx('rounded-lg border p-5', severityTheme[topStory.severity]?.surface, severityTheme[topStory.severity]?.border)}>
                                <p className="text-xs font-semibold uppercase tracking-wide text-brand-500 dark:text-brand-400">What matters most</p>
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
                                <div className="rounded-lg border border-brand-200 bg-brand-50 p-5 dark:border-brand-700 dark:bg-brand-900/35">
                                    <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-brand-500 dark:text-brand-400">Severity story</p>
                                    <div className="mt-4 space-y-3">
                                        {['Critical', 'High', 'Medium', 'Low'].map((severity) => {
                                            const count = (data.threats || []).filter((t) => t.severity === severity).length;
                                            return (
                                                <div key={severity} className="flex items-center justify-between gap-3">
                                                    <div className="flex items-center gap-2">
                                                        <div className={clsx('h-2.5 w-10 rounded-full', severityTheme[severity].accent.replace('from-', 'bg-').split(' ')[0])} />
                                                        <span className="text-sm font-medium text-brand-700 dark:text-brand-300">{severityTheme[severity].label}</span>
                                                    </div>
                                                    <span className="text-sm font-bold text-brand-950 dark:text-white">{count}</span>
                                                </div>
                                            );
                                        })}
                                    </div>
                                </div>

                                <div className="rounded-lg border border-brand-200 bg-brand-50 p-5 dark:border-brand-700 dark:bg-brand-900/35">
                                    <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-brand-500 dark:text-brand-400">Review posture</p>
                                    <div className="mt-4 grid grid-cols-2 gap-3">
                                        {Object.entries(reviewStateMeta).map(([state, meta]) => (
                                            <div key={state} className="rounded-lg border border-brand-200 bg-white px-4 py-3 dark:border-brand-700 dark:bg-brand-800/60">
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
                    <div className={clsx(insightCardBase, 'p-6')}>
                        <div className="flex items-center gap-2">
                            <HelpCircle className="h-5 w-5 text-brand-primary" />
                            <h3 className="text-lg font-bold text-brand-950 dark:text-white">Questions to tighten confidence</h3>
                        </div>
                        {followUpQuestions.length ? (
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
                        ) : (
                            <EmptyInsight
                                icon={HelpCircle}
                                title="No follow-up gaps right now"
                                description="The current model has enough architectural detail that the analyzer did not generate targeted clarification prompts."
                            />
                        )}
                    </div>

                    <div className={clsx(insightCardBase, 'p-6')}>
                        <div className="flex items-center gap-2">
                            <ListChecks className="h-5 w-5 text-brand-primary" />
                            <h3 className="text-lg font-bold text-brand-950 dark:text-white">Change and review signal</h3>
                        </div>
                        <div className="mt-4 space-y-3">
                            <div className="rounded-lg border border-brand-200 bg-brand-50 p-4 dark:border-brand-700 dark:bg-brand-900/35">
                                <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-brand-500 dark:text-brand-400">Diff summary</p>
                                {diffSummary ? (
                                    diffSummary.changed ? (
                                        <div className="mt-3 grid gap-3 sm:grid-cols-2">
                                            <div className="rounded-lg border border-brand-200 bg-white px-4 py-3 dark:border-brand-700 dark:bg-brand-800/60">
                                                <p className="text-xs text-brand-500 dark:text-brand-400">Score movement</p>
                                                <p className="mt-1 text-2xl font-black text-brand-950 dark:text-white">
                                                    {diffSummary.score_delta > 0 ? '+' : ''}{diffSummary.score_delta || 0}
                                                </p>
                                            </div>
                                            <div className="rounded-lg border border-brand-200 bg-white px-4 py-3 dark:border-brand-700 dark:bg-brand-800/60">
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

                            <div className="rounded-lg border border-brand-200 bg-brand-50 p-4 dark:border-brand-700 dark:bg-brand-900/35">
                                <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-brand-500 dark:text-brand-400">Coverage</p>
                                <div className="mt-3 grid grid-cols-2 gap-3">
                                    <div className="rounded-lg border border-brand-200 bg-white px-4 py-3 dark:border-brand-700 dark:bg-brand-800/60">
                                        <p className="text-xs text-brand-500 dark:text-brand-400">Components</p>
                                        <p className="mt-1 text-2xl font-black text-brand-950 dark:text-white">{data.coverage?.components_analyzed ?? 0}</p>
                                    </div>
                                    <div className="rounded-lg border border-brand-200 bg-white px-4 py-3 dark:border-brand-700 dark:bg-brand-800/60">
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
                <div className={clsx(insightCardBase, 'p-6')}>
                    <div className="flex items-center gap-2">
                        <Sparkles className="h-5 w-5 text-brand-primary" />
                        <h3 className="text-lg font-bold text-brand-950 dark:text-white">AI security lens</h3>
                    </div>
                    <p className="mt-2 text-sm leading-6 text-brand-600 dark:text-brand-400">
                        {aiSecurityLens.overview || 'A focused readout on prompt, data, model, and agent-specific AI risk themes.'}
                    </p>
                    {aiSecurityLens.items?.length ? (
                        <div className={clsx('mt-5 grid gap-4', aiLensGridClass)}>
                            {aiSecurityLens.items.map((item) => (
                                <AISecurityLensCard key={item.id} item={item} />
                            ))}
                        </div>
                    ) : (
                        <EmptyInsight
                            icon={Sparkles}
                            title="No AI-specific lens available"
                            description="This run did not generate AI-specific risk storytelling, which usually means the current architecture does not look AI-native yet."
                        />
                    )}
                </div>

                <div className={clsx(insightCardBase, 'p-6')}>
                    <div className="flex items-center gap-2">
                        <ShieldAlert className="h-5 w-5 text-brand-primary" />
                        <h3 className="text-lg font-bold text-brand-950 dark:text-white">Top 3 things to fix first</h3>
                    </div>
                    <p className="mt-2 text-sm leading-6 text-brand-600 dark:text-brand-400">
                        The fastest path to reducing the current risk story, based on severity, evidence, and architectural exposure.
                    </p>
                    {priorityActions.length ? (
                        <div className="mt-5 space-y-4">
                            {priorityActions.slice(0, 3).map((action, index) => (
                                <PriorityActionCard key={`${action.title}-${index}`} action={action} index={index} />
                            ))}
                        </div>
                    ) : (
                        <EmptyInsight
                            icon={ShieldCheck}
                            title="No urgent actions surfaced"
                            description="The analyzer did not generate a short priority list for this run. Add more detail or rerun after a design change to surface clearer next steps."
                        />
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
                        className="mt-5 flex min-h-[320px] w-full items-center justify-center overflow-auto rounded-md border border-slate-200 bg-white p-4 sm:min-h-[400px] sm:p-6"
                        aria-label="Architecture diagram. Use the mouse wheel or zoom controls to change scale."
                    >
                        <div ref={mermaidRef} className="flex h-full min-w-full w-max shrink-0 items-center justify-center" />
                    </div>
                </div>

                {publicationBlocked && (
                    <div className="relative mt-6 border-l-4 border-red-600 bg-white px-4 py-3 text-sm text-slate-700">
                        <p className="font-semibold text-red-700">This analysis is incomplete and cannot be published as a final report.</p>
                        <p className="mt-1">
                            {qualityGate.unclassified_known_issues || 0} unclassified issues, {qualityGate.confirmed_unmapped_findings || 0} unscoped confirmed findings, {qualityGate.omitted_named_components || 0} omitted components, and {qualityGate.duplicate_component_aliases || 0} duplicate aliases require resolution.
                        </p>
                    </div>
                )}
            </section>

            <section className="mt-6 grid gap-6 xl:grid-cols-2">
                <div className={clsx(insightCardBase, 'p-6')}>
                    <div className="flex items-center gap-2">
                        <ListChecks className="h-5 w-5 text-brand-primary" />
                        <h3 className="text-lg font-bold text-brand-950 dark:text-white">Technical system model</h3>
                    </div>
                    <div className="mt-5 grid grid-cols-2 gap-3 text-sm">
                        <div className="border-b border-brand-200 pb-3 dark:border-brand-700"><span className="text-brand-500 dark:text-brand-400">Public entry points</span><p className="mt-1 font-semibold text-brand-950 dark:text-white">{systemModel.public_entry_points?.length ?? 0}</p></div>
                        <div className="border-b border-brand-200 pb-3 dark:border-brand-700"><span className="text-brand-500 dark:text-brand-400">Confirmed boundary crossings</span><p className="mt-1 font-semibold text-brand-950 dark:text-white">{systemModel.boundary_crossings?.length ?? 0}</p><p className="mt-1 text-xs text-brand-500 dark:text-brand-400">{systemModel.inferred_boundary_crossings?.length ?? 0} inferred</p></div>
                        <div><span className="text-brand-500 dark:text-brand-400">Identities modeled</span><p className="mt-1 font-semibold text-brand-950 dark:text-white">{systemModel.identities?.length ?? 0}</p></div>
                        <div><span className="text-brand-500 dark:text-brand-400">Cloud resources</span><p className="mt-1 font-semibold text-brand-950 dark:text-white">{systemModel.cloud_resources?.length ?? 0}</p></div>
                    </div>
                </div>

                <div className={clsx(insightCardBase, 'p-6')}>
                    <div className="flex items-center gap-2">
                        <TrendingUp className="h-5 w-5 text-brand-primary" />
                        <h3 className="text-lg font-bold text-brand-950 dark:text-white">Evidence-backed attack paths</h3>
                    </div>
                    {attackPaths.length ? (
                        <div className="mt-4 space-y-3">
                            {attackPaths.slice(0, 3).map((path) => (
                                <div key={path.id || path.related_threat_id} className="border-l-2 border-brand-primary pl-4">
                                    <p className="text-sm font-semibold text-brand-950 dark:text-white">{path.entry_point} to {path.target_component}</p>
                                    <p className="mt-1 text-sm leading-6 text-brand-600 dark:text-brand-400">{path.steps?.[0] || path.impact}</p>
                                    <p className="mt-1 text-xs font-medium uppercase tracking-wide text-brand-500 dark:text-brand-400">{path.severity} confidence {path.confidence}</p>
                                </div>
                            ))}
                        </div>
                    ) : (
                        <p className="mt-4 text-sm text-brand-500 dark:text-brand-400">No attack path has enough evidence to model in this analysis.</p>
                    )}
                </div>
            </section>

            <section className="mt-6">
                <div className={clsx(insightCardBase, 'p-6')}>
                    <div className="flex flex-wrap items-start justify-between gap-4">
                        <div>
                            <div className="flex items-center gap-2">
                                <ShieldAlert className="h-5 w-5 text-brand-primary" />
                                <h3 className="text-lg font-bold text-brand-950 dark:text-white">STRIDE assessment coverage</h3>
                            </div>
                            <p className="mt-1 text-sm text-brand-600 dark:text-brand-400">Every modeled element is evaluated against all six STRIDE categories. Unknown cells identify missing architecture evidence.</p>
                        </div>
                        <div className="text-right">
                            <p className="text-2xl font-black text-brand-950 dark:text-white">{strideCoverage.assessment_percent ?? 100}% assessed</p>
                            <p className="text-xs text-brand-500 dark:text-brand-400">
                                {strideCoverage.evidence_resolution_percent ?? strideCoverage.coverage_percent ?? 0}% evidence resolution | {strideCoverage.unknown_cells ?? 0} unknown
                            </p>
                        </div>
                    </div>
                    <div className="mt-5 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
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
                    <div className="mt-5 flex flex-wrap gap-2 text-xs">
                        {Object.entries(engineStatus).map(([name, status]) => (
                            <span key={name} className="border border-brand-200 px-2.5 py-1.5 text-brand-600 dark:border-brand-700 dark:text-brand-300">
                                {name.replaceAll('_', ' ')}: {status?.status || 'unknown'}
                            </span>
                        ))}
                    </div>
                </div>
            </section>

            <section className="mt-6">
                <div className={clsx(insightCardBase, 'p-6')}>
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
            </section>

            <section className="mt-8">
                <ThreatSection threats={sortedFilteredThreats} onSelectThreat={setSelectedThreat} />
            </section>

            <AnalystWorkbench
                data={data}
                projectName={projectName}
                reviewStates={reviewStates}
            />

            {assumptions.length > 0 && (
                <section className={clsx(insightCardBase, 'mt-8 p-6')}>
                    <div className="flex items-center gap-2">
                        <Sparkles className="h-5 w-5 text-brand-primary" />
                        <h3 className="text-lg font-bold text-brand-950 dark:text-white">Assumptions still shaping the model</h3>
                    </div>
                    <div className="mt-4 grid gap-3 md:grid-cols-2">
                        {assumptions.slice(0, 4).map((assumption, index) => (
                            <div key={`${assumption.scope}-${index}`} className="rounded-lg border border-yellow-200 bg-yellow-50 px-4 py-3 dark:border-yellow-900/40 dark:bg-yellow-950/20">
                                <p className="text-sm leading-6 text-yellow-900 dark:text-yellow-300">{assumption.message}</p>
                            </div>
                        ))}
                    </div>
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
