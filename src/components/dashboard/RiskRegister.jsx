import { useEffect } from 'react';
import { clsx } from 'clsx';
import { ArrowUpRight, Eye, ShieldCheck, X } from 'lucide-react';

import { EmptyInsight, SeverityBadge } from './InsightCards';
import { affectedComponents, insightCardBase, reviewStateMeta, severityTheme } from './theme';

const noFlowReason = {
    no_flows_modeled: 'No data flows are modeled for this architecture, so no path was assessed.',
    component_isolated: 'The architecture models no flow reaching this component.',
};

/**
 * Which data flows this finding relates to, or why none are shown.
 *
 * A blank flow list has two very different meanings: the finding is local to a
 * component, or the architecture never described any path at all. The second is
 * a gap in the model the analyst needs to close, so it is named rather than
 * shown as an absence of impact.
 */
const FlowContext = ({ threat }) => {
    const scoped = threat.affected_data_flows || [];
    const related = threat.explanation?.component_flows || [];
    const heading = scoped.length ? 'Data flows' : related.length ? 'Flows touching this component' : 'Data flows';

    return (
        <div>
            <p className="text-xs font-semibold text-brand-600 dark:text-brand-400">{heading}</p>
            {scoped.length > 0 && (
                <p className="mt-2 text-sm leading-6 text-brand-700 dark:text-brand-300">{scoped.join(', ')}</p>
            )}
            {scoped.length === 0 && related.length > 0 && (
                <ul className="mt-2 space-y-1 text-sm leading-6 text-brand-700 dark:text-brand-300">
                    {related.map((flow) => (
                        <li key={`${flow.reference}-${flow.direction}`} className="flex flex-wrap items-baseline gap-x-2">
                            <span>{flow.label}</span>
                            <span className="text-xs text-brand-500 dark:text-brand-400">
                                {flow.direction}
                                {flow.protocol ? ` · ${flow.protocol}` : ''}
                                {flow.crosses_trust_boundary ? ' · crosses a trust boundary' : ''}
                                {flow.assumed ? ' · assumed' : ''}
                            </span>
                        </li>
                    ))}
                </ul>
            )}
            {scoped.length === 0 && related.length === 0 && (
                <p className="mt-2 text-sm leading-6 text-brand-700 dark:text-brand-300">
                    {noFlowReason[threat.explanation?.flow_context] || 'No flow-specific impact noted'}
                </p>
            )}
        </div>
    );
};

/**
 * Which document, page and line each piece of evidence came from.
 *
 * With several uploads the first question an analyst asks about a finding is
 * which file said so, because that decides who they go and talk to. A finding
 * resting only on inference says that instead of naming a document.
 */
const EvidenceSources = ({ threat }) => {
    const cited = [];
    const seen = new Set();
    let inferred = 0;

    for (const detail of threat.evidence_details || []) {
        if (!detail?.cite) {
            if (detail?.source_type === 'inference') inferred += 1;
            continue;
        }
        if (seen.has(detail.cite)) continue;
        seen.add(detail.cite);
        cited.push(detail);
    }

    if (cited.length === 0 && inferred === 0) return null;

    return (
        <div className="mt-3">
            <p className="text-xs font-semibold text-brand-600 dark:text-brand-400">Cited in</p>
            {cited.length > 0 ? (
                <ul className="mt-2 space-y-1 text-sm leading-6 text-brand-700 dark:text-brand-300">
                    {cited.map((detail) => (
                        <li key={detail.cite} className="flex flex-wrap items-baseline gap-x-2">
                            <span>{detail.document}</span>
                            <span className="text-xs text-brand-500 dark:text-brand-400">
                                {[detail.locator, detail.line ? `line ${detail.line}` : null]
                                    .filter(Boolean)
                                    .join(' · ')}
                            </span>
                        </li>
                    ))}
                </ul>
            ) : (
                <p className="mt-2 text-sm leading-6 text-brand-700 dark:text-brand-300">
                    Inferred from architecture context; no document states this directly.
                </p>
            )}
        </div>
    );
};

const pathStatusNote = {
    partially_inferred: 'Some hops on this route were assumed rather than described.',
    unresolved_entry_path: 'No route from a modeled entry point reaches this component.',
    unmapped: 'This finding is not tied to a component in the architecture graph.',
};

/**
 * How an attacker gets here, and what it opens up once they do.
 *
 * A finding on its own says a component is weak. The route says whether anyone
 * outside can reach it, and the onward reach says whether reaching it matters,
 * which is the difference between a bug and an incident.
 */
const AttackRoute = ({ threat }) => {
    const path = threat.attack_path;
    if (!path) return null;

    const hops = path.hops || [];
    const reached = path.sensitive_data_reached || [];

    return (
        <div>
            <p className="text-xs font-semibold text-brand-600 dark:text-brand-400">Route in</p>
            {hops.length > 0 ? (
                <ol className="mt-2 space-y-1 text-sm leading-6 text-brand-700 dark:text-brand-300">
                    <li className="text-xs text-brand-500 dark:text-brand-400">Starts at {path.entry_point}</li>
                    {hops.map((hop, index) => (
                        <li key={`${hop.source}-${hop.target}-${index}`} className="flex flex-wrap items-baseline gap-x-2">
                            <span>{hop.source} → {hop.target}</span>
                            <span className="text-xs text-brand-500 dark:text-brand-400">
                                {hop.protocol}
                                {hop.evidence_status === 'inferred' ? ' · assumed' : ''}
                            </span>
                        </li>
                    ))}
                </ol>
            ) : (
                <p className="mt-2 text-sm leading-6 text-brand-700 dark:text-brand-300">
                    {pathStatusNote[path.path_status] || `Reached directly at ${path.entry_point}.`}
                </p>
            )}
            {reached.length > 0 && (
                <p className="mt-2 text-sm leading-6 text-brand-700 dark:text-brand-300">
                    Onward reach: sensitive data held by {reached.join(', ')}.
                </p>
            )}
        </div>
    );
};

/**
 * One finding in full: why it was raised, what it touches, and what to do.
 *
 * The narrative and the evidence sit beside each other deliberately. A finding
 * an analyst cannot trace back to a line of the design is one they will not
 * act on, so the report never states a conclusion without showing its basis.
 */
export const ThreatCard = ({ threat, reviewState = 'open', onReviewStateChange }) => {
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
                            <EvidenceSources threat={threat} />
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
                            <FlowContext threat={threat} />
                            <AttackRoute threat={threat} />
                            <div>
                                <p className="text-xs font-semibold text-brand-600 dark:text-brand-400">Risk inputs</p>
                                <p className="mt-2 text-sm leading-6 text-brand-700 dark:text-brand-300">
                                    Exposure {threat.risk_factors?.exposure || threat.exposure || 'unspecified'}; evidence {threat.risk_factors?.evidence_confidence || threat.confidence}
                                    {typeof threat.risk_factors?.blast_radius === 'number' && (
                                        <>; reaches {threat.risk_factors.blast_radius} component{threat.risk_factors.blast_radius === 1 ? '' : 's'}</>
                                    )}
                                    {threat.risk_factors?.crosses_trust_boundary && <>; sits on a trust boundary</>}
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

/** Every finding at a glance, ordered by severity and risk score. */
export const ThreatSection = ({ threats, onSelectThreat }) => (
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

export const RiskDetailsModal = ({ threat, reviewState, onReviewStateChange, onClose }) => {
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
