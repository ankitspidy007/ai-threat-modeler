import React, { useMemo, useState } from 'react';
import { Bot, Download, Layers3, ListTodo, MessageSquareQuote, Users } from 'lucide-react';
import { clsx } from 'clsx';
import { answerAnalysisQuestion } from '../utils/analysisCopilot';

const domainTone = {
  general: 'bg-brand-50 text-brand-700 dark:bg-brand-900/30 dark:text-brand-300',
  saas: 'bg-sky-50 text-sky-700 dark:bg-sky-900/30 dark:text-sky-300',
  fintech: 'bg-emerald-50 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300',
  healthcare: 'bg-rose-50 text-rose-700 dark:bg-rose-900/30 dark:text-rose-300',
  ai: 'bg-violet-50 text-violet-700 dark:bg-violet-900/30 dark:text-violet-300',
  platform: 'bg-amber-50 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300',
};

function downloadBlob(filename, content, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

export default function AnalystWorkbench({ data, projectName, reviewStates }) {
  const [question, setQuestion] = useState('');
  const [copilotAnswer, setCopilotAnswer] = useState(() => answerAnalysisQuestion('', data));
  const [owners, setOwners] = useState({});
  const [notes, setNotes] = useState({});
  const [componentNotes, setComponentNotes] = useState({});

  const actionRows = useMemo(() => {
    return (data.threats || []).slice(0, 8).map((threat) => ({
      id: threat.id,
      title: threat.title,
      severity: threat.severity,
      tier: threat.tier,
      owner: owners[threat.id] || '',
      note: notes[threat.id] || '',
      reviewState: reviewStates[threat.id] || 'open',
    }));
  }, [data.threats, notes, owners, reviewStates]);

  const askCopilot = () => {
    setCopilotAnswer(answerAnalysisQuestion(question, data));
  };

  const exportActionRegister = () => {
    const headers = ['ID', 'Title', 'Severity', 'Tier', 'Review State', 'Owner', 'Note'];
    const rows = actionRows.map((row) =>
      [row.id, row.title, row.severity, row.tier, row.reviewState, row.owner, row.note]
        .map((cell) => `"${String(cell || '').replace(/"/g, '""')}"`)
        .join(',')
    );
    downloadBlob(`${projectName.replace(/\s+/g, '_')}_action_register.csv`, [headers.join(','), ...rows].join('\n'), 'text/csv');
  };

  const exportActionBrief = () => {
    const lines = [
      `# ${projectName} Action Register`,
      '',
      `Domain: ${data.domain_context?.label || 'General'}`,
      '',
      ...actionRows.map((row) => [
        `## ${row.title}`,
        `- Severity: ${row.severity}`,
        `- Tier: ${row.tier}`,
        `- Review state: ${row.reviewState}`,
        `- Owner: ${row.owner || 'Unassigned'}`,
        `- Note: ${row.note || 'No note yet'}`,
        '',
      ].join('\n')),
    ];
    downloadBlob(`${projectName.replace(/\s+/g, '_')}_action_register.md`, lines.join('\n'), 'text/markdown');
  };

  return (
    <section className="mt-8 grid gap-6 xl:grid-cols-[1.05fr_0.95fr]">
      <div className="space-y-6">
        <div className="ui-panel p-6">
          <div className="flex items-center gap-2">
            <Bot className="h-5 w-5 text-brand-primary" />
            <h3 className="text-lg font-bold text-brand-950 dark:text-white">Threat modeling copilot</h3>
          </div>
          <p className="mt-2 text-sm leading-6 text-brand-600 dark:text-brand-400">
            Ask about priorities, auth risks, missing detail, or what changed. This lightweight copilot answers from the current analysis state.
          </p>
          <div className="mt-4 flex gap-3">
            <input
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
              placeholder="What should I fix first?"
              className="input-brand flex-1 text-sm"
            />
            <button onClick={askCopilot} className="btn-brand whitespace-nowrap">Ask</button>
          </div>
          <div className="ui-subpanel mt-4">
            <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-brand-500 dark:text-brand-400">{copilotAnswer.title}</p>
            <p className="mt-3 text-sm leading-7 text-brand-700 dark:text-brand-300">{copilotAnswer.answer}</p>
            {copilotAnswer.bullets?.length > 0 && (
              <ul className="mt-3 space-y-2 text-sm text-brand-700 dark:text-brand-300">
                {copilotAnswer.bullets.map((bullet, index) => (
                  <li key={index} className="rounded-lg border border-brand-200 bg-white px-3 py-2 dark:border-brand-700 dark:bg-brand-800/60">{bullet}</li>
                ))}
              </ul>
            )}
          </div>
        </div>

        <div className="ui-panel p-6">
          <div className="flex items-center gap-2">
            <Layers3 className="h-5 w-5 text-brand-primary" />
            <h3 className="text-lg font-bold text-brand-950 dark:text-white">Architecture workbench</h3>
          </div>
          <p className="mt-2 text-sm leading-6 text-brand-600 dark:text-brand-400">
            Review the parsed model directly. Add notes to components as you validate the generated architecture with teammates.
          </p>
          <div className="mt-4 grid gap-3">
            {(data.architecture?.components || []).slice(0, 8).map((component) => (
              <div key={component.id} className="ui-subpanel">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <p className="font-semibold text-brand-950 dark:text-white">{component.name}</p>
                    <p className="text-xs text-brand-500 dark:text-brand-400">{component.type}</p>
                  </div>
                  <span className={clsx('rounded-full px-2.5 py-1 text-[10px] font-semibold', domainTone[data.domain_context?.profile || 'general'])}>
                    {component.properties?.trust_boundary || 'internal'}
                  </span>
                </div>
                <textarea
                  value={componentNotes[component.id] || ''}
                  onChange={(e) => setComponentNotes((prev) => ({ ...prev, [component.id]: e.target.value }))}
                  placeholder="Validation note for this component..."
                  className="input-brand mt-3 h-20 w-full resize-none text-sm"
                />
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="space-y-6">
        <div className="ui-panel p-6">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <MessageSquareQuote className="h-5 w-5 text-brand-primary" />
              <h3 className="text-lg font-bold text-brand-950 dark:text-white">Domain lens</h3>
            </div>
            <span className={clsx('rounded-full px-3 py-1 text-xs font-semibold', domainTone[data.domain_context?.profile || 'general'])}>
              {data.domain_context?.label || 'General'}
            </span>
          </div>
          <p className="mt-3 text-sm leading-7 text-brand-700 dark:text-brand-300">
            {data.domain_context?.headline || 'No domain-specific context was attached to this run.'}
          </p>
          <div className="mt-4 grid gap-3 md:grid-cols-2">
            <div className="ui-subpanel">
              <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-brand-500 dark:text-brand-400">Priority controls</p>
              <ul className="mt-3 space-y-2 text-sm text-brand-700 dark:text-brand-300">
                {(data.domain_context?.priority_controls || []).map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </div>
            <div className="ui-subpanel">
              <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-brand-500 dark:text-brand-400">High-risk areas</p>
              <ul className="mt-3 space-y-2 text-sm text-brand-700 dark:text-brand-300">
                {(data.domain_context?.high_risk_areas || []).map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </div>
          </div>
        </div>

        <div className="ui-panel p-6">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <ListTodo className="h-5 w-5 text-brand-primary" />
              <h3 className="text-lg font-bold text-brand-950 dark:text-white">Action register</h3>
            </div>
            <div className="flex gap-2">
              <button onClick={exportActionRegister} className="ui-button-secondary px-3 py-2 text-xs">
                <span className="inline-flex items-center gap-1.5"><Download className="h-3.5 w-3.5" /> CSV</span>
              </button>
              <button onClick={exportActionBrief} className="ui-button-secondary px-3 py-2 text-xs">
                <span className="inline-flex items-center gap-1.5"><Download className="h-3.5 w-3.5" /> Brief</span>
              </button>
            </div>
          </div>
          <div className="mt-4 space-y-3">
            {actionRows.map((row) => (
              <div key={row.id} className="ui-subpanel">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <p className="font-semibold text-brand-950 dark:text-white">{row.title}</p>
                    <p className="text-xs text-brand-500 dark:text-brand-400">{row.severity} · {row.tier} · {row.reviewState}</p>
                  </div>
                  <Users className="h-4 w-4 text-brand-400" />
                </div>
                <div className="mt-3 grid gap-3 md:grid-cols-[0.7fr_1.3fr]">
                  <input
                    value={owners[row.id] || ''}
                    onChange={(e) => setOwners((prev) => ({ ...prev, [row.id]: e.target.value }))}
                    placeholder="Owner"
                    className="input-brand text-sm"
                  />
                  <input
                    value={notes[row.id] || ''}
                    onChange={(e) => setNotes((prev) => ({ ...prev, [row.id]: e.target.value }))}
                    placeholder="Action note or next step"
                    className="input-brand text-sm"
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
