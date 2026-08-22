import React, { useMemo, useState } from 'react';
import { Copy, Download, RefreshCw, Check, PencilLine, AlertTriangle } from 'lucide-react';

/**
 * Components in the draft that no flow row mentions.
 *
 * This reads the document rather than the parsed model, because the point is to
 * say something while the reviewer is still typing, before anything is parsed.
 * It is deliberately literal: a row label or a component name appearing
 * anywhere in the flow table counts as reached.
 */
function unconnectedComponents(document) {
  const rows = document.split('\n').filter((line) => /^Row \d+:/.test(line));
  const components = [];
  let flowText = '';

  for (const row of rows) {
    const cells = row.replace(/^Row \d+:\s*/, '').split('|').map((cell) => cell.trim());
    const [label, name] = cells;
    if (/^C\d+$/i.test(label) && name) {
      components.push({ label: label.toLowerCase(), name });
    } else if (/^F\d+$/i.test(label)) {
      flowText += ` ${cells.slice(1).join(' ')} `;
    }
  }

  const reached = flowText.toLowerCase();
  return components
    .filter(({ label, name }) => {
      const byLabel = new RegExp(`\\b${label}\\b`).test(reached);
      const byName = name.length > 2 && reached.includes(name.toLowerCase());
      return !byLabel && !byName;
    })
    .map(({ name }) => name);
}

/**
 * The analyzed model, in the format the analyzer reads back.
 *
 * A reviewer who spots a missing component would otherwise have to return to the
 * original description and re-run everything, hoping the extractor made the same
 * choices twice. Editing the model directly avoids that: the structured format
 * is parsed without inference, so correcting one row leaves the rest of the
 * model exactly where it was.
 */
export default function ArchitectureModelEditor({ document: initialDocument, onReanalyze, isAnalyzing }) {
  const [draft, setDraft] = useState(initialDocument || '');
  const [copied, setCopied] = useState(false);
  // A re-analysis returns a fresh model, and the editor has to show it rather
  // than the draft it replaced. Adjusting during render instead of in an effect
  // avoids rendering once with the stale draft and then again with the new one.
  const [loadedDocument, setLoadedDocument] = useState(initialDocument);
  if (initialDocument !== loadedDocument) {
    setLoadedDocument(initialDocument);
    setDraft(initialDocument || '');
  }

  const edited = draft !== (initialDocument || '');

  const counts = useMemo(() => {
    const rows = draft.split('\n').filter((line) => /^Row \d+:/.test(line));
    const tables = draft.split('\n').filter((line) => /^\[Table \d+\]/.test(line)).length;
    return { rows: Math.max(rows.length - tables, 0), tables };
  }, [draft]);

  // Adding a component without adding its flows is the common way an amendment
  // does nothing: the threats are on the paths, so an unreachable component is
  // barely assessed. Worth saying before a minute is spent on the analysis
  // rather than after.
  const unconnected = useMemo(() => unconnectedComponents(draft), [draft]);

  if (!initialDocument) return null;

  const handleCopy = async () => {
    await navigator.clipboard.writeText(draft);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([draft], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const link = window.document.createElement('a');
    link.href = url;
    link.download = 'architecture-model.txt';
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="panel-soft px-6 py-5">
      <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="mb-1 inline-flex items-center gap-2 text-sm font-semibold text-brand-950 dark:text-white">
            <PencilLine className="h-4 w-4 text-brand-primary" />
            Architecture model
          </div>
          <p className="max-w-2xl text-xs leading-5 text-brand-600 dark:text-brand-400">
            This is the model the analysis ran against. Add a row for anything that was
            missed and re-analyze — you do not need to rewrite the description. Ids are
            labels only, so appending is safe.
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <button onClick={handleCopy} className="ui-button-secondary h-9 px-3" title="Copy to clipboard">
            {copied ? <Check className="h-3.5 w-3.5 text-brand-success" /> : <Copy className="h-3.5 w-3.5" />}
            <span className="hidden sm:inline">{copied ? 'Copied' : 'Copy'}</span>
          </button>
          <button onClick={handleDownload} className="ui-button-secondary h-9 px-3" title="Download as a text file">
            <Download className="h-3.5 w-3.5" />
            <span className="hidden sm:inline">Download</span>
          </button>
          <button
            onClick={() => onReanalyze(draft)}
            disabled={!edited || isAnalyzing}
            className="ui-button-primary h-9 px-3 disabled:cursor-not-allowed disabled:opacity-50"
            title={edited ? 'Re-run the analysis against the edited model' : 'Edit the model to re-analyze'}
          >
            <RefreshCw className={`h-3.5 w-3.5 ${isAnalyzing ? 'animate-spin' : ''}`} />
            <span className="hidden sm:inline">{isAnalyzing ? 'Analyzing' : 'Re-analyze'}</span>
          </button>
        </div>
      </div>

      <textarea
        value={draft}
        onChange={(event) => setDraft(event.target.value)}
        spellCheck={false}
        rows={18}
        className="ui-input w-full resize-y whitespace-pre font-mono text-xs leading-5"
        aria-label="Architecture model, editable"
      />

      <div className="mt-2 flex flex-wrap items-center justify-between gap-2 text-xs text-brand-500 dark:text-brand-400">
        <span className="font-mono">
          {counts.tables} tables · {counts.rows} rows
        </span>
        {edited && <span className="text-brand-primary">Edited — re-analyze to apply</span>}
      </div>

      {unconnected.length > 0 && (
        <div className="mt-3 flex items-start gap-2 rounded-lg border border-brand-warning/40 bg-brand-warning/10 px-3 py-2">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-brand-warning" />
          <p className="text-xs leading-5 text-brand-700 dark:text-brand-300">
            No flow reaches <span className="font-semibold">{unconnected.join(', ')}</span>. Most
            risk is found on the paths between components, so add a row to the flow table saying
            what talks to {unconnected.length === 1 ? 'it' : 'them'} and what data it carries —
            otherwise the analysis will have little to say about
            {unconnected.length === 1 ? ' it' : ' them'}.
          </p>
        </div>
      )}
    </div>
  );
}
