import React, { useEffect, useRef } from 'react';
import { ShieldAlert, AlertTriangle, CheckCircle, Download, FileText, Share2, Code } from 'lucide-react';
import { generateReport } from '../utils/pdfGenerator';
import { clsx } from 'clsx';
import mermaid from 'mermaid';
import RiskMatrix from './RiskMatrix';

const SeverityBadge = ({ severity }) => {
    const colors = {
        Critical: 'bg-red-50 text-red-600 border-red-500',
        High: 'bg-orange-50 text-orange-600 border-orange-500',
        Medium: 'bg-yellow-50 text-yellow-600 border-yellow-500',
        Low: 'bg-blue-50 text-blue-600 border-blue-500',
    };

    return (
        <span className={clsx('px-2 py-1 rounded text-xs font-bold border', colors[severity] || colors.Low)}>
            {severity?.toUpperCase()}
        </span>
    );
};

const ThreatCard = ({ threat }) => (
    <div className="bg-white border border-brand-200 rounded-lg p-4 shadow-sm">
        <div className="flex justify-between items-start mb-2">
            <div>
                <div className="flex items-center gap-2 mb-1 flex-wrap">
                    <SeverityBadge severity={threat.severity} />
                    <span className={clsx(
                        'px-2 py-0.5 rounded text-[10px] font-bold',
                        threat.tier === 'Confirmed' ? 'bg-green-100 text-green-700' : 'bg-yellow-100 text-yellow-700'
                    )}>
                        {threat.tier}
                    </span>
                    <span className="text-xs text-brand-500">Confidence: {threat.confidence}</span>
                </div>
                <h4 className="font-bold text-brand-900">{threat.title}</h4>
                <div className="text-xs text-brand-500">
                    {threat.category}
                    {threat.stride_category && threat.stride_category !== threat.category && ` → ${threat.stride_category}`}
                </div>
            </div>
        </div>

        <p className="text-sm text-brand-700 mb-3">{threat.description}</p>

        {/* Aggregated Affected Components */}
        {threat.affected_components && threat.affected_components.length > 0 && (
            <div className="text-xs mb-2">
                <span className="font-bold text-brand-600">Affected Components: </span>
                <span className="text-brand-800">{threat.affected_components.join(', ')}</span>
            </div>
        )}

        {threat.affected_data_flows && threat.affected_data_flows.length > 0 && (
            <div className="text-xs mb-2">
                <span className="font-bold text-brand-600">Affected Data Flows: </span>
                <span className="text-brand-800">{threat.affected_data_flows.join(', ')}</span>
            </div>
        )}

        {/* Evidence */}
        {threat.evidence && threat.evidence.length > 0 && (
            <div className="bg-brand-50 p-2 rounded text-xs mb-3">
                <span className="font-bold text-brand-600">Evidence:</span>
                <ul className="list-disc list-inside mt-1">
                    {threat.evidence.map((ev, i) => <li key={i} className="text-brand-700">{ev}</li>)}
                </ul>
            </div>
        )}

        <div className="flex items-start gap-2 bg-green-50 p-2 rounded">
            <CheckCircle className="w-4 h-4 text-green-600 mt-0.5 shrink-0" />
            <p className="text-sm text-green-800">{threat.mitigation}</p>
        </div>
    </div>
);

const ThreatDashboard = ({ data, projectName }) => {
    const mermaidRef = useRef(null);

    useEffect(() => {
        if (data?.diagram && mermaidRef.current) {
            mermaid.initialize({ startOnLoad: true, theme: 'default' });
            mermaid.render('graphDiv', data.diagram).then((result) => {
                mermaidRef.current.innerHTML = result.svg;
            });
        }
    }, [data]);

    if (!data) return null;

    // Separate threats by tier
    const confirmed = data.threats?.filter(t => t.tier === 'Confirmed') || [];
    const potential = data.threats?.filter(t => t.tier === 'Potential') || [];

    const downloadJSON = () => {
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'threat_model.json';
        a.click();
    };

    const downloadCSV = () => {
        const headers = ['ID', 'Tier', 'Severity', 'Confidence', 'Category', 'Title', 'Description', 'Mitigation'];
        const rows = data.threats.map(t => [
            t.id, t.tier, t.severity, t.confidence, t.category, t.title, t.description, t.mitigation
        ].map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(','));

        const csv = [headers.join(','), ...rows].join('\n');
        const blob = new Blob([csv], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'threat_model.csv';
        a.click();
    };

    return (
        <div className="w-full max-w-6xl mx-auto animate-fade-in pb-20">
            <div className="flex justify-between items-center mb-6">
                <h2 className="text-2xl font-bold flex items-center gap-2 text-brand-900">
                    <ShieldAlert className="w-8 h-8 text-brand-success" />
                    Threat Analysis Report
                </h2>
                <div className="flex gap-2">
                    <button onClick={downloadJSON} className="flex items-center gap-2 bg-white hover:bg-brand-50 text-brand-700 px-3 py-2 rounded border border-brand-200 text-sm transition-colors shadow-sm">
                        <Code className="w-4 h-4" /> JSON
                    </button>
                    <button onClick={downloadCSV} className="flex items-center gap-2 bg-white hover:bg-brand-50 text-brand-700 px-3 py-2 rounded border border-brand-200 text-sm transition-colors shadow-sm">
                        <Share2 className="w-4 h-4" /> CSV
                    </button>
                    {data.report_markdown && (
                        <button
                            onClick={() => {
                                const blob = new Blob([data.report_markdown], { type: 'text/markdown' });
                                const url = URL.createObjectURL(blob);
                                const a = document.createElement('a');
                                a.href = url;
                                a.download = `${projectName.replace(/\s+/g, '_')}_Threat_Report.md`;
                                a.click();
                            }}
                            className="flex items-center gap-2 bg-purple-50 hover:bg-purple-100 text-purple-700 px-3 py-2 rounded border border-purple-200 text-sm transition-colors shadow-sm"
                        >
                            <FileText className="w-4 h-4" /> MD
                        </button>
                    )}
                    <button
                        onClick={() => generateReport(data, projectName)}
                        className="flex items-center gap-2 bg-brand-primary hover:bg-brand-primary/90 text-white px-4 py-2 rounded transition-colors shadow-md"
                    >
                        <Download className="w-4 h-4" />
                        Export PDF
                    </button>
                </div>
            </div>

            <div id="report-content" className="space-y-6 p-8 bg-white text-brand-900 rounded-xl shadow-lg border border-brand-100">
                {/* Header Info */}
                <div className="border-b-2 border-brand-100 pb-4 mb-6 flex justify-between items-end">
                    <div>
                        <div className="flex items-center gap-2 mb-2 text-brand-primary">
                            <FileText className="w-6 h-6" />
                            <h1 className="text-2xl font-bold uppercase tracking-wider">Analysis Summary</h1>
                        </div>
                        <h2 className="text-xl font-bold text-brand-900 mb-2">{projectName}</h2>
                        <p className="text-lg font-medium mb-1 text-brand-700">{data.summary}</p>
                        <p className="text-xs text-brand-400">Generated at: {data.timestamp || new Date().toLocaleString()}</p>
                    </div>
                    <div className="text-right">
                        <h3 className="text-sm font-bold text-brand-400 uppercase">Security Score</h3>
                        <div className={clsx(
                            "text-4xl font-black",
                            data.score >= 70 ? "text-green-600" : data.score >= 40 ? "text-yellow-600" : "text-red-600"
                        )}>
                            {data.score}/100
                        </div>
                        <div className="text-xs text-brand-500">
                            {confirmed.length} confirmed, {potential.length} potential
                        </div>
                    </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
                    {/* Risk Matrix */}
                    <div>
                        <RiskMatrix threats={data.threats} />
                    </div>

                    {/* Architecture Diagram */}
                    <div className="bg-brand-50 border border-brand-200 rounded-lg p-4">
                        <h3 className="font-bold text-lg mb-2 text-center border-b border-brand-200 pb-2 text-brand-800">Inferred Architecture</h3>
                        <div ref={mermaidRef} className="flex justify-center items-center overflow-hidden"></div>
                    </div>
                </div>

                {/* TWO-TIER OUTPUT */}
                <div className="mb-8">
                    <h3 className="font-bold text-lg mb-4 border-b-2 border-green-600 pb-1 text-green-700 flex items-center gap-2">
                        <CheckCircle className="w-5 h-5" />
                        Confirmed Risks ({confirmed.length})
                    </h3>
                    {confirmed.length === 0 ? (
                        <p className="text-brand-500 italic p-4">No confirmed risks detected.</p>
                    ) : (
                        <div className="space-y-4">
                            {confirmed.map(threat => (
                                <ThreatCard key={threat.id} threat={threat} />
                            ))}
                        </div>
                    )}
                </div>

                <div className="mb-8">
                    <h3 className="font-bold text-lg mb-4 border-b-2 border-yellow-500 pb-1 text-yellow-700 flex items-center gap-2">
                        <AlertTriangle className="w-5 h-5" />
                        Potential Risks ({potential.length})
                    </h3>
                    {potential.length === 0 ? (
                        <p className="text-brand-500 italic p-4">No potential risks detected.</p>
                    ) : (
                        <div className="space-y-4">
                            {potential.map(threat => (
                                <ThreatCard key={threat.id} threat={threat} />
                            ))}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default ThreatDashboard;
