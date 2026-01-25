import React, { useEffect, useRef } from 'react';
import { ShieldAlert, AlertTriangle, CheckCircle, Download, FileText, Share2, Code } from 'lucide-react';
import { generateReport } from '../utils/pdfGenerator';
import { clsx } from 'clsx';
import mermaid from 'mermaid';
import RiskMatrix from './RiskMatrix';

const SeverityBadge = ({ severity }) => {
    const colors = {
        Critical: 'bg-cyber-danger/20 text-cyber-danger border-cyber-danger',
        High: 'bg-orange-500/20 text-orange-400 border-orange-500',
        Medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500',
        Low: 'bg-blue-500/20 text-blue-400 border-blue-500',
    };

    return (
        <span className={clsx('px-2 py-1 rounded text-xs font-bold border', colors[severity] || colors.Low)}>
            {severity.toUpperCase()}
        </span>
    );
};

const ThreatDashboard = ({ data }) => {
    const mermaidRef = useRef(null);

    useEffect(() => {
        if (data?.diagram && mermaidRef.current) {
            mermaid.initialize({ startOnLoad: true, theme: 'dark' });
            mermaid.render('graphDiv', data.diagram).then((result) => {
                mermaidRef.current.innerHTML = result.svg;
            });
        }
    }, [data]);

    if (!data) return null;

    const downloadJSON = () => {
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'threat_model.json';
        a.click();
    };

    const downloadCSV = () => {
        const headers = ['ID', 'Severity', 'Likelihood', 'Category', 'Title', 'OWASP', 'NIST', 'Description', 'Mitigation'];
        const rows = data.threats.map(t => [
            t.id, t.severity, t.likelihood, t.category, t.title,
            t.compliance?.owasp || '', t.compliance?.nist || '',
            t.explanation, t.mitigation
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
                <h2 className="text-2xl font-bold flex items-center gap-2 text-white">
                    <ShieldAlert className="w-8 h-8 text-cyber-success" />
                    Threat Analysis Report
                </h2>
                <div className="flex gap-2">
                    <button onClick={downloadJSON} className="flex items-center gap-2 bg-cyber-800 hover:bg-cyber-700 text-white px-3 py-2 rounded border border-cyber-600 text-sm">
                        <Code className="w-4 h-4" /> JSON
                    </button>
                    <button onClick={downloadCSV} className="flex items-center gap-2 bg-cyber-800 hover:bg-cyber-700 text-white px-3 py-2 rounded border border-cyber-600 text-sm">
                        <Share2 className="w-4 h-4" /> CSV
                    </button>
                    <button
                        onClick={() => generateReport('report-content')}
                        className="flex items-center gap-2 bg-cyber-700 hover:bg-cyber-600 text-white px-4 py-2 rounded transition-colors border border-cyber-500"
                    >
                        <Download className="w-4 h-4" />
                        Export PDF
                    </button>
                </div>
            </div>

            <div id="report-content" className="space-y-6 p-6 bg-white text-black rounded-lg shadow-xl">
                {/* Header Info */}
                <div className="border-b-2 border-black pb-4 mb-6 flex justify-between items-end">
                    <div>
                        <div className="flex items-center gap-2 mb-2 text-cyber-700">
                            <FileText className="w-6 h-6" />
                            <h1 className="text-2xl font-bold uppercase tracking-wider">Analysis Summary</h1>
                        </div>
                        <p className="text-lg font-medium mb-1">{data.summary}</p>
                        <p className="text-xs text-gray-500">Generated at: {data.timestamp}</p>
                    </div>
                    <div className="text-right">
                        <h3 className="text-sm font-bold text-gray-400 uppercase">System Security Score</h3>
                        <div className="text-4xl font-black text-cyber-700">
                            {Math.max(0, 100 - (data.threats.length * 5))}/100
                        </div>
                    </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
                    {/* Risk Matrix */}
                    <div>
                        <RiskMatrix threats={data.threats} />
                    </div>

                    {/* Architecture Diagram */}
                    <div className="bg-gray-50 border border-gray-200 rounded p-4">
                        <h3 className="font-bold text-lg mb-2 text-center border-b pb-2">Inferred Architecture</h3>
                        <div ref={mermaidRef} className="flex justify-center items-center overflow-hidden"></div>
                    </div>
                </div>

                {/* Threats Table */}
                <h3 className="font-bold text-lg mb-2 border-b-2 border-black pb-1">Detailed Findings</h3>
                <div className="w-full overflow-x-auto">
                    <table className="w-full border-collapse border border-black text-sm">
                        <thead>
                            <tr className="bg-gray-800 text-white">
                                <th className="border border-black p-2 text-left w-24">Risk</th>
                                <th className="border border-black p-2 text-left w-48">Threat & Compliance</th>
                                <th className="border border-black p-2 text-left">Analysis & Simulation</th>
                                <th className="border border-black p-2 text-left w-64">Mitigation</th>
                            </tr>
                        </thead>
                        <tbody>
                            {data.threats.map((threat) => (
                                <tr key={threat.id} className="break-inside-avoid odd:bg-white even:bg-gray-50">
                                    <td className="border border-black p-2 align-top">
                                        <div className="flex flex-col gap-1">
                                            <SeverityBadge severity={threat.severity} />
                                            <div className="text-[10px] font-bold text-gray-500 uppercase mt-1">
                                                Likelihood: {threat.likelihood}
                                            </div>
                                        </div>
                                    </td>
                                    <td className="border border-black p-2 align-top">
                                        <div className="font-bold text-base">{threat.title}</div>
                                        <div className="text-xs text-gray-600 italic mb-2">{threat.category}</div>

                                        {threat.compliance && (
                                            <div className="flex flex-col gap-1 mt-2">
                                                {threat.compliance.owasp && (
                                                    <span className="inline-block bg-purple-100 text-purple-800 text-[10px] px-1 py-0.5 rounded border border-purple-200 font-mono">
                                                        OWASP: {threat.compliance.owasp}
                                                    </span>
                                                )}
                                                {threat.compliance.nist && (
                                                    <span className="inline-block bg-blue-100 text-blue-800 text-[10px] px-1 py-0.5 rounded border border-blue-200 font-mono">
                                                        NIST: {threat.compliance.nist}
                                                    </span>
                                                )}
                                            </div>
                                        )}
                                    </td>
                                    <td className="border border-black p-2 align-top">
                                        <div className="mb-3 text-gray-800">
                                            {threat.explanation}
                                        </div>

                                        <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-xs bg-gray-100 p-2 rounded mb-3 border border-gray-200">
                                            <div>
                                                <span className="font-bold block text-gray-700">Impact:</span>
                                                {threat.impact}
                                            </div>
                                            <div>
                                                <span className="font-bold block text-gray-700">Violated Assumption:</span>
                                                {threat.violatedAssumption}
                                            </div>
                                        </div>

                                        {threat.attackSimulation && (
                                            <div className="mt-2">
                                                <span className="font-bold text-xs uppercase tracking-wide text-red-700 block mb-1">Attack Vector:</span>
                                                <div className="space-y-1">
                                                    {threat.attackSimulation.map((step, i) => (
                                                        <div key={i} className="text-xs flex gap-2">
                                                            <span className="font-mono font-bold text-gray-500">{step.step}.</span>
                                                            <span>{step.action}</span>
                                                        </div>
                                                    ))}
                                                </div>
                                            </div>
                                        )}
                                    </td>
                                    <td className="border border-black p-2 align-top bg-green-50/50">
                                        <div className="flex items-start gap-2">
                                            <CheckCircle className="w-4 h-4 text-green-700 mt-0.5 shrink-0" />
                                            <p className="text-sm font-medium text-gray-800">{threat.mitigation}</p>
                                        </div>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
};

export default ThreatDashboard;
