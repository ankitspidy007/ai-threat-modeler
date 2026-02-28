import React, { useState } from 'react';
import { Clock, Trash2, Eye, GitCompare, X, ArrowUpRight, ArrowDownRight, Minus } from 'lucide-react';
import { loadAnalyses, deleteAnalysis, clearAllAnalyses } from '../utils/storage';
import { useToast } from './Toast';

const AnalysisHistory = ({ onLoadAnalysis }) => {
    const [analyses, setAnalyses] = useState(() => loadAnalyses());
    const [compareMode, setCompareMode] = useState(false);
    const [selectedForCompare, setSelectedForCompare] = useState([]);
    const [comparison, setComparison] = useState(null);
    const toast = useToast();

    const refresh = () => setAnalyses(loadAnalyses());

    const handleDelete = (id) => {
        deleteAnalysis(id);
        refresh();
        toast.success('Analysis deleted');
    };

    const handleClearAll = () => {
        if (window.confirm('Delete all saved analyses? This cannot be undone.')) {
            clearAllAnalyses();
            refresh();
            toast.success('All analyses cleared');
        }
    };

    const handleLoad = (analysis) => {
        onLoadAnalysis(analysis.data, analysis.projectName);
    };

    const toggleCompareSelect = (analysis) => {
        if (selectedForCompare.find(a => a.id === analysis.id)) {
            setSelectedForCompare(selectedForCompare.filter(a => a.id !== analysis.id));
        } else if (selectedForCompare.length < 2) {
            setSelectedForCompare([...selectedForCompare, analysis]);
        }
    };

    const runComparison = () => {
        if (selectedForCompare.length !== 2) return;
        const [older, newer] = selectedForCompare.sort((a, b) => a.id - b.id);

        const olderThreats = older.data?.threats || [];
        const newerThreats = newer.data?.threats || [];

        const olderTitles = new Set(olderThreats.map(t => t.title));
        const newerTitles = new Set(newerThreats.map(t => t.title));

        const newThreats = newerThreats.filter(t => !olderTitles.has(t.title));
        const resolvedThreats = olderThreats.filter(t => !newerTitles.has(t.title));
        const persistentThreats = newerThreats.filter(t => olderTitles.has(t.title));

        setComparison({
            older: { name: older.projectName, date: older.timestamp, score: older.data?.score, threatCount: olderThreats.length },
            newer: { name: newer.projectName, date: newer.timestamp, score: newer.data?.score, threatCount: newerThreats.length },
            newThreats,
            resolvedThreats,
            persistentThreats,
            scoreDelta: (newer.data?.score || 0) - (older.data?.score || 0),
        });
    };

    const formatDate = (ts) => {
        try {
            return new Date(ts).toLocaleString();
        } catch {
            return ts;
        }
    };

    if (comparison) {
        return (
            <div className="w-full max-w-4xl mx-auto animate-fade-in-up">
                <div className="flex items-center justify-between mb-6">
                    <h2 className="text-2xl font-bold dark:text-white">Analysis Comparison</h2>
                    <button onClick={() => { setComparison(null); setSelectedForCompare([]); setCompareMode(false); }}
                        className="text-brand-500 hover:text-brand-700 dark:hover:text-brand-300 flex items-center gap-1">
                        <X className="w-4 h-4" /> Close
                    </button>
                </div>

                {/* Score comparison */}
                <div className="grid grid-cols-2 gap-4 mb-6">
                    <div className="bg-white dark:bg-brand-800 border border-brand-200 dark:border-brand-700 rounded-lg p-4">
                        <div className="text-xs text-brand-500 font-mono mb-1">OLDER</div>
                        <div className="font-bold dark:text-white">{comparison.older.name}</div>
                        <div className="text-sm text-brand-500">{formatDate(comparison.older.date)}</div>
                        <div className="mt-2 text-2xl font-bold text-brand-primary">{comparison.older.score}/100</div>
                        <div className="text-sm text-brand-600 dark:text-brand-400">{comparison.older.threatCount} threats</div>
                    </div>
                    <div className="bg-white dark:bg-brand-800 border border-brand-200 dark:border-brand-700 rounded-lg p-4">
                        <div className="text-xs text-brand-500 font-mono mb-1">NEWER</div>
                        <div className="font-bold dark:text-white">{comparison.newer.name}</div>
                        <div className="text-sm text-brand-500">{formatDate(comparison.newer.date)}</div>
                        <div className="mt-2 text-2xl font-bold text-brand-primary">{comparison.newer.score}/100</div>
                        <div className="text-sm text-brand-600 dark:text-brand-400">{comparison.newer.threatCount} threats</div>
                    </div>
                </div>

                {/* Score delta */}
                <div className={`flex items-center justify-center gap-2 p-3 rounded-lg mb-6 ${comparison.scoreDelta > 0 ? 'bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-400'
                    : comparison.scoreDelta < 0 ? 'bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-400'
                        : 'bg-gray-50 dark:bg-brand-700 text-brand-600 dark:text-brand-300'}`}>
                    {comparison.scoreDelta > 0 ? <ArrowUpRight className="w-5 h-5" /> :
                        comparison.scoreDelta < 0 ? <ArrowDownRight className="w-5 h-5" /> :
                            <Minus className="w-5 h-5" />}
                    <span className="font-bold text-lg">Score {comparison.scoreDelta > 0 ? '+' : ''}{comparison.scoreDelta} points</span>
                </div>

                {/* New threats */}
                {comparison.newThreats.length > 0 && (
                    <div className="mb-4">
                        <h3 className="font-bold text-red-600 dark:text-red-400 mb-2">🆕 New Threats ({comparison.newThreats.length})</h3>
                        <div className="space-y-1">
                            {comparison.newThreats.map((t, i) => (
                                <div key={i} className="text-sm p-2 bg-red-50 dark:bg-red-900/20 rounded border-l-3 border-red-500 dark:text-brand-300">
                                    <span className="font-mono text-xs bg-red-100 dark:bg-red-800 px-1 rounded mr-2">{t.severity}</span>
                                    {t.title}
                                </div>
                            ))}
                        </div>
                    </div>
                )}

                {/* Resolved threats */}
                {comparison.resolvedThreats.length > 0 && (
                    <div className="mb-4">
                        <h3 className="font-bold text-green-600 dark:text-green-400 mb-2">✅ Resolved Threats ({comparison.resolvedThreats.length})</h3>
                        <div className="space-y-1">
                            {comparison.resolvedThreats.map((t, i) => (
                                <div key={i} className="text-sm p-2 bg-green-50 dark:bg-green-900/20 rounded border-l-3 border-green-500 dark:text-brand-300 line-through opacity-75">
                                    <span className="font-mono text-xs bg-green-100 dark:bg-green-800 px-1 rounded mr-2 no-underline">{t.severity}</span>
                                    {t.title}
                                </div>
                            ))}
                        </div>
                    </div>
                )}

                {/* Persistent threats */}
                {comparison.persistentThreats.length > 0 && (
                    <div>
                        <h3 className="font-bold text-brand-600 dark:text-brand-400 mb-2">🔄 Persistent Threats ({comparison.persistentThreats.length})</h3>
                        <div className="space-y-1">
                            {comparison.persistentThreats.map((t, i) => (
                                <div key={i} className="text-sm p-2 bg-brand-50 dark:bg-brand-700 rounded dark:text-brand-300">
                                    <span className="font-mono text-xs bg-brand-100 dark:bg-brand-600 px-1 rounded mr-2">{t.severity}</span>
                                    {t.title}
                                </div>
                            ))}
                        </div>
                    </div>
                )}
            </div>
        );
    }

    return (
        <div className="w-full max-w-4xl mx-auto">
            <div className="text-center mb-8">
                <h2 className="text-3xl font-bold text-brand-900 dark:text-white mb-2">Analysis History</h2>
                <p className="text-brand-600 dark:text-brand-400">Browse, load, or compare your past threat analyses</p>
            </div>

            {analyses.length === 0 ? (
                <div className="text-center py-16 text-brand-500 dark:text-brand-400">
                    <Clock className="w-12 h-12 mx-auto mb-3 opacity-40" />
                    <p className="text-lg">No saved analyses yet</p>
                    <p className="text-sm">Run your first analysis to see it here</p>
                </div>
            ) : (
                <>
                    <div className="flex items-center justify-between mb-4">
                        <span className="text-sm text-brand-500 dark:text-brand-400">{analyses.length} saved analyses</span>
                        <div className="flex gap-2">
                            <button
                                onClick={() => { setCompareMode(!compareMode); setSelectedForCompare([]); }}
                                className={`text-sm px-3 py-1.5 rounded-lg border transition-all flex items-center gap-1 ${compareMode
                                    ? 'bg-purple-50 dark:bg-purple-900/30 border-purple-300 dark:border-purple-700 text-purple-700 dark:text-purple-400'
                                    : 'border-brand-300 dark:border-brand-600 text-brand-600 dark:text-brand-300 hover:bg-brand-50 dark:hover:bg-brand-700'}`}
                            >
                                <GitCompare className="w-3.5 h-3.5" />
                                {compareMode ? 'Cancel Compare' : 'Compare'}
                            </button>
                            <button onClick={handleClearAll}
                                className="text-sm px-3 py-1.5 rounded-lg border border-red-200 dark:border-red-800 text-red-500 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20">
                                Clear All
                            </button>
                        </div>
                    </div>

                    {compareMode && (
                        <div className="mb-4 p-3 bg-purple-50 dark:bg-purple-900/20 border border-purple-200 dark:border-purple-800 rounded-lg text-sm text-purple-700 dark:text-purple-300 flex items-center justify-between">
                            <span>Select 2 analyses to compare ({selectedForCompare.length}/2 selected)</span>
                            {selectedForCompare.length === 2 && (
                                <button onClick={runComparison}
                                    className="px-3 py-1 bg-purple-600 text-white rounded-lg hover:bg-purple-700 font-bold">
                                    Compare Now
                                </button>
                            )}
                        </div>
                    )}

                    <div className="space-y-3">
                        {[...analyses].reverse().map((analysis) => {
                            const isSelected = selectedForCompare.find(a => a.id === analysis.id);
                            return (
                                <div
                                    key={analysis.id}
                                    className={`bg-white dark:bg-brand-800 border rounded-lg p-4 shadow-sm transition-all ${compareMode
                                        ? isSelected
                                            ? 'border-purple-400 dark:border-purple-600 ring-2 ring-purple-200 dark:ring-purple-800'
                                            : 'border-brand-200 dark:border-brand-700 cursor-pointer hover:border-purple-300 dark:hover:border-purple-600'
                                        : 'border-brand-200 dark:border-brand-700 hover:shadow-md'}`}
                                    onClick={compareMode ? () => toggleCompareSelect(analysis) : undefined}
                                >
                                    <div className="flex items-center justify-between">
                                        <div>
                                            <h3 className="font-bold text-brand-900 dark:text-white">{analysis.projectName}</h3>
                                            <div className="flex items-center gap-3 mt-1 text-sm text-brand-500 dark:text-brand-400">
                                                <span className="flex items-center gap-1">
                                                    <Clock className="w-3.5 h-3.5" />
                                                    {formatDate(analysis.timestamp)}
                                                </span>
                                                {analysis.data?.threats && (
                                                    <span className="font-mono">{analysis.data.threats.length} threats</span>
                                                )}
                                                {analysis.data?.score !== undefined && (
                                                    <span className="font-mono font-bold text-brand-primary">Score: {analysis.data.score}</span>
                                                )}
                                            </div>
                                        </div>
                                        {!compareMode && (
                                            <div className="flex items-center gap-2">
                                                <button onClick={() => handleLoad(analysis)}
                                                    className="p-2 rounded-lg hover:bg-brand-100 dark:hover:bg-brand-700 text-brand-primary" title="Load analysis">
                                                    <Eye className="w-4 h-4" />
                                                </button>
                                                <button onClick={(e) => { e.stopPropagation(); handleDelete(analysis.id); }}
                                                    className="p-2 rounded-lg hover:bg-red-50 dark:hover:bg-red-900/20 text-red-400 hover:text-red-600" title="Delete">
                                                    <Trash2 className="w-4 h-4" />
                                                </button>
                                            </div>
                                        )}
                                        {compareMode && (
                                            <div className={`w-5 h-5 rounded-full border-2 flex items-center justify-center ${isSelected ? 'bg-purple-600 border-purple-600' : 'border-brand-300 dark:border-brand-600'}`}>
                                                {isSelected && <span className="text-white text-xs">✓</span>}
                                            </div>
                                        )}
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                </>
            )}
        </div>
    );
};

export default AnalysisHistory;
