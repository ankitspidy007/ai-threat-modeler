import React, { useState } from 'react';

const RiskMatrix = ({ threats, onCellClick }) => {
    const [hoveredCell, setHoveredCell] = useState(null);

    // Initialize grid counts
    const matrix = {
        High: { High: 0, Medium: 0, Low: 0 },
        Medium: { High: 0, Medium: 0, Low: 0 },
        Low: { High: 0, Medium: 0, Low: 0 },
    };

    // Track threat titles per cell for tooltips
    const cellThreats = {};

    // Populate grid
    threats.forEach(t => {
        const sev = t.severity === 'Critical' ? 'High' : t.severity;
        const lik = t.likelihood || 'Medium';
        if (matrix[sev] && matrix[sev][lik]) {
            matrix[sev][lik]++;
        }
        const key = `${sev}-${lik}`;
        if (!cellThreats[key]) cellThreats[key] = [];
        cellThreats[key].push(t.title);
    });

    const getCellColor = (impact, likelihood) => {
        if (impact === 'High') {
            if (likelihood === 'High') return 'bg-red-500 dark:bg-red-600';
            if (likelihood === 'Medium') return 'bg-red-400 dark:bg-red-500';
            return 'bg-orange-400 dark:bg-orange-500';
        }
        if (impact === 'Medium') {
            if (likelihood === 'High') return 'bg-orange-400 dark:bg-orange-500';
            if (likelihood === 'Medium') return 'bg-yellow-400 dark:bg-yellow-500';
            return 'bg-yellow-300 dark:bg-yellow-400';
        }
        return 'bg-green-400 dark:bg-green-500';
    };

    const handleClick = (impact, likelihood) => {
        if (onCellClick) {
            onCellClick(impact, likelihood);
        }
    };

    return (
        <div className="mb-6 w-full max-w-md rounded-lg border border-brand-200 bg-white p-4 text-black shadow-sm dark:border-brand-700 dark:bg-brand-800 dark:text-white">
            <h3 className="mb-4 text-center text-lg font-semibold">Risk Assessment Matrix</h3>
            <div className="relative">
                {/* Y-Axis Label */}
                <div className="absolute -left-8 top-1/2 -translate-y-1/2 -rotate-90 text-xs font-bold uppercase tracking-wider text-brand-600 dark:text-brand-400">
                    Impact
                </div>

                <div className="grid grid-cols-4 gap-1 text-sm">
                    {/* Header Row */}
                    <div className="font-bold"></div>
                    <div className="rounded-sm bg-brand-100 p-1 text-center font-semibold dark:bg-brand-700">Low</div>
                    <div className="rounded-sm bg-brand-100 p-1 text-center font-semibold dark:bg-brand-700">Medium</div>
                    <div className="rounded-sm bg-brand-100 p-1 text-center font-semibold dark:bg-brand-700">High</div>

                    {/* Rows */}
                    {['High', 'Medium', 'Low'].map((impact) => (
                        <React.Fragment key={impact}>
                            <div className="flex items-center justify-end rounded-sm bg-brand-100 pr-2 font-semibold dark:bg-brand-700">{impact}</div>
                            {['Low', 'Medium', 'High'].map((likelihood) => {
                                const displayCount = matrix[impact]?.[likelihood] || 0;
                                const cellKey = `${impact}-${likelihood}`;
                                const isHovered = hoveredCell === cellKey;

                                return (
                                    <div
                                        key={cellKey}
                                        className={`h-16 flex items-center justify-center border border-gray-300 dark:border-brand-600 font-bold text-lg rounded-sm
                                            ${getCellColor(impact, likelihood)}
                                            ${displayCount > 0 ? 'opacity-100 cursor-pointer hover:scale-105 hover:shadow-md' : 'opacity-30'}
                                            ${isHovered ? 'ring-2 ring-brand-primary' : ''}
                                            transition-all duration-200`}
                                        onClick={() => displayCount > 0 && handleClick(impact, likelihood)}
                                        onMouseEnter={() => setHoveredCell(cellKey)}
                                        onMouseLeave={() => setHoveredCell(null)}
                                        title={cellThreats[cellKey]?.join('\n') || ''}
                                    >
                                        {displayCount > 0 ? displayCount : ''}
                                    </div>
                                );
                            })}
                        </React.Fragment>
                    ))}
                </div>
                {/* X-Axis Label */}
                <div className="text-center text-xs font-bold uppercase tracking-wider mt-2 text-brand-600 dark:text-brand-400">
                    Likelihood
                </div>
            </div>
            <div className="text-xs text-center mt-2 text-gray-500 dark:text-brand-400 italic">
                {onCellClick ? 'Click a cell to filter threats' : 'Numbers represent count of identified threats'}
            </div>
        </div>
    );
};

export default RiskMatrix;
