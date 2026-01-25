import React from 'react';

const RiskMatrix = ({ threats }) => {
    // Initialize grid counts
    const matrix = {
        High: { High: 0, Medium: 0, Low: 0 },
        Medium: { High: 0, Medium: 0, Low: 0 },
        Low: { High: 0, Medium: 0, Low: 0 },
    };

    // Populate grid
    threats.forEach(t => {
        if (matrix[t.severity] && matrix[t.severity][t.likelihood]) {
            matrix[t.severity][t.likelihood]++;
        }
    });

    const getCellColor = (impact, likelihood) => {
        if (impact === 'Critical' || impact === 'High') {
            if (likelihood === 'High' || likelihood === 'Medium') return 'bg-red-500';
            return 'bg-orange-400';
        }
        if (impact === 'Medium') {
            if (likelihood === 'High') return 'bg-orange-400';
            return 'bg-yellow-400';
        }
        return 'bg-green-400';
    };

    // Helper to map severity to grid label
    const mapSeverity = (s) => s === 'Critical' ? 'High' : s;

    return (
        <div className="bg-white p-4 rounded-lg shadow border border-gray-200 mb-6 text-black w-full max-w-md mx-auto">
            <h3 className="text-lg font-bold mb-4 text-center">Risk Assessment Matrix</h3>
            <div className="relative">
                {/* Y-Axis Label */}
                <div className="absolute -left-8 top-1/2 -translate-y-1/2 -rotate-90 text-xs font-bold uppercase tracking-wider">
                    Impact
                </div>

                <div className="grid grid-cols-4 gap-1 text-sm">
                    {/* Header Row */}
                    <div className="font-bold"></div>
                    <div className="text-center font-bold bg-gray-100 p-1">Low</div>
                    <div className="text-center font-bold bg-gray-100 p-1">Medium</div>
                    <div className="text-center font-bold bg-gray-100 p-1">High</div>

                    {/* Rows */}
                    {['High', 'Medium', 'Low'].map((impact) => (
                        <React.Fragment key={impact}>
                            <div className="flex items-center justify-end pr-2 font-bold bg-gray-100">{impact}</div>
                            {['Low', 'Medium', 'High'].map((likelihood) => {
                                const count = matrix[impact][likelihood] || 0;
                                // Add Critical threats to High Impact for simplicity in 3x3
                                let displayCount = count;
                                if (impact === 'High') {
                                    // Also add Criticals here if likelihood matches
                                    threats.forEach(t => {
                                        if (t.severity === 'Critical' && t.likelihood === likelihood) displayCount++;
                                    });
                                }

                                return (
                                    <div key={`${impact}-${likelihood}`} className={`h-16 flex items-center justify-center border border-gray-300 font-bold text-lg ${getCellColor(impact, likelihood)} ${displayCount > 0 ? 'opacity-100' : 'opacity-30'}`}>
                                        {displayCount > 0 ? displayCount : ''}
                                    </div>
                                );
                            })}
                        </React.Fragment>
                    ))}
                </div>
                {/* X-Axis Label */}
                <div className="text-center text-xs font-bold uppercase tracking-wider mt-2">
                    Likelihood
                </div>
            </div>
            <div className="text-xs text-center mt-2 text-gray-500 italic">
                Numbers represent count of identified threats
            </div>
        </div>
    );
};

export default RiskMatrix;
