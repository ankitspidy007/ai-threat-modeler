import React from 'react';

const STRIDE_CATEGORIES = [
    { key: 'Spoofing', color: '#ef4444', label: 'S' },
    { key: 'Tampering', color: '#f97316', label: 'T' },
    { key: 'Repudiation', color: '#eab308', label: 'R' },
    { key: 'Information Disclosure', color: '#3b82f6', label: 'I' },
    { key: 'Denial of Service', color: '#8b5cf6', label: 'D' },
    { key: 'Elevation of Privilege', color: '#ec4899', label: 'E' },
];

const StrideChart = ({ threats }) => {
    // Count threats per STRIDE category
    const counts = {};
    let total = 0;
    STRIDE_CATEGORIES.forEach(c => { counts[c.key] = 0; });

    threats.forEach(t => {
        const cat = t.stride_category || t.category;
        if (counts[cat] !== undefined) {
            counts[cat]++;
            total++;
        } else {
            // Try to match partial
            const match = STRIDE_CATEGORIES.find(c =>
                cat?.toLowerCase().includes(c.key.toLowerCase().split(' ')[0])
            );
            if (match) {
                counts[match.key]++;
                total++;
            }
        }
    });

    if (total === 0) return null;

    // Build donut chart using SVG
    const size = 180;
    const cx = size / 2;
    const cy = size / 2;
    const radius = 70;
    const strokeWidth = 28;
    const circumference = 2 * Math.PI * radius;

    let cumulativePercent = 0;
    const segments = STRIDE_CATEGORIES.filter(c => counts[c.key] > 0).map(c => {
        const percent = counts[c.key] / total;
        const offset = cumulativePercent * circumference;
        const length = percent * circumference;
        cumulativePercent += percent;
        return { ...c, percent, offset, length, count: counts[c.key] };
    });

    return (
        <div className="mb-6 w-full max-w-md rounded-lg border border-brand-200 bg-white p-4 shadow-sm dark:border-brand-700 dark:bg-brand-800">
            <h3 className="mb-4 text-center text-lg font-semibold dark:text-white">STRIDE Distribution</h3>
            <div className="flex flex-col items-center gap-4">
                <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
                    {segments.map((seg) => (
                        <circle
                            key={seg.key}
                            cx={cx}
                            cy={cy}
                            r={radius}
                            fill="none"
                            stroke={seg.color}
                            strokeWidth={strokeWidth}
                            strokeDasharray={`${seg.length} ${circumference - seg.length}`}
                            strokeDashoffset={-seg.offset}
                            transform={`rotate(-90 ${cx} ${cy})`}
                            className="transition-all duration-500"
                            style={{ opacity: 0.85 }}
                        >
                            <title>{seg.key}: {seg.count} threat{seg.count !== 1 ? 's' : ''}</title>
                        </circle>
                    ))}
                    <text x={cx} y={cy - 8} textAnchor="middle" className="fill-brand-900 dark:fill-white text-2xl font-bold" fontSize="28">{total}</text>
                    <text x={cx} y={cy + 14} textAnchor="middle" className="fill-brand-500 dark:fill-brand-400 text-xs" fontSize="12">threats</text>
                </svg>
                <div className="grid grid-cols-2 gap-x-6 gap-y-1.5 text-sm w-full px-2">
                    {STRIDE_CATEGORIES.map(c => (
                        <div key={c.key} className="flex items-center gap-2">
                            <span
                                className="w-3 h-3 rounded-full inline-block shrink-0"
                                style={{ backgroundColor: c.color }}
                            />
                            <span className="text-brand-700 dark:text-brand-300 truncate">{c.key}</span>
                            <span className="ml-auto font-mono font-bold text-brand-900 dark:text-white">{counts[c.key]}</span>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
};

export default StrideChart;
