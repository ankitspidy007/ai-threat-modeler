import { useState, useCallback, useRef } from 'react';

const WS_URL = `ws://${window.location.hostname}:8000/ws/analyze`;

/**
 * React hook for streaming threat analysis via WebSocket.
 * 
 * Returns:
 *   analyze(description, projectName) - start analysis
 *   progress - 0-100 percentage
 *   phase - current phase label
 *   message - current status message
 *   result - final analysis result (null until complete)
 *   error - error message if failed
 *   isAnalyzing - whether analysis is in progress
 *   cancel - cancel the analysis
 */
export function useStreamingAnalysis() {
    const [progress, setProgress] = useState(0);
    const [phase, setPhase] = useState('');
    const [message, setMessage] = useState('');
    const [result, setResult] = useState(null);
    const [error, setError] = useState(null);
    const [isAnalyzing, setIsAnalyzing] = useState(false);
    const wsRef = useRef(null);

    const cancel = useCallback(() => {
        if (wsRef.current) {
            wsRef.current.close();
            wsRef.current = null;
        }
        setIsAnalyzing(false);
        setProgress(0);
        setPhase('');
        setMessage('Cancelled');
    }, []);

    const analyze = useCallback((description, projectName = 'Untitled Project', useLocalSlm = true) => {
        return new Promise((resolve, reject) => {
            // Reset state
            setProgress(0);
            setPhase('Connecting...');
            setMessage('Establishing connection...');
            setResult(null);
            setError(null);
            setIsAnalyzing(true);

            const ws = new WebSocket(WS_URL);
            wsRef.current = ws;

            ws.onopen = () => {
                setPhase('Connected');
                setMessage('Sending architecture for analysis...');
                ws.send(JSON.stringify({
                    description,
                    project_name: projectName,
                    use_local_slm: useLocalSlm
                }));
            };

            ws.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);

                    if (data.type === 'progress') {
                        setProgress(data.progress || 0);
                        setPhase(data.phase || '');
                        setMessage(data.message || '');
                    } else if (data.type === 'result') {
                        setProgress(100);
                        setPhase('complete');
                        setMessage('Analysis complete!');
                        setIsAnalyzing(false);

                        // Map backend response to frontend format
                        const r = data.data;
                        const mapped = {
                            summary: r.summary,
                            projectName: r.project_name,
                            score: r.score,
                            architecture: r.architecture,
                            timestamp: new Date().toLocaleString(),
                            threats: (r.threats || []).map(t => ({
                                id: t.id,
                                category: t.category,
                                stride_category: t.stride_category || t.category,
                                title: t.title,
                                severity: t.severity,
                                likelihood: t.likelihood || 'Medium',
                                confidence: t.confidence || 'Medium',
                                tier: t.tier || 'Potential',
                                status: t.status || 'Identified',
                                evidence: t.evidence || [],
                                description: t.description,
                                impact: t.impact || 'Unknown',
                                mitigation: t.mitigation,
                                cwe: t.cwe || [],
                                mitre_attack: t.mitre_attack || [],
                                owasp_top_10: t.owasp_top_10 || [],
                                nist_800_53: t.nist_800_53 || [],
                                affected_components: t.affected_components || [],
                                affected_data_flows: t.affected_data_flows || [],
                                component_id: t.component_id,
                                mapped_controls: t.mapped_controls || null,
                            })),
                            diagram: r.mermaid_diagram || "graph LR; Error[No Diagram Generated];",
                            report_markdown: r.report_markdown,
                        };

                        setResult(mapped);
                        resolve(mapped);
                    } else if (data.type === 'error') {
                        setError(data.message);
                        setIsAnalyzing(false);
                        reject(new Error(data.message));
                    }
                } catch (e) {
                    console.error('Failed to parse WebSocket message:', e);
                }
            };

            ws.onerror = () => {
                setError('WebSocket connection failed. Falling back to REST API...');
                setIsAnalyzing(false);
                reject(new Error('WebSocket connection failed'));
            };

            ws.onclose = (event) => {
                wsRef.current = null;
                if (event.code !== 1000 && !result) {
                    // Abnormal close without result
                    setIsAnalyzing(false);
                }
            };
        });
    }, []);

    return {
        analyze,
        progress,
        phase,
        message,
        result,
        error,
        isAnalyzing,
        cancel,
    };
}
