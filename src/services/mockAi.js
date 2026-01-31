// Backend API Service
export const analyzeSystem = async (systemDescription, projectName = "Untitled Project") => {
    try {
        const response = await fetch('http://localhost:8000/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                description: systemDescription,
                project_name: projectName
            }),
        });

        if (!response.ok) {
            throw new Error(`API error: ${response.status}`);
        }

        const result = await response.json();

        // Map Backend response -> Frontend expected format
        return {
            summary: result.summary,
            projectName: result.project_name,
            score: result.score, // Pass through score
            architecture: result.architecture, // Pass through architecture
            timestamp: new Date().toLocaleString(),
            threats: result.threats.map(t => ({
                id: t.id,
                category: t.category,
                stride_category: t.stride_category || t.category,
                title: t.title,
                severity: t.severity,
                likelihood: t.likelihood || 'Medium',
                confidence: t.confidence || 'Medium',
                tier: t.tier || 'Potential',  // Confirmed or Potential
                status: t.status || 'Identified',
                evidence: t.evidence || [],
                description: t.description,
                impact: t.impact || "Unknown",
                mitigation: t.mitigation,
                // Aggregated fields
                affected_components: t.affected_components || [],
                affected_data_flows: t.affected_data_flows || [],
                // Legacy
                component_id: t.component_id,
                mapped_controls: t.mapped_controls || null
            })),
            diagram: result.mermaid_diagram || "graph LR; Error[No Diagram Generated];",
            report_markdown: result.report_markdown
        };
    } catch (error) {
        console.error("Backend connection failed, falling back to offline mode for demo purposes.", error);
        // Fallback or re-throw depending on preference.
        throw error;
    }
};


