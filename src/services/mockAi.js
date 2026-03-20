// Backend API Service
import { API_BASE_URL } from '../config';
import { mapAnalysisResult } from '../utils/analysisMapper';

const getAnalysisMode = (useLocalSlm = true) => (useLocalSlm ? 'standard' : 'fast');

export const analyzeSystem = async (systemDescription, projectName = "Untitled Project", useLocalSlm = true) => {
    try {
        const response = await fetch(`${API_BASE_URL}/analyze`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                description: systemDescription,
                project_name: projectName,
                use_local_slm: useLocalSlm,
                analysis_mode: getAnalysisMode(useLocalSlm)
            }),
        });

        if (!response.ok) {
            throw new Error(`API error: ${response.status}`);
        }

        const result = await response.json();

        return mapAnalysisResult(result);
    } catch (error) {
        console.error("Backend connection failed, falling back to offline mode for demo purposes.", error);
        // Fallback or re-throw depending on preference.
        throw error;
    }
};

export const analyzeIac = async (iacContent, projectName = "Untitled Project", formatHint = 'auto') => {
    try {
        const response = await fetch(`${API_BASE_URL}/analyze-iac`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                iac_content: iacContent,
                project_name: projectName,
                format_hint: formatHint,
                analysis_mode: 'standard'
            }),
        });

        if (!response.ok) {
            throw new Error(`API error: ${response.status}`);
        }

        const result = await response.json();

        return mapAnalysisResult(result);
    } catch (error) {
        console.error("Backend connection failed for IaC Analysis.", error);
        throw error;
    }
};
