// Local storage utilities for saving and loading analyses

export const saveAnalysis = (projectName, data) => {
    try {
        const saved = JSON.parse(localStorage.getItem('savedAnalyses') || '[]');
        const newAnalysis = {
            id: Date.now(),
            projectName,
            data,
            timestamp: new Date().toISOString()
        };

        saved.push(newAnalysis);

        // Keep only last 50 analyses
        if (saved.length > 50) {
            saved.shift();
        }

        localStorage.setItem('savedAnalyses', JSON.stringify(saved));
        return newAnalysis.id;
    } catch (error) {
        console.error('Failed to save analysis:', error);
        return null;
    }
};

export const loadAnalyses = () => {
    try {
        return JSON.parse(localStorage.getItem('savedAnalyses') || '[]');
    } catch (error) {
        console.error('Failed to load analyses:', error);
        return [];
    }
};

export const loadAnalysisById = (id) => {
    try {
        const saved = loadAnalyses();
        return saved.find(a => a.id === id);
    } catch (error) {
        console.error('Failed to load analysis:', error);
        return null;
    }
};

export const deleteAnalysis = (id) => {
    try {
        const saved = loadAnalyses();
        const filtered = saved.filter(a => a.id !== id);
        localStorage.setItem('savedAnalyses', JSON.stringify(filtered));
        return true;
    } catch (error) {
        console.error('Failed to delete analysis:', error);
        return false;
    }
};

export const clearAllAnalyses = () => {
    try {
        localStorage.removeItem('savedAnalyses');
        return true;
    } catch (error) {
        console.error('Failed to clear analyses:', error);
        return false;
    }
};

export const exportAnalysisAsFile = (analysis) => {
    try {
        const dataStr = JSON.stringify(analysis, null, 2);
        const blob = new Blob([dataStr], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `${analysis.projectName.replace(/\s+/g, '_')}_${analysis.id}.json`;
        link.click();
        URL.revokeObjectURL(url);
        return true;
    } catch (error) {
        console.error('Failed to export analysis:', error);
        return false;
    }
};

export const importAnalysisFromFile = (file) => {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();

        reader.onload = (e) => {
            try {
                const analysis = JSON.parse(e.target.result);

                // Validate structure
                if (!analysis.projectName || !analysis.data) {
                    reject(new Error('Invalid analysis file format'));
                    return;
                }

                // Save to local storage
                const saved = loadAnalyses();
                saved.push({
                    ...analysis,
                    id: Date.now(),
                    timestamp: new Date().toISOString()
                });
                localStorage.setItem('savedAnalyses', JSON.stringify(saved));

                resolve(analysis);
            } catch (error) {
                reject(error);
            }
        };

        reader.onerror = () => reject(new Error('Failed to read file'));
        reader.readAsText(file);
    });
};
