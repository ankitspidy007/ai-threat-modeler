import React, { useState } from 'react';
import { Send, FileCode, Upload, Code } from 'lucide-react';

const IacInput = ({ onAnalyze, isAnalyzing }) => {
    const [iacContent, setIacContent] = useState('');
    const [projectName, setProjectName] = useState('My IaC Audit');
    const [formatHint, setFormatHint] = useState('auto');

    const handleSubmit = (e) => {
        e.preventDefault();
        if (iacContent.trim()) {
            onAnalyze(iacContent, projectName, formatHint);
        }
    };

    const handleKeyDown = (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
            e.preventDefault();
            if (iacContent.trim() && !isAnalyzing) {
                onAnalyze(iacContent, projectName, formatHint);
            }
        }
    };

    const handleFileUpload = (e) => {
        const file = e.target.files[0];
        if (!file) return;

        // Auto-detect format from filename
        const filename = file.name.toLowerCase();
        if (filename.includes('compose')) {
            setFormatHint('docker-compose');
        } else if (filename.endsWith('.yaml') || filename.endsWith('.yml')) {
            // Default to k8s for generic yamls unless it explicitly says compose
            setFormatHint('kubernetes');
        }

        const reader = new FileReader();
        reader.onload = (evt) => {
            setIacContent(evt.target.result);
        };
        reader.readAsText(file);
    };

    return (
        <div className="w-full max-w-3xl mx-auto mb-10 animate-fade-in-up">
            <div className="glass-panel rounded-xl p-6 border-l-4 border-l-brand-success dark:bg-brand-800 dark:border-brand-success">
                <div className="flex items-center justify-between mb-4">
                    <h2 className="text-xl font-bold flex items-center gap-2 text-brand-success">
                        <FileCode className="w-6 h-6" />
                        Infrastructure-as-Code Analysis
                    </h2>
                </div>
                
                <div className="mb-4">
                    <label className="block text-xs font-mono text-brand-500 mb-1">Project Name</label>
                    <input
                        type="text"
                        value={projectName}
                        onChange={(e) => setProjectName(e.target.value)}
                        className="input-brand w-full font-mono"
                        placeholder="e.g. Cluster Production Config"
                    />
                </div>

                <div className="flex flex-col md:flex-row gap-4 mb-4">
                    <div className="flex-1">
                        <label className="block text-xs font-mono text-brand-500 mb-1">Upload File</label>
                        <label className="flex items-center justify-center w-full h-10 px-4 transition bg-white border-2 border-brand-300 border-dashed rounded-lg appearance-none cursor-pointer hover:border-brand-primary focus:outline-none dark:bg-brand-700 dark:border-brand-600">
                            <span className="flex items-center space-x-2">
                                <Upload className="w-4 h-4 text-brand-500" />
                                <span className="text-sm font-medium text-brand-600 dark:text-brand-300">
                                    Drop YAML file or click to browse
                                </span>
                            </span>
                            <input type="file" name="file_upload" className="hidden" accept=".yaml,.yml" onChange={handleFileUpload} />
                        </label>
                    </div>
                    
                    <div className="w-full md:w-48">
                        <label className="block text-xs font-mono text-brand-500 mb-1">Format Hint</label>
                        <select 
                            value={formatHint} 
                            onChange={(e) => setFormatHint(e.target.value)}
                            className="input-brand w-full font-mono text-sm py-2"
                        >
                            <option value="auto">Auto-detect</option>
                            <option value="docker-compose">Docker Compose</option>
                            <option value="kubernetes">Kubernetes</option>
                        </select>
                    </div>
                </div>

                <p className="text-brand-600 dark:text-brand-400 text-sm mb-4">
                    Or paste your Docker Compose or Kubernetes YAML manifest below:
                </p>
                
                <form onSubmit={handleSubmit} className="relative">
                    <div className="relative">
                        <div className="absolute top-2 right-2 text-brand-400">
                            <Code className="w-4 h-4" />
                        </div>
                        <textarea
                            className="input-brand w-full h-64 resize-y font-mono text-sm leading-relaxed bg-brand-50 dark:bg-brand-900/50"
                            placeholder="version: '3.8'\nservices:\n  api:\n    image: node:18\n..."
                            value={iacContent}
                            onChange={(e) => setIacContent(e.target.value)}
                            onKeyDown={handleKeyDown}
                            disabled={isAnalyzing}
                            spellCheck="false"
                        />
                    </div>

                    <div className="flex items-center justify-between mt-4">
                        <span className="text-xs text-brand-400 font-mono">Ctrl+Enter to submit</span>
                        <button
                            type="submit"
                            disabled={isAnalyzing || !iacContent.trim()}
                            className={`flex items-center gap-2 bg-brand-success hover:bg-green-600 text-white px-4 py-2 rounded-lg font-bold transition-all shadow-md shadow-green-500/20 ${isAnalyzing ? 'opacity-50 cursor-not-allowed' : ''}`}
                        >
                            {isAnalyzing ? (
                                <>Parsing IaC...</>
                            ) : (
                                <>
                                    <Send className="w-4 h-4" />
                                    Analyze Infrastructure
                                </>
                            )}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
};

export default IacInput;
