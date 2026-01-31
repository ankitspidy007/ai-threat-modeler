import React, { useState } from 'react';
import { Send, Cpu } from 'lucide-react';

const ThreatInput = ({ onAnalyze, isAnalyzing }) => {
    const [description, setDescription] = useState('');

    const [projectName, setProjectName] = useState('My Security Audit');

    const handleSubmit = (e) => {
        e.preventDefault();
        if (description.trim()) {
            onAnalyze(description, projectName);
        }
    };

    return (
        <div className="w-full max-w-3xl mx-auto mb-10">
            <div className="glass-panel rounded-xl p-6 border-l-4 border-l-brand-primary">
                <h2 className="text-xl font-bold mb-4 flex items-center gap-2 text-brand-primary">
                    <Cpu className="w-6 h-6" />
                    System Architecture Description
                </h2>
                <div className="mb-4">
                    <label className="block text-xs font-mono text-brand-500 mb-1">Project Name</label>
                    <input
                        type="text"
                        value={projectName}
                        onChange={(e) => setProjectName(e.target.value)}
                        className="input-brand w-full font-mono"
                        placeholder="e.g. Payment Gateway V2"
                    />
                </div>
                <p className="text-brand-600 text-sm mb-4">
                    Describe your system architecture (e.g., "A Node.js API connected to MongoDB with React frontend, hosted on AWS using Cognito for auth").
                </p>
                <form onSubmit={handleSubmit} className="relative">
                    <textarea
                        className="input-brand w-full h-32 resize-none font-mono text-sm leading-relaxed"
                        placeholder="// Describe your stack here..."
                        value={description}
                        onChange={(e) => setDescription(e.target.value)}
                        disabled={isAnalyzing}
                    />
                    <div className="flex justify-end mt-4">
                        <button
                            type="submit"
                            disabled={isAnalyzing || !description.trim()}
                            className={`btn-brand flex items-center gap-2 ${isAnalyzing ? 'opacity-50 cursor-not-allowed' : ''
                                }`}
                        >
                            {isAnalyzing ? (
                                <>Analyzing...</>
                            ) : (
                                <>
                                    <Send className="w-4 h-4" />
                                    Analyze Threats
                                </>
                            )}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
};

export default ThreatInput;
