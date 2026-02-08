import React, { useState } from 'react';
import { Sparkles, Key, AlertCircle, Loader2, CheckCircle2 } from 'lucide-react';
import { useToast } from './Toast';

const AIAnalysis = ({ onAnalysisComplete }) => {
    const [provider, setProvider] = useState('openai');
    const [apiKey, setApiKey] = useState('');
    const [description, setDescription] = useState('');
    const [projectName, setProjectName] = useState('');
    const [isValidating, setIsValidating] = useState(false);
    const [isAnalyzing, setIsAnalyzing] = useState(false);
    const [keyValid, setKeyValid] = useState(null);
    const toast = useToast();

    const validateApiKey = async () => {
        if (!apiKey || apiKey.length < 10) {
            toast.error('Please enter a valid API key');
            return;
        }

        setIsValidating(true);
        try {
            const response = await fetch('http://127.0.0.1:8000/validate-api-key', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ provider, api_key: apiKey })
            });

            const result = await response.json();

            if (result.valid) {
                setKeyValid(true);
                toast.success(`${provider.toUpperCase()} API key validated successfully!`);
            } else {
                setKeyValid(false);
                toast.error(`Invalid ${provider.toUpperCase()} API key`);
            }
        } catch (error) {
            setKeyValid(false);
            toast.error('Failed to validate API key');
        } finally {
            setIsValidating(false);
        }
    };

    const handleAnalyze = async () => {
        if (!projectName || !description) {
            toast.error('Please fill in all fields');
            return;
        }

        if (!apiKey) {
            toast.error('Please enter your API key');
            return;
        }

        setIsAnalyzing(true);
        try {
            const response = await fetch('http://127.0.0.1:8000/analyze-with-llm', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    project_name: projectName,
                    description: description,
                    llm_provider: provider,
                    api_key: apiKey,
                    model: null
                })
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.detail || 'Analysis failed');
            }

            const result = await response.json();
            toast.success(`AI analysis complete! Found ${result.threats?.length || 0} threats`);
            onAnalysisComplete(result, projectName);
        } catch (error) {
            toast.error(error.message || 'AI analysis failed');
        } finally {
            setIsAnalyzing(false);
        }
    };

    return (
        <div className="w-full max-w-4xl mx-auto p-6 space-y-6">
            {/* Header */}
            <div className="text-center mb-8">
                <div className="flex items-center justify-center gap-3 mb-2">
                    <Sparkles className="w-8 h-8 text-purple-600" />
                    <h2 className="text-3xl font-bold text-brand-900">AI-Powered Threat Analysis</h2>
                </div>
                <p className="text-brand-600">
                    Enhance your threat detection with OpenAI GPT-4 or Claude 3.5 Sonnet
                </p>
            </div>

            {/* Provider Selection */}
            <div className="bg-white border border-brand-200 rounded-lg p-6 shadow-sm">
                <label className="block text-sm font-bold text-brand-900 mb-3">
                    Select AI Provider
                </label>
                <div className="grid grid-cols-2 gap-4">
                    <button
                        onClick={() => {
                            setProvider('openai');
                            setKeyValid(null);
                        }}
                        className={`p-4 border-2 rounded-lg transition-all ${provider === 'openai'
                                ? 'border-green-500 bg-green-50'
                                : 'border-brand-200 hover:border-brand-300'
                            }`}
                    >
                        <div className="font-bold text-lg mb-1">OpenAI</div>
                        <div className="text-sm text-brand-600">GPT-4 / GPT-4 Turbo</div>
                    </button>
                    <button
                        onClick={() => {
                            setProvider('claude');
                            setKeyValid(null);
                        }}
                        className={`p-4 border-2 rounded-lg transition-all ${provider === 'claude'
                                ? 'border-purple-500 bg-purple-50'
                                : 'border-brand-200 hover:border-brand-300'
                            }`}
                    >
                        <div className="font-bold text-lg mb-1">Claude</div>
                        <div className="text-sm text-brand-600">Claude 3.5 Sonnet</div>
                    </button>
                </div>
            </div>

            {/* API Key Input */}
            <div className="bg-white border border-brand-200 rounded-lg p-6 shadow-sm">
                <label className="block text-sm font-bold text-brand-900 mb-2">
                    <Key className="inline w-4 h-4 mr-1" />
                    API Key
                </label>
                <div className="flex gap-2">
                    <input
                        type="password"
                        value={apiKey}
                        onChange={(e) => {
                            setApiKey(e.target.value);
                            setKeyValid(null);
                        }}
                        placeholder={provider === 'openai' ? 'sk-...' : 'sk-ant-...'}
                        className="flex-1 px-4 py-2 border border-brand-300 rounded focus:outline-none focus:ring-2 focus:ring-brand-primary"
                    />
                    <button
                        onClick={validateApiKey}
                        disabled={isValidating || !apiKey}
                        className="px-4 py-2 bg-brand-primary text-white rounded hover:bg-brand-primary/90 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
                    >
                        {isValidating ? (
                            <>
                                <Loader2 className="w-4 h-4 animate-spin" />
                                Validating...
                            </>
                        ) : (
                            'Validate'
                        )}
                    </button>
                </div>
                {keyValid === true && (
                    <div className="mt-2 flex items-center gap-2 text-green-600 text-sm">
                        <CheckCircle2 className="w-4 h-4" />
                        API key is valid
                    </div>
                )}
                {keyValid === false && (
                    <div className="mt-2 flex items-center gap-2 text-red-600 text-sm">
                        <AlertCircle className="w-4 h-4" />
                        Invalid API key
                    </div>
                )}
                <p className="mt-2 text-xs text-brand-500">
                    Your API key is sent directly to {provider === 'openai' ? 'OpenAI' : 'Anthropic'} and never stored on our servers.
                </p>
            </div>

            {/* Project Name */}
            <div className="bg-white border border-brand-200 rounded-lg p-6 shadow-sm">
                <label className="block text-sm font-bold text-brand-900 mb-2">
                    Project Name
                </label>
                <input
                    type="text"
                    value={projectName}
                    onChange={(e) => setProjectName(e.target.value)}
                    placeholder="e.g., E-Commerce Platform"
                    className="w-full px-4 py-2 border border-brand-300 rounded focus:outline-none focus:ring-2 focus:ring-brand-primary"
                />
            </div>

            {/* Architecture Description */}
            <div className="bg-white border border-brand-200 rounded-lg p-6 shadow-sm">
                <label className="block text-sm font-bold text-brand-900 mb-2">
                    System Architecture Description
                </label>
                <textarea
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                    placeholder="Describe your system architecture in detail. Include:
- Microservices and their tech stacks
- Databases and data stores
- Third-party integrations
- Security controls
- Known issues or concerns

Example:
1. User Service (Node.js + Express): Handles authentication with JWT
2. Payment Service (Java Spring Boot): Integrates with Stripe
3. PostgreSQL database with read replicas
4. Redis cluster for session management

KNOWN ISSUES:
- JWT signature is not validated
- No rate limiting on API endpoints"
                    rows={12}
                    className="w-full px-4 py-2 border border-brand-300 rounded focus:outline-none focus:ring-2 focus:ring-brand-primary font-mono text-sm"
                />
                <p className="mt-2 text-xs text-brand-500">
                    The more detailed your description, the better the AI analysis will be.
                </p>
            </div>

            {/* Analyze Button */}
            <button
                onClick={handleAnalyze}
                disabled={isAnalyzing || !projectName || !description || !apiKey}
                className="w-full py-4 bg-gradient-to-r from-purple-600 to-blue-600 text-white rounded-lg font-bold text-lg hover:from-purple-700 hover:to-blue-700 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 shadow-lg"
            >
                {isAnalyzing ? (
                    <>
                        <Loader2 className="w-5 h-5 animate-spin" />
                        Analyzing with {provider === 'openai' ? 'OpenAI' : 'Claude'}...
                    </>
                ) : (
                    <>
                        <Sparkles className="w-5 h-5" />
                        Analyze with AI
                    </>
                )}
            </button>

            {/* Info Box */}
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                <div className="flex items-start gap-2">
                    <AlertCircle className="w-5 h-5 text-blue-600 mt-0.5 shrink-0" />
                    <div className="text-sm text-blue-800">
                        <p className="font-bold mb-1">How it works:</p>
                        <ul className="list-disc list-inside space-y-1">
                            <li>AI analyzes your architecture using the STRIDE framework</li>
                            <li>Combines rule-based detection with AI insights</li>
                            <li>Identifies threats with OWASP Top 10 and CWE mappings</li>
                            <li>AI-detected threats are marked with [AI] prefix</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default AIAnalysis;
