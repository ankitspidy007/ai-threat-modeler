import React, { useState } from 'react';
import ThreatInput from './components/ThreatInput';
import ThreatDashboard from './components/ThreatDashboard';
import AIAnalysis from './components/AIAnalysis';
import { analyzeSystem } from './services/mockAi';
import { Shield, Zap, Sparkles } from 'lucide-react';
import { useToast } from './components/Toast';

function App() {
  const [data, setData] = useState(null);
  const [projectName, setProjectName] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [activeTab, setActiveTab] = useState('static'); // 'static' or 'ai'
  const toast = useToast();

  const handleAnalyze = async (description, name) => {
    setIsAnalyzing(true);
    setProjectName(name);
    // Clear previous data
    setData(null);
    try {
      const result = await analyzeSystem(description, name);
      setData(result);
      toast.success(`Analysis complete! Found ${result.threats.length} potential threats.`, 'Success');
    } catch (error) {
      console.error("Analysis failed", error);
      toast.error(
        error.message || 'Failed to analyze system. Please check your connection and try again.',
        'Analysis Failed'
      );
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleAIAnalysisComplete = (result, name) => {
    setData(result);
    setProjectName(name);
  };

  return (
    <div className="min-h-screen text-brand-900 selection:bg-brand-primary selection:text-white">
      <header className="border-b border-brand-200 bg-white/80 backdrop-blur-sm sticky top-0 z-50 shadow-sm">
        <div className="container mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="relative">
              <div className="absolute inset-0 bg-brand-primary blur-md opacity-20 animate-pulse"></div>
              <Shield className="w-8 h-8 text-brand-primary relative z-10" />
            </div>
            <h1 className="text-2xl font-bold tracking-tight">
              <span className="text-brand-900">AITM</span>
              <span className="text-brand-500 text-sm ml-2">(AI based threat modeling)</span>
            </h1>
          </div>
          <div className="text-xs font-mono text-brand-500 border border-brand-200 px-2 py-1 rounded bg-brand-50">
            v1.0.0-alpha
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="container mx-auto px-4">
          <div className="flex gap-1 border-b border-brand-200">
            <button
              onClick={() => setActiveTab('static')}
              className={`px-6 py-3 font-semibold transition-all flex items-center gap-2 ${activeTab === 'static'
                  ? 'border-b-2 border-brand-primary text-brand-primary bg-brand-50'
                  : 'text-brand-600 hover:text-brand-900 hover:bg-brand-50'
                }`}
            >
              <Zap className="w-4 h-4" />
              Static Analysis
            </button>
            <button
              onClick={() => setActiveTab('ai')}
              className={`px-6 py-3 font-semibold transition-all flex items-center gap-2 ${activeTab === 'ai'
                  ? 'border-b-2 border-purple-600 text-purple-600 bg-purple-50'
                  : 'text-brand-600 hover:text-brand-900 hover:bg-brand-50'
                }`}
            >
              <Sparkles className="w-4 h-4" />
              AI Analysis (OpenAI / Claude)
            </button>
          </div>
        </div>
      </header>

      <main className="container mx-auto px-4 py-10 flex flex-col items-center">
        {activeTab === 'static' ? (
          <>
            {!data && !isAnalyzing && (
              <div className="text-center mb-12 max-w-2xl animate-fade-in-up">
                <h2 className="text-4xl font-bold mb-4 text-brand-900">
                  Rule-Based Threat Detection
                </h2>
                <p className="text-brand-600 text-lg">
                  Fast, accurate threat detection using our enhanced rule engine with 60+ threat patterns.
                </p>
              </div>
            )}

            <ThreatInput onAnalyze={handleAnalyze} isAnalyzing={isAnalyzing} />

            {isAnalyzing && (
              <div className="flex flex-col items-center justify-center py-20 animate-pulse">
                <div className="w-16 h-16 border-4 border-brand-200 border-t-brand-primary rounded-full animate-spin mb-4"></div>
                <p className="text-brand-primary font-mono font-medium">ANALYZING ARCHITECTURE...</p>
              </div>
            )}

            <ThreatDashboard data={data} projectName={projectName} />
          </>
        ) : (
          <>
            {!data && (
              <AIAnalysis onAnalysisComplete={handleAIAnalysisComplete} />
            )}
            {data && (
              <ThreatDashboard data={data} projectName={projectName} />
            )}
          </>
        )}
      </main>

      <footer className="py-6 text-center text-brand-500 text-sm border-t border-brand-200 mt-auto bg-white">
        <p>&copy; 2026 AITM (AI based threat modeling). Secure by Design.</p>
      </footer>
    </div>
  );
}

export default App;

