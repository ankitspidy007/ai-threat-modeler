import React, { useState, useEffect } from 'react';
import ThreatInput from './components/ThreatInput';
import ThreatDashboard from './components/ThreatDashboard';
import AIAnalysis from './components/AIAnalysis';
import AnalysisHistory from './components/AnalysisHistory';
import { analyzeSystem } from './services/mockAi';
import { saveAnalysis } from './utils/storage';
import { Shield, Zap, Sparkles, Clock, Moon, Sun, RotateCcw } from 'lucide-react';
import { useToast } from './components/Toast';

function App() {
  const [data, setData] = useState(null);
  const [projectName, setProjectName] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [activeTab, setActiveTab] = useState('static'); // 'static', 'ai', 'history'
  const [darkMode, setDarkMode] = useState(() => {
    return localStorage.getItem('theme') === 'dark';
  });
  const toast = useToast();

  // Apply dark mode class to document
  useEffect(() => {
    if (darkMode) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
    localStorage.setItem('theme', darkMode ? 'dark' : 'light');
  }, [darkMode]);

  const handleAnalyze = async (description, name) => {
    setIsAnalyzing(true);
    setProjectName(name);
    // Clear previous data
    setData(null);
    try {
      const result = await analyzeSystem(description, name);
      setData(result);
      // Auto-save to history
      saveAnalysis(name, result);
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
    // Map backend response -> frontend expected format (same as static analysis)
    const mappedResult = {
      summary: result.summary,
      projectName: result.project_name,
      score: result.score,
      architecture: result.architecture,
      timestamp: new Date().toLocaleString(),
      threats: (result.threats || []).map(t => ({
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
        mapped_controls: t.mapped_controls || null
      })),
      diagram: result.mermaid_diagram || "graph LR; Error[No Diagram Generated];",
      report_markdown: result.report_markdown
    };
    setData(mappedResult);
    setProjectName(name);
    // Auto-save AI analysis too
    saveAnalysis(name, mappedResult);
  };

  const handleLoadFromHistory = (analysisData, name) => {
    setData(analysisData);
    setProjectName(name);
    setActiveTab('static');
    toast.success('Analysis loaded from history');
  };

  const handleNewAnalysis = () => {
    setData(null);
    setProjectName('');
  };

  return (
    <div className="min-h-screen text-brand-900 dark:text-brand-100 selection:bg-brand-primary selection:text-white transition-colors duration-300">
      <header className="border-b border-brand-200 dark:border-brand-700 bg-white/80 dark:bg-brand-900/80 backdrop-blur-sm sticky top-0 z-50 shadow-sm">
        <div className="container mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="relative">
              <div className="absolute inset-0 bg-brand-primary blur-md opacity-20 animate-pulse"></div>
              <Shield className="w-8 h-8 text-brand-primary relative z-10" />
            </div>
            <h1 className="text-2xl font-bold tracking-tight">
              <span className="text-brand-900 dark:text-white">AITM</span>
              <span className="text-brand-500 dark:text-brand-400 text-sm ml-2">(AI based threat modeling)</span>
            </h1>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => setDarkMode(!darkMode)}
              className="p-2 rounded-lg border border-brand-200 dark:border-brand-700 hover:bg-brand-100 dark:hover:bg-brand-800 transition-colors"
              title={darkMode ? 'Switch to light mode' : 'Switch to dark mode'}
            >
              {darkMode ? <Sun className="w-4 h-4 text-yellow-400" /> : <Moon className="w-4 h-4 text-brand-600" />}
            </button>
            <div className="text-xs font-mono text-brand-500 dark:text-brand-400 border border-brand-200 dark:border-brand-700 px-2 py-1 rounded bg-brand-50 dark:bg-brand-800">
              v2.0.0
            </div>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="container mx-auto px-4">
          <div className="flex gap-1 border-b border-brand-200 dark:border-brand-700">
            <button
              onClick={() => setActiveTab('static')}
              className={`px-6 py-3 font-semibold transition-all flex items-center gap-2 ${activeTab === 'static'
                ? 'border-b-2 border-brand-primary text-brand-primary bg-brand-50 dark:bg-brand-800'
                : 'text-brand-600 dark:text-brand-400 hover:text-brand-900 dark:hover:text-white hover:bg-brand-50 dark:hover:bg-brand-800'
                }`}
            >
              <Zap className="w-4 h-4" />
              Static Analysis
            </button>
            <button
              onClick={() => setActiveTab('ai')}
              className={`px-6 py-3 font-semibold transition-all flex items-center gap-2 ${activeTab === 'ai'
                ? 'border-b-2 border-purple-600 text-purple-600 bg-purple-50 dark:bg-purple-900/30'
                : 'text-brand-600 dark:text-brand-400 hover:text-brand-900 dark:hover:text-white hover:bg-brand-50 dark:hover:bg-brand-800'
                }`}
            >
              <Sparkles className="w-4 h-4" />
              AI Analysis
            </button>
            <button
              onClick={() => setActiveTab('history')}
              className={`px-6 py-3 font-semibold transition-all flex items-center gap-2 ${activeTab === 'history'
                ? 'border-b-2 border-brand-secondary text-brand-secondary bg-sky-50 dark:bg-sky-900/30'
                : 'text-brand-600 dark:text-brand-400 hover:text-brand-900 dark:hover:text-white hover:bg-brand-50 dark:hover:bg-brand-800'
                }`}
            >
              <Clock className="w-4 h-4" />
              History
            </button>
          </div>
        </div>
      </header>

      <main className="container mx-auto px-4 py-10 flex flex-col items-center">
        {activeTab === 'static' ? (
          <>
            {!data && !isAnalyzing && (
              <div className="text-center mb-12 max-w-2xl animate-fade-in-up">
                <h2 className="text-4xl font-bold mb-4 text-brand-900 dark:text-white">
                  Rule-Based Threat Detection
                </h2>
                <p className="text-brand-600 dark:text-brand-400 text-lg">
                  Fast, accurate threat detection using our enhanced rule engine with 60+ threat patterns.
                </p>
              </div>
            )}

            {!data && <ThreatInput onAnalyze={handleAnalyze} isAnalyzing={isAnalyzing} />}

            {isAnalyzing && (
              <div className="flex flex-col items-center justify-center py-20 animate-pulse">
                <div className="w-16 h-16 border-4 border-brand-200 dark:border-brand-700 border-t-brand-primary rounded-full animate-spin mb-4"></div>
                <p className="text-brand-primary font-mono font-medium">ANALYZING ARCHITECTURE...</p>
              </div>
            )}

            {data && (
              <div className="w-full">
                <div className="flex justify-center mb-6">
                  <button
                    onClick={handleNewAnalysis}
                    className="flex items-center gap-2 px-4 py-2 border border-brand-300 dark:border-brand-600 rounded-lg hover:bg-brand-100 dark:hover:bg-brand-800 transition-colors text-brand-600 dark:text-brand-300"
                  >
                    <RotateCcw className="w-4 h-4" />
                    New Analysis
                  </button>
                </div>
                <ThreatDashboard data={data} projectName={projectName} />
              </div>
            )}
          </>
        ) : activeTab === 'ai' ? (
          <>
            {!data && (
              <AIAnalysis onAnalysisComplete={handleAIAnalysisComplete} />
            )}
            {data && (
              <div className="w-full">
                <div className="flex justify-center mb-6">
                  <button
                    onClick={handleNewAnalysis}
                    className="flex items-center gap-2 px-4 py-2 border border-brand-300 dark:border-brand-600 rounded-lg hover:bg-brand-100 dark:hover:bg-brand-800 transition-colors text-brand-600 dark:text-brand-300"
                  >
                    <RotateCcw className="w-4 h-4" />
                    New Analysis
                  </button>
                </div>
                <ThreatDashboard data={data} projectName={projectName} />
              </div>
            )}
          </>
        ) : (
          <AnalysisHistory onLoadAnalysis={handleLoadFromHistory} />
        )}
      </main>

      <footer className="py-6 text-center text-brand-500 dark:text-brand-400 text-sm border-t border-brand-200 dark:border-brand-700 mt-auto bg-white dark:bg-brand-900">
        <p>&copy; 2026 AITM (AI based threat modeling). Secure by Design.</p>
      </footer>
    </div>
  );
}

export default App;
