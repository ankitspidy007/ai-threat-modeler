import React, { useState, useEffect } from 'react';
import ThreatInput from './components/ThreatInput';
import ThreatDashboard from './components/ThreatDashboard';
import AIAnalysis from './components/AIAnalysis';
import AnalysisHistory from './components/AnalysisHistory';
import Sidebar from './components/Sidebar';
import { analyzeSystem } from './services/mockAi';
import { useStreamingAnalysis } from './hooks/useStreamingAnalysis';
import { saveAnalysis } from './utils/storage';
import { RotateCcw, Zap, Sparkles, Clock } from 'lucide-react';
import { useToast } from './components/Toast';

function App() {
  const [data, setData] = useState(null);
  const [projectName, setProjectName] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [activeTab, setActiveTab] = useState('static');
  const [darkMode, setDarkMode] = useState(() => {
    return localStorage.getItem('theme') === 'dark';
  });
  const toast = useToast();
  const streaming = useStreamingAnalysis();

  useEffect(() => {
    if (darkMode) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
    localStorage.setItem('theme', darkMode ? 'dark' : 'light');
  }, [darkMode]);

  const handleAnalyze = async (description, name) => {
    setProjectName(name);
    setData(null);
    setIsAnalyzing(true);

    try {
      // Try WebSocket streaming first
      const result = await streaming.analyze(description, name);
      setData(result);
      saveAnalysis(name, result);
      toast.success(`Analysis complete! Found ${result.threats.length} potential threats.`, 'Success');
    } catch (wsError) {
      // Fallback to REST API
      console.warn('WebSocket failed, falling back to REST:', wsError.message);
      try {
        const result = await analyzeSystem(description, name);
        setData(result);
        saveAnalysis(name, result);
        toast.success(`Analysis complete! Found ${result.threats.length} potential threats.`, 'Success');
      } catch (error) {
        console.error('Analysis failed', error);
        toast.error(
          error.message || 'Failed to analyze system. Please check your connection and try again.',
          'Analysis Failed'
        );
      }
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleAIAnalysisComplete = (result, name) => {
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

  // Page titles and icons for the header
  const pageInfo = {
    static: { title: 'Static Analysis', subtitle: 'Rule-based + NLP + Semantic threat detection', icon: Zap, color: 'text-brand-primary' },
    ai: { title: 'AI Analysis', subtitle: 'LLM-enhanced analysis with RAG', icon: Sparkles, color: 'text-purple-500' },
    history: { title: 'Analysis History', subtitle: 'Previous analyses saved locally', icon: Clock, color: 'text-brand-secondary' },
  };

  const currentPage = pageInfo[activeTab];
  const PageIcon = currentPage.icon;

  return (
    <div className="min-h-screen text-brand-900 dark:text-brand-100 selection:bg-brand-primary selection:text-white transition-colors duration-300">
      {/* Sidebar */}
      <Sidebar
        activeTab={activeTab}
        onTabChange={setActiveTab}
        darkMode={darkMode}
        onToggleDarkMode={() => setDarkMode(!darkMode)}
      />

      {/* Main Content — offset by sidebar width */}
      <div className="ml-[68px] transition-all duration-300">
        {/* Top Bar */}
        <header className="sticky top-0 z-40 border-b border-brand-200/60 dark:border-brand-700/60 bg-white/80 dark:bg-brand-900/80 backdrop-blur-xl">
          <div className="px-6 py-4 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <PageIcon className={`w-5 h-5 ${currentPage.color}`} />
              <div>
                <h1 className="text-lg font-bold text-brand-900 dark:text-white">{currentPage.title}</h1>
                <p className="text-xs text-brand-500 dark:text-brand-400">{currentPage.subtitle}</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              {data && (
                <button
                  onClick={handleNewAnalysis}
                  className="flex items-center gap-2 px-3 py-1.5 text-sm border border-brand-300 dark:border-brand-600 rounded-lg hover:bg-brand-100 dark:hover:bg-brand-800 transition-colors text-brand-600 dark:text-brand-300"
                >
                  <RotateCcw className="w-3.5 h-3.5" />
                  New Analysis
                </button>
              )}
              <div className="text-[10px] font-mono text-brand-400 dark:text-brand-500 border border-brand-200 dark:border-brand-700 px-2 py-1 rounded-md bg-brand-50 dark:bg-brand-800">
                v2.0.0
              </div>
            </div>
          </div>
        </header>

        {/* Page Content */}
        <main className="p-6 max-w-[1400px] mx-auto">
          {activeTab === 'static' ? (
            <>
              {!data && !isAnalyzing && (
                <div className="text-center mb-10 max-w-2xl mx-auto animate-fade-in-up">
                  <h2 className="text-3xl font-bold mb-3 text-brand-900 dark:text-white">
                    Rule-Based Threat Detection
                  </h2>
                  <p className="text-brand-600 dark:text-brand-400 text-base">
                    Fast, accurate threat detection using our enhanced rule engine with 60+ threat patterns, NLP-powered parsing, and semantic matching.
                  </p>
                </div>
              )}

              {!data && <ThreatInput onAnalyze={handleAnalyze} isAnalyzing={isAnalyzing} />}

              {(isAnalyzing || streaming.isAnalyzing) && (
                <div className="flex flex-col items-center justify-center py-16 space-y-6 animate-fade-in-up">
                  {/* Live progress bar */}
                  <div className="w-full max-w-md">
                    <div className="flex justify-between items-center mb-2">
                      <span className="text-sm font-mono font-medium text-brand-primary capitalize">
                        {streaming.phase?.replace(/_/g, ' ') || 'Connecting...'}
                      </span>
                      <span className="text-xs font-mono text-brand-500 dark:text-brand-400">
                        {Math.round(streaming.progress || 0)}%
                      </span>
                    </div>
                    <div className="h-2 bg-brand-100 dark:bg-brand-800 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-gradient-to-r from-brand-primary to-brand-accent rounded-full transition-all duration-500 ease-out"
                        style={{ width: `${streaming.progress || 2}%` }}
                      />
                    </div>
                    <p className="text-xs text-brand-500 dark:text-brand-400 mt-2 text-center">
                      {streaming.message || 'Initializing analysis pipeline...'}
                    </p>
                  </div>
                  {/* Spinner */}
                  <div className="w-10 h-10 border-3 border-brand-200 dark:border-brand-700 border-t-brand-primary rounded-full animate-spin" />
                </div>
              )}

              {data && (
                <div className="w-full">
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
                  <ThreatDashboard data={data} projectName={projectName} />
                </div>
              )}
            </>
          ) : (
            <AnalysisHistory onLoadAnalysis={handleLoadFromHistory} />
          )}
        </main>

        {/* Footer */}
        <footer className="py-4 text-center text-brand-400 dark:text-brand-500 text-xs border-t border-brand-200/60 dark:border-brand-700/60 mt-auto">
          <p>&copy; 2026 AITM v2.0 • NLP &bull; Semantic Search &bull; Attack Chains &bull; Multi-LLM</p>
        </footer>
      </div>
    </div>
  );
}

export default App;
