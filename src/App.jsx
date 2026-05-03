import React, { useState, useEffect } from 'react';
import ThreatInput from './components/ThreatInput';
import IacInput from './components/IacInput';
import ThreatDashboard from './components/ThreatDashboard';
import AIAnalysis from './components/AIAnalysis';
import AnalysisHistory from './components/AnalysisHistory';
import Sidebar from './components/Sidebar';
import { analyzeDocuments, analyzeSystem, analyzeIac } from './services/mockAi';
import { useStreamingAnalysis } from './hooks/useStreamingAnalysis';
import { saveAnalysis } from './utils/storage';
import { mapAnalysisResult } from './utils/analysisMapper';
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

  const handleAnalyze = async (description, name, useLocalSlm = true, options = {}) => {
    setProjectName(name);
    setData(null);
    setIsAnalyzing(true);

    const uploadedFiles = options.files || [];

    try {
      if (uploadedFiles.length > 0) {
        const result = await analyzeDocuments(uploadedFiles, name, useLocalSlm, options);
        setData(result);
        saveAnalysis(name, result);
        toast.success(`Document analysis complete! Found ${result.threats.length} potential threats.`, 'Success');
        return;
      }

      // Try WebSocket streaming first
      const result = await streaming.analyze(description, name, useLocalSlm, options);
      setData(result);
      saveAnalysis(name, result);
      toast.success(`Analysis complete! Found ${result.threats.length} potential threats.`, 'Success');
    } catch (wsError) {
      // Fallback to REST API
      console.warn('WebSocket failed, falling back to REST:', wsError.message);
      try {
        const result = await analyzeSystem(description, name, useLocalSlm, options);
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

  const handleIacAnalyze = async (iacContent, name, formatHint) => {
    setProjectName(name);
    setData(null);
    setIsAnalyzing(true);

    try {
        const result = await analyzeIac(iacContent, name, formatHint);
        setData(result);
        saveAnalysis(name, result);
        toast.success(`IaC Analysis complete! Found ${result.threats.length} potential threats.`, 'Success');
    } catch (error) {
        console.error('IaC Analysis failed', error);
        toast.error(
          error.message || 'Failed to analyze IaC. Ensure it is valid YAML.',
          'Analysis Failed'
        );
    } finally {
        setIsAnalyzing(false);
    }
  };

  const handleAIAnalysisComplete = (result, name) => {
    const mappedResult = mapAnalysisResult(result);
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
    iac: { title: 'Infrastructure-as-Code', subtitle: 'Parse Docker Compose and K8s files', icon: Zap, color: 'text-brand-success' },
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
        <header className="sticky top-0 z-40 border-b border-white/70 dark:border-brand-700/60 bg-white/58 dark:bg-brand-900/58 backdrop-blur-xl">
          <div className="px-6 py-4 flex items-center justify-between max-w-[1440px] mx-auto">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-white/80 dark:bg-brand-800/80 shadow-sm border border-white/70 dark:border-brand-700/60">
                <PageIcon className={`w-5 h-5 ${currentPage.color}`} />
              </div>
              <div>
                <h1 className="text-lg font-bold text-brand-900 dark:text-white">{currentPage.title}</h1>
                <p className="text-xs text-brand-500 dark:text-brand-400">{currentPage.subtitle}</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              {data && (
                <button
                  onClick={handleNewAnalysis}
                  className="flex items-center gap-2 px-3.5 py-2 text-sm border border-brand-200 dark:border-brand-600 rounded-xl hover:bg-white dark:hover:bg-brand-800 transition-colors text-brand-600 dark:text-brand-300 shadow-sm"
                >
                  <RotateCcw className="w-3.5 h-3.5" />
                  New Analysis
                </button>
              )}
              <div className="text-[10px] font-mono text-brand-500 dark:text-brand-500 border border-brand-200 dark:border-brand-700 px-2.5 py-1 rounded-full bg-white/70 dark:bg-brand-800/80">
                v2.0.0
              </div>
            </div>
          </div>
        </header>

        {/* Page Content */}
        <main className="px-6 py-8 max-w-[1440px] mx-auto">
          {activeTab === 'static' ? (
            <>
              {!data && !isAnalyzing && (
                <div className="text-center mb-10 max-w-4xl mx-auto animate-fade-in-up panel-soft px-8 py-10">
                  <div className="inline-flex items-center gap-2 rounded-full bg-brand-primary/10 px-3 py-1 text-xs font-semibold uppercase tracking-[0.18em] text-brand-primary mb-4">
                    Local Analysis
                  </div>
                  <h2 className="text-4xl font-bold mb-3 text-brand-900 dark:text-white tracking-tight">
                    Rule-Based Threat Detection
                  </h2>
                  <p className="text-brand-600 dark:text-brand-400 text-base max-w-2xl mx-auto leading-7">
                    Fast, accurate threat detection using our enhanced rule engine with 60+ threat patterns, NLP-powered parsing, and semantic matching.
                  </p>
                </div>
              )}

              {!data && <ThreatInput onAnalyze={handleAnalyze} isAnalyzing={isAnalyzing || streaming.isAnalyzing} />}

              {activeTab === 'static' && (isAnalyzing || streaming.isAnalyzing) && (
                <div className="flex flex-col items-center justify-center py-16 space-y-6 animate-fade-in-up panel-soft">
                  {/* Live progress bar */}
                  <div className="w-full max-w-md px-8 pt-10">
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
                  <div className="w-10 h-10 mb-10 border-3 border-brand-200 dark:border-brand-700 border-t-brand-primary rounded-full animate-spin" />
                </div>
              )}

              {data && (
                <div className="w-full">
                  <ThreatDashboard data={data} projectName={projectName} />
                </div>
              )}
            </>
          ) : activeTab === 'iac' ? (
            <>
              {!data && !isAnalyzing && (
                <div className="text-center mb-10 max-w-4xl mx-auto animate-fade-in-up panel-soft px-8 py-10">
                  <div className="inline-flex items-center gap-2 rounded-full bg-brand-success/10 px-3 py-1 text-xs font-semibold uppercase tracking-[0.18em] text-brand-success mb-4">
                    Infrastructure
                  </div>
                  <h2 className="text-4xl font-bold mb-3 text-brand-900 dark:text-white tracking-tight">
                    IaC Architecture Parser
                  </h2>
                  <p className="text-brand-600 dark:text-brand-400 text-base max-w-2xl mx-auto leading-7">
                    Directly parse Docker Compose and Kubernetes manifests to build architectural threat models.
                  </p>
                </div>
              )}

              {!data && <IacInput onAnalyze={handleIacAnalyze} isAnalyzing={isAnalyzing} />}

              {isAnalyzing && (
                <div className="flex flex-col items-center justify-center py-16 space-y-6 animate-fade-in-up panel-soft">
                  <div className="w-10 h-10 border-3 border-brand-200 dark:border-brand-700 border-t-brand-success rounded-full animate-spin" />
                  <p className="text-sm font-mono text-brand-500 dark:text-brand-400 pb-10">Parsing Infrastructure-as-Code...</p>
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
