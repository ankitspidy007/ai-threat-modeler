import React, { useState, useEffect } from 'react';
import ThreatInput from './components/ThreatInput';
import IacInput from './components/IacInput';
import CodeInput from './components/CodeInput';
import ThreatDashboard from './components/ThreatDashboard';
import AIAnalysis from './components/AIAnalysis';
import AnalysisHistory from './components/AnalysisHistory';
import Sidebar from './components/Sidebar';
import { analyzeDocuments, analyzeSystem, analyzeIac, analyzeCode } from './services/mockAi';
import { useStreamingAnalysis } from './hooks/useStreamingAnalysis';
import { saveAnalysis } from './utils/storage';
import { mapAnalysisResult } from './utils/analysisMapper';
import { RotateCcw, Zap, Sparkles, Clock, FileCode2 } from 'lucide-react';
import { useToast } from './hooks/useToast';

function App() {
  const [data, setData] = useState(null);
  const [projectName, setProjectName] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [activeTab, setActiveTab] = useState('static');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(true);
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
        toast.success(`Document analysis complete! Found ${result.threats.length} security findings.`, 'Success');
        return;
      }

      // Try WebSocket streaming first
      const result = await streaming.analyze(description, name, useLocalSlm, options);
      setData(result);
      saveAnalysis(name, result);
      toast.success(`Analysis complete! Found ${result.threats.length} security findings.`, 'Success');
    } catch (wsError) {
      // Fallback to REST API
      console.warn('WebSocket failed, falling back to REST:', wsError.message);
      try {
        const result = await analyzeSystem(description, name, useLocalSlm, options);
        setData(result);
        saveAnalysis(name, result);
        toast.success(`Analysis complete! Found ${result.threats.length} security findings.`, 'Success');
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
        toast.success(`IaC Analysis complete! Found ${result.threats.length} security findings.`, 'Success');
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

  const handleCodeAnalyze = async (codeContent, name, language) => {
    setProjectName(name);
    setData(null);
    setIsAnalyzing(true);
    try {
      const result = await analyzeCode(codeContent, name, language);
      setData(result);
      saveAnalysis(name, result);
      toast.success(`Code analysis complete! Found ${result.threats.length} security findings.`, 'Success');
    } catch (error) {
      console.error('Code analysis failed', error);
      toast.error(error.message || 'Failed to analyze source code.', 'Analysis Failed');
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

  // Re-running an edited model is the ordinary analysis path with the model as
  // its input; the structured format parses without inference, so only what the
  // reviewer changed changes.
  const handleReanalyze = (architectureDocument) => {
    handleAnalyze(architectureDocument, projectName || 'Untitled', true);
  };

  const handleNewAnalysis = () => {
    setData(null);
    setProjectName('');
  };

  // Page titles and icons for the header
  const pageInfo = {
    static: { title: 'Static Analysis', subtitle: 'Rule-based + NLP + Semantic threat detection', icon: Zap, color: 'text-brand-primary' },
    code: { title: 'Code Security', subtitle: 'Evidence-backed checks for common source vulnerabilities', icon: FileCode2, color: 'text-brand-primary' },
    iac: { title: 'Infrastructure-as-Code', subtitle: 'Analyze Compose, Kubernetes, Terraform, and CloudFormation', icon: Zap, color: 'text-brand-success' },
    ai: { title: 'AI Analysis', subtitle: 'LLM-enhanced analysis with RAG', icon: Sparkles, color: 'text-brand-secondary' },
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
        collapsed={sidebarCollapsed}
        onCollapsedChange={setSidebarCollapsed}
      />

      {/* Main Content — offset by sidebar width */}
      <div className={`${sidebarCollapsed ? 'ml-[68px]' : 'ml-[220px]'} transition-all duration-300`}>
        {/* Top Bar */}
        <header className="sticky top-0 z-40 border-b border-brand-200 bg-white/95 dark:border-brand-700 dark:bg-brand-900/95">
          <div className="mx-auto flex max-w-[1440px] items-center justify-between gap-2 px-3 py-3 sm:px-8 sm:py-3.5">
            <div className="flex min-w-0 items-center gap-2 sm:gap-3">
              <div className="hidden h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-brand-200 bg-brand-50 dark:border-brand-700 dark:bg-brand-800 sm:flex">
                <PageIcon className={`w-5 h-5 ${currentPage.color}`} />
              </div>
              <div className="min-w-0">
                <h1 className="text-base font-semibold text-brand-950 dark:text-white sm:text-lg">{currentPage.title}</h1>
                <p className="hidden text-xs text-brand-500 dark:text-brand-400 md:block">{currentPage.subtitle}</p>
              </div>
            </div>
            <div className="flex shrink-0 items-center gap-2 sm:gap-3">
              {data && (
                <button
                  onClick={handleNewAnalysis}
                  className="ui-button-secondary h-9 px-2 sm:px-3.5"
                  title="Start a new analysis"
                >
                  <RotateCcw className="w-3.5 h-3.5" />
                  <span className="hidden sm:inline">New Analysis</span>
                </button>
              )}
              <div className="ui-chip hidden font-mono sm:inline-flex">
                v2.3.1
              </div>
            </div>
          </div>
        </header>

        {/* Page Content */}
        <main className="mx-auto max-w-[1440px] px-3 py-5 sm:px-8 sm:py-7">
          {activeTab === 'static' ? (
            <>
              {!data && !isAnalyzing && (
                <div className="mx-auto mb-7 w-full max-w-6xl animate-fade-in-up panel-soft px-6 py-5">
                  <div className="mb-3 inline-flex items-center gap-2 rounded-full bg-brand-primary/10 px-3 py-1 text-xs font-semibold uppercase tracking-wide text-brand-primary">
                    Local Analysis
                  </div>
                  <h2 className="mb-2 text-2xl font-semibold tracking-tight text-brand-950 dark:text-white">
                    Rule-Based Threat Detection
                  </h2>
                  <p className="max-w-3xl text-sm leading-6 text-brand-600 dark:text-brand-400">
                    Fast, accurate threat detection using our enhanced rule engine with 60+ threat patterns, NLP-powered parsing, and semantic matching.
                  </p>
                </div>
              )}

              {!data && <ThreatInput onAnalyze={handleAnalyze} isAnalyzing={isAnalyzing || streaming.isAnalyzing} />}

              {activeTab === 'static' && (isAnalyzing || streaming.isAnalyzing) && (
                <div className="mx-auto flex w-full max-w-6xl flex-col items-center justify-center space-y-6 px-6 py-14 animate-fade-in-up panel-soft">
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
                        className="h-full rounded-full bg-brand-primary transition-all duration-500 ease-out"
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
                  <ThreatDashboard
                    data={data}
                    projectName={projectName}
                    darkMode={darkMode}
                    onReanalyze={handleReanalyze}
                    isAnalyzing={isAnalyzing || streaming.isAnalyzing}
                  />
                </div>
              )}
            </>
          ) : activeTab === 'code' ? (
            <>
              {!data && <CodeInput onAnalyze={handleCodeAnalyze} isAnalyzing={isAnalyzing} />}
              {isAnalyzing && (
                <div className="mx-auto flex w-full max-w-6xl items-center justify-center gap-3 px-6 py-14 panel-soft text-sm text-brand-500 dark:text-brand-400">
                  <FileCode2 className="h-5 w-5 animate-pulse text-brand-primary" />
                  Analyzing source code...
                </div>
              )}
              {data && <div className="w-full"><ThreatDashboard
                    data={data}
                    projectName={projectName}
                    darkMode={darkMode}
                    onReanalyze={handleReanalyze}
                    isAnalyzing={isAnalyzing || streaming.isAnalyzing}
                  /></div>}
            </>
          ) : activeTab === 'iac' ? (
            <>
              {!data && !isAnalyzing && (
                <div className="mx-auto mb-7 w-full max-w-6xl animate-fade-in-up panel-soft px-6 py-5">
                  <div className="mb-3 inline-flex items-center gap-2 rounded-full bg-brand-success/10 px-3 py-1 text-xs font-semibold uppercase tracking-wide text-brand-success">
                    Infrastructure
                  </div>
                  <h2 className="mb-2 text-2xl font-semibold tracking-tight text-brand-950 dark:text-white">
                    IaC Architecture Parser
                  </h2>
                  <p className="max-w-3xl text-sm leading-6 text-brand-600 dark:text-brand-400">
                    Directly parse Docker Compose and Kubernetes manifests to build architectural threat models.
                  </p>
                </div>
              )}

              {!data && <IacInput onAnalyze={handleIacAnalyze} isAnalyzing={isAnalyzing} />}

              {isAnalyzing && (
                <div className="mx-auto flex w-full max-w-6xl flex-col items-center justify-center space-y-6 px-6 py-14 animate-fade-in-up panel-soft">
                  <div className="w-10 h-10 border-3 border-brand-200 dark:border-brand-700 border-t-brand-success rounded-full animate-spin" />
                  <p className="text-sm font-mono text-brand-500 dark:text-brand-400 pb-10">Parsing Infrastructure-as-Code...</p>
                </div>
              )}

              {data && (
                <div className="w-full">
                  <ThreatDashboard
                    data={data}
                    projectName={projectName}
                    darkMode={darkMode}
                    onReanalyze={handleReanalyze}
                    isAnalyzing={isAnalyzing || streaming.isAnalyzing}
                  />
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
                  <ThreatDashboard
                    data={data}
                    projectName={projectName}
                    darkMode={darkMode}
                    onReanalyze={handleReanalyze}
                    isAnalyzing={isAnalyzing || streaming.isAnalyzing}
                  />
                </div>
              )}
            </>
          ) : (
            <AnalysisHistory onLoadAnalysis={handleLoadFromHistory} />
          )}
        </main>

        {/* Footer */}
        <footer className="mt-auto border-t border-brand-200 py-4 text-center text-xs text-brand-400 dark:border-brand-700 dark:text-brand-500">
          <p>&copy; 2026 AITM v2.3.1 • NLP &bull; Semantic Search &bull; Attack Chains &bull; Multi-LLM</p>
        </footer>
      </div>
    </div>
  );
}

export default App;
