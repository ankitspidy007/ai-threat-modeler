import React, { useState } from 'react';
import ThreatInput from './components/ThreatInput';
import ThreatDashboard from './components/ThreatDashboard';
import { analyzeSystem } from './services/mockAi';
import { Shield } from 'lucide-react';

function App() {
  const [data, setData] = useState(null);
  const [projectName, setProjectName] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  const handleAnalyze = async (description, name) => {
    setIsAnalyzing(true);
    setProjectName(name);
    // Clear previous data
    setData(null);
    try {
      const result = await analyzeSystem(description, name);
      setData(result);
    } catch (error) {
      console.error("Analysis failed", error);
    } finally {
      setIsAnalyzing(false);
    }
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
      </header>

      <main className="container mx-auto px-4 py-10 flex flex-col items-center">
        {!data && !isAnalyzing && (
          <div className="text-center mb-12 max-w-2xl animate-fade-in-up">
            <h2 className="text-4xl font-bold mb-4 text-brand-900">
              AI-Powered Threat Modeling
            </h2>
            <p className="text-brand-600 text-lg">
              Describe your system architecture and let our AI engine identify potential vulnerabilities using the STRIDE model.
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
      </main>

      <footer className="py-6 text-center text-brand-500 text-sm border-t border-brand-200 mt-auto bg-white">
        <p>&copy; 2026 AITM (AI based threat modeling). Secure by Design.</p>
      </footer>
    </div>
  );
}

export default App;
