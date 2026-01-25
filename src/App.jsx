import React, { useState } from 'react';
import ThreatInput from './components/ThreatInput';
import ThreatDashboard from './components/ThreatDashboard';
import { analyzeSystem } from './services/mockAi';
import { Shield } from 'lucide-react';

function App() {
  const [data, setData] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  const handleAnalyze = async (description) => {
    setIsAnalyzing(true);
    // Clear previous data
    setData(null);
    try {
      const result = await analyzeSystem(description);
      setData(result);
    } catch (error) {
      console.error("Analysis failed", error);
    } finally {
      setIsAnalyzing(false);
    }
  };

  return (
    <div className="min-h-screen text-gray-100 selection:bg-cyber-accent selection:text-cyber-900">
      <header className="border-b border-cyber-700 bg-cyber-800/50 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="relative">
              <div className="absolute inset-0 bg-cyber-accent blur-md opacity-50 animate-pulse"></div>
              <Shield className="w-8 h-8 text-cyber-accent relative z-10" />
            </div>
            <h1 className="text-2xl font-bold tracking-tight">
              <span className="text-white">AITM</span>
              <span className="text-cyber-accent text-sm ml-2">(AI based threat modeling)</span>
            </h1>
          </div>
          <div className="text-xs font-mono text-cyber-muted border border-cyber-700 px-2 py-1 rounded">
            v1.0.0-alpha
          </div>
        </div>
      </header>

      <main className="container mx-auto px-4 py-10 flex flex-col items-center">
        {!data && !isAnalyzing && (
          <div className="text-center mb-12 max-w-2xl animate-fade-in-up">
            <h2 className="text-4xl font-bold mb-4 bg-gradient-to-r from-white to-cyber-muted bg-clip-text text-transparent">
              AI-Powered Threat Modeling
            </h2>
            <p className="text-cyber-muted text-lg">
              Describe your system architecture and let our AI engine identify potential vulnerabilities using the STRIDE model.
            </p>
          </div>
        )}

        <ThreatInput onAnalyze={handleAnalyze} isAnalyzing={isAnalyzing} />

        {isAnalyzing && (
          <div className="flex flex-col items-center justify-center py-20 animate-pulse">
            <div className="w-16 h-16 border-4 border-cyber-700 border-t-cyber-accent rounded-full animate-spin mb-4"></div>
            <p className="text-cyber-accent font-mono">SCANNING NEURAL VECTORS...</p>
          </div>
        )}

        <ThreatDashboard data={data} />
      </main>

      <footer className="py-6 text-center text-cyber-muted text-sm border-t border-cyber-800/50 mt-auto">
        <p>&copy; 2026 AITM (AI based threat modeling). Secure by Design.</p>
      </footer>
    </div>
  );
}

export default App;
