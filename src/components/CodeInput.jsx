import React, { useState } from 'react';
import { Braces, FileCode2, Send, Upload } from 'lucide-react';

const CodeInput = ({ onAnalyze, isAnalyzing }) => {
  const [codeContent, setCodeContent] = useState('');
  const [projectName, setProjectName] = useState('Source Security Audit');
  const [language, setLanguage] = useState('auto');

  const submit = (event) => {
    event.preventDefault();
    if (codeContent.trim() && !isAnalyzing) onAnalyze(codeContent, projectName, language);
  };

  const upload = (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    const extension = file.name.split('.').pop()?.toLowerCase();
    const languageMap = { js: 'javascript', jsx: 'javascript', ts: 'typescript', tsx: 'typescript', py: 'python', java: 'java', go: 'go', php: 'php', rb: 'ruby' };
    setLanguage(languageMap[extension] || 'auto');
    const reader = new FileReader();
    reader.onload = (loadEvent) => setCodeContent(String(loadEvent.target?.result || ''));
    reader.readAsText(file);
  };

  return (
    <div className="mx-auto w-full max-w-6xl animate-fade-in-up panel-soft px-6 py-6">
      <form onSubmit={submit} className="space-y-4">
        <div className="grid gap-4 md:grid-cols-[1fr_220px]">
          <div>
            <label className="ui-label">Project Name</label>
            <input value={projectName} onChange={(event) => setProjectName(event.target.value)} className="input-brand w-full font-mono" />
          </div>
          <div>
            <label className="ui-label">Language</label>
            <select value={language} onChange={(event) => setLanguage(event.target.value)} className="input-brand w-full font-mono text-sm py-2">
              <option value="auto">Auto-detect</option>
              <option value="javascript">JavaScript</option>
              <option value="typescript">TypeScript</option>
              <option value="python">Python</option>
              <option value="java">Java</option>
              <option value="go">Go</option>
              <option value="php">PHP</option>
            </select>
          </div>
        </div>

        <div className="flex items-center justify-between gap-4">
          <label className="flex h-10 cursor-pointer items-center gap-2 text-sm font-medium text-brand-600 dark:text-brand-300">
            <Upload className="h-4 w-4" />
            <span>Upload source file</span>
            <input type="file" className="hidden" accept=".js,.jsx,.ts,.tsx,.py,.java,.go,.php,.rb" onChange={upload} />
          </label>
          <FileCode2 className="h-5 w-5 text-brand-primary" />
        </div>

        <textarea
          value={codeContent}
          onChange={(event) => setCodeContent(event.target.value)}
          disabled={isAnalyzing}
          spellCheck="false"
          className="input-brand h-80 w-full resize-y bg-brand-50 font-mono text-sm leading-relaxed dark:bg-brand-900/50"
          placeholder={'db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);'}
        />

        <div className="flex justify-end">
          <button type="submit" disabled={isAnalyzing || !codeContent.trim()} className={`inline-flex items-center gap-2 rounded-lg bg-brand-primary px-4 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-brand-800 ${isAnalyzing ? 'cursor-not-allowed opacity-50' : ''}`}>
            {isAnalyzing ? <Braces className="h-4 w-4 animate-pulse" /> : <Send className="h-4 w-4" />}
            Analyze Source
          </button>
        </div>
      </form>
    </div>
  );
};

export default CodeInput;
