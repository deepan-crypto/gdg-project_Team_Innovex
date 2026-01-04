import { useState } from 'react';
import { Github, Lock, AlertCircle } from 'lucide-react';
import type { ScanRequest } from '../types/scan';

interface ScanInputProps {
  onScanStart: (request: ScanRequest) => void;
  isScanning: boolean;
}

export default function ScanInput({ onScanStart, isScanning }: ScanInputProps) {
  const [repoUrl, setRepoUrl] = useState('');
  const [githubToken, setGithubToken] = useState('');
  const [showTokenInput, setShowTokenInput] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (repoUrl.trim()) {
      onScanStart({
        repo_url: repoUrl.trim(),
        github_token: githubToken.trim() || undefined,
      });
    }
  };

  const isValidGithubUrl = (url: string) => {
    return url.match(/^https?:\/\/(www\.)?github\.com\/[\w-]+\/[\w.-]+/);
  };

  const urlIsValid = !repoUrl || isValidGithubUrl(repoUrl);

  return (
    <div className="max-w-4xl mx-auto px-4 py-12">
      <div className="bg-white rounded-2xl shadow-xl border border-slate-200 p-8">
        <div className="flex items-center mb-6">
          <Github className="w-8 h-8 text-slate-700 mr-3" />
          <h2 className="text-3xl font-bold text-slate-900">
            Scan Repository
          </h2>
        </div>

        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label className="block text-sm font-semibold text-slate-700 mb-2">
              GitHub Repository URL
            </label>
            <input
              type="text"
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
              placeholder="https://github.com/username/repository"
              className={`w-full px-4 py-3 border-2 rounded-lg focus:outline-none focus:ring-2 transition-colors ${
                urlIsValid
                  ? 'border-slate-300 focus:border-blue-500 focus:ring-blue-200'
                  : 'border-red-300 focus:border-red-500 focus:ring-red-200'
              }`}
              disabled={isScanning}
            />
            {!urlIsValid && (
              <p className="mt-2 text-sm text-red-600 flex items-center">
                <AlertCircle className="w-4 h-4 mr-1" />
                Please enter a valid GitHub repository URL
              </p>
            )}
          </div>

          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="block text-sm font-semibold text-slate-700">
                GitHub Token (Optional)
              </label>
              <button
                type="button"
                onClick={() => setShowTokenInput(!showTokenInput)}
                className="text-sm text-blue-600 hover:text-blue-700 font-medium"
              >
                {showTokenInput ? 'Hide' : 'Add Token'}
              </button>
            </div>

            {showTokenInput && (
              <>
                <div className="relative">
                  <Lock className="absolute left-3 top-3.5 w-5 h-5 text-slate-400" />
                  <input
                    type="password"
                    value={githubToken}
                    onChange={(e) => setGithubToken(e.target.value)}
                    placeholder="ghp_xxxxxxxxxxxx"
                    className="w-full pl-11 pr-4 py-3 border-2 border-slate-300 rounded-lg focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-colors"
                    disabled={isScanning}
                  />
                </div>
                <p className="mt-2 text-sm text-slate-600">
                  Required for private repositories. Token is never stored.
                </p>
              </>
            )}
          </div>

          <button
            type="submit"
            disabled={isScanning || !repoUrl.trim() || !urlIsValid}
            className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-slate-300 disabled:cursor-not-allowed text-white font-semibold py-4 rounded-lg transition-all transform hover:scale-[1.02] shadow-lg disabled:transform-none"
          >
            {isScanning ? 'Scanning...' : 'Start Security Scan'}
          </button>
        </form>

        <div className="mt-8 pt-6 border-t border-slate-200">
          <h3 className="text-sm font-semibold text-slate-700 mb-3">
            What we scan for:
          </h3>
          <div className="grid sm:grid-cols-2 gap-3 text-sm text-slate-600">
            <div className="flex items-center">
              <div className="w-2 h-2 bg-red-500 rounded-full mr-2"></div>
              Prompt Injection Vulnerabilities
            </div>
            <div className="flex items-center">
              <div className="w-2 h-2 bg-orange-500 rounded-full mr-2"></div>
              Hardcoded API Keys & Secrets
            </div>
            <div className="flex items-center">
              <div className="w-2 h-2 bg-yellow-500 rounded-full mr-2"></div>
              SQL Injection Patterns
            </div>
            <div className="flex items-center">
              <div className="w-2 h-2 bg-blue-500 rounded-full mr-2"></div>
              XSS Vulnerabilities
            </div>
            <div className="flex items-center">
              <div className="w-2 h-2 bg-purple-500 rounded-full mr-2"></div>
              Dependency Vulnerabilities
            </div>
            <div className="flex items-center">
              <div className="w-2 h-2 bg-pink-500 rounded-full mr-2"></div>
              Unsafe LLM Outputs
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
