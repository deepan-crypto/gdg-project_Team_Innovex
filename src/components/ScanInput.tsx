import { useState } from 'react';
import { Github, Lock, AlertCircle, Upload, X } from 'lucide-react';
import type { ScanRequest } from '../types/scan';

interface ScanInputProps {
  onScanStart: (request: ScanRequest) => void;
  isScanning: boolean;
}

export default function ScanInput({ onScanStart, isScanning }: ScanInputProps) {
  const [repoUrl, setRepoUrl] = useState('');
  const [githubToken, setGithubToken] = useState('');
  const [showTokenInput, setShowTokenInput] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setSelectedFile(file);
      setRepoUrl(''); // Clear repo URL when file is selected
    }
  };

  const handleRemoveFile = () => {
    setSelectedFile(null);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (repoUrl.trim()) {
      onScanStart({
        repo_url: repoUrl.trim(),
        github_token: githubToken.trim() || undefined,
      });
    } else if (selectedFile) {
      // Handle file upload
      onScanStart({
        repo_url: `file://${selectedFile.name}`,
        github_token: undefined,
      });
    }
  };

  const isValidGithubUrl = (url: string) => {
    // Strict validation: only allow alphanumeric, hyphens, underscores, and dots
    // This prevents special regex characters that could cause backend parsing issues
    const githubPattern = /^https?:\/\/(www\.)?github\.com\/[a-zA-Z0-9_-]+\/[a-zA-Z0-9._-]+(\/)?$/;
    return githubPattern.test(url.trim());
  };

  const hasSpecialCharacters = (url: string) => {
    // Check for characters that could cause regex issues on the backend
    const specialChars = /[\[\]\(\)\{\}\*\+\?\^\$\|\\]/;
    return specialChars.test(url);
  };

  const urlHasSpecialChars = repoUrl && hasSpecialCharacters(repoUrl);
  const urlIsValid = !repoUrl || (isValidGithubUrl(repoUrl) && !urlHasSpecialChars);

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
              onChange={(e) => {
                setRepoUrl(e.target.value);
                if (e.target.value.trim()) {
                  setSelectedFile(null); // Clear file when URL is entered
                }
              }}
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
                {urlHasSpecialChars 
                  ? 'URL contains special characters that are not allowed'
                  : 'Please enter a valid GitHub repository URL (e.g., https://github.com/owner/repo)'}
              </p>
            )}
          </div>

          {/* File Upload Option */}
          <div>
            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-slate-300"></div>
              </div>
              <div className="relative flex justify-center text-sm">
                <span className="px-2 bg-white text-slate-500">OR</span>
              </div>
            </div>
          </div>

          <div>
            <label className="block text-sm font-semibold text-slate-700 mb-2">
              Upload Repository Archive
            </label>
            <div className="relative">
              <input
                type="file"
                id="file-upload"
                onChange={handleFileChange}
                accept=".zip,.tar,.tar.gz,.tgz"
                className="hidden"
                disabled={isScanning || !!repoUrl.trim()}
              />
              <label
                htmlFor="file-upload"
                className={`flex items-center justify-center w-full px-4 py-3 border-2 border-dashed rounded-lg cursor-pointer transition-colors ${
                  isScanning || repoUrl.trim()
                    ? 'border-slate-200 bg-slate-50 cursor-not-allowed'
                    : 'border-slate-300 hover:border-blue-400 hover:bg-blue-50'
                }`}
              >
                <Upload className="w-5 h-5 text-slate-500 mr-2" />
                <span className="text-slate-600">
                  {selectedFile ? selectedFile.name : 'Choose a file (ZIP, TAR, TGZ)'}
                </span>
              </label>
            </div>
            {selectedFile && (
              <div className="mt-2 flex items-center justify-between bg-blue-50 border border-blue-200 rounded-lg px-3 py-2">
                <div className="flex items-center text-sm text-blue-700">
                  <Upload className="w-4 h-4 mr-2" />
                  <span className="font-medium">{selectedFile.name}</span>
                  <span className="ml-2 text-blue-500">
                    ({(selectedFile.size / 1024 / 1024).toFixed(2)} MB)
                  </span>
                </div>
                <button
                  type="button"
                  onClick={handleRemoveFile}
                  className="text-blue-600 hover:text-blue-800"
                  disabled={isScanning}
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            )}
            <p className="mt-2 text-sm text-slate-600">
              Upload a ZIP or TAR archive of your repository code
            </p>
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
            disabled={isScanning || (!repoUrl.trim() && !selectedFile) || (!!repoUrl && !urlIsValid)}
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
