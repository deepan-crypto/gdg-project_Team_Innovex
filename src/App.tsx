import { useState, useCallback } from 'react';
import Hero from './components/Hero';
import ScanInput from './components/ScanInput';
import ScanProgress from './components/ScanProgress';
import ScanResults from './components/ScanResults';
import type { ScanRequest, ScanResult, Vulnerability, BackendVulnerability, BackendScanResponse } from './types/scan';
import { api } from './services/api';

type AppView = 'hero' | 'input' | 'scanning' | 'results';

/**
 * Transform backend vulnerabilities to frontend format
 */
function transformVulnerabilities(
  scannerResult: { vulnerabilities: BackendVulnerability[] },
  type: string
): Vulnerability[] {
  return scannerResult.vulnerabilities.map((vuln, index) => ({
    id: `${type}-${index}`,
    type: vuln.type as Vulnerability['type'] || type as Vulnerability['type'],
    severity: (vuln.severity?.toLowerCase() || 'medium') as Vulnerability['severity'],
    title: vuln.description?.split('.')[0] || `${type} vulnerability`,
    description: vuln.description || '',
    file_path: vuln.file || 'unknown',
    line_number: vuln.line || 0,
    code_snippet: vuln.code_snippet || '',
    explanation: vuln.why_dangerous || vuln.description || '',
    risk: vuln.why_dangerous || 'Potential security vulnerability detected',
    fix: vuln.fix || 'Review and fix the vulnerability',
    references: [],
  }));
}

/**
 * Transform backend response to frontend ScanResult format
 */
function transformBackendResponse(response: BackendScanResponse): ScanResult {
  const allVulnerabilities: Vulnerability[] = [];
  
  // Transform each scanner's results
  if (response.results.prompt_injection?.vulnerabilities) {
    allVulnerabilities.push(
      ...transformVulnerabilities(response.results.prompt_injection, 'prompt_injection')
    );
  }
  if (response.results.secrets?.vulnerabilities) {
    allVulnerabilities.push(
      ...transformVulnerabilities(response.results.secrets, 'hardcoded_secrets')
    );
  }
  if (response.results.sql_xss?.vulnerabilities) {
    allVulnerabilities.push(
      ...transformVulnerabilities(response.results.sql_xss, 'sql_injection')
    );
  }
  if (response.results.dependencies?.vulnerabilities) {
    allVulnerabilities.push(
      ...transformVulnerabilities(response.results.dependencies, 'dependency')
    );
  }
  // Handle ML-based analysis results
  if (response.results.ml_analysis?.vulnerabilities) {
    allVulnerabilities.push(
      ...transformVulnerabilities(response.results.ml_analysis, 'prompt_injection')
    );
  }

  // Calculate severity summary
  const summary = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  
  allVulnerabilities.forEach((vuln) => {
    if (vuln.severity in summary) {
      summary[vuln.severity as keyof typeof summary]++;
    }
  });

  return {
    scan_id: response.scan_id,
    repo_url: response.repo_url,
    scan_date: response.timestamp,
    status: 'completed',
    total_files_scanned: allVulnerabilities.length > 0 ? 
      new Set(allVulnerabilities.map(v => v.file_path)).size : 0,
    vulnerabilities: allVulnerabilities,
    summary,
  };
}

function App() {
  const [view, setView] = useState<AppView>('hero');
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [currentScan, setCurrentScan] = useState<ScanRequest | null>(null);
  const [filesScanned, setFilesScanned] = useState(0);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanStatus, setScanStatus] = useState('');
  const [scanError, setScanError] = useState<string | null>(null);

  const handleStartScan = () => {
    setView('input');
    setScanError(null);
  };

  const handleScanSubmit = useCallback(async (request: ScanRequest) => {
    setCurrentScan(request);
    setView('scanning');
    setFilesScanned(0);
    setScanProgress(0);
    setScanStatus('Connecting to scanner...');
    setScanError(null);

    try {
      // Try WebSocket first for real-time updates
      const cleanup = api.scanWithProgress(
        { repo_url: request.repo_url, github_token: request.github_token },
        (message) => {
          // Handle progress updates
          if (message.progress !== undefined) {
            setScanProgress(message.progress);
          }
          if (message.status) {
            setScanStatus(message.status);
          }
          // Simulate files scanned based on progress
          setFilesScanned(Math.floor((message.progress || 0) * 1.27));
          
          // Handle completion
          if (message.progress === 100 && message.results) {
            const result = transformBackendResponse({
              scan_id: message.scan_id || Math.random().toString(36).substring(7),
              repo_url: request.repo_url,
              timestamp: message.timestamp || new Date().toISOString(),
              results: message.results,
              report_path: '',
            });
            setScanResult(result);
            setView('results');
            cleanup();
          }
        },
        async (error) => {
          // Only fall back to HTTP if we haven't received any progress yet
          // This prevents falling back when the WebSocket is working but encounters a non-fatal error
          console.warn('WebSocket error, checking if fallback needed:', error);
          
          // Check if we already have progress - if so, WebSocket was working
          if (scanProgress > 20) {
            console.log('WebSocket was working (progress > 20%), not falling back to HTTP');
            setScanError(error instanceof Error ? error.message : 'Scan failed');
            setView('input');
            return;
          }
          
          console.log('Falling back to HTTP...');
          // Fallback to HTTP polling
          try {
            setScanStatus('Scanning repository (HTTP fallback)...');
            
            // Simulate progress while waiting for HTTP response
            const progressInterval = setInterval(() => {
              setScanProgress((prev) => Math.min(prev + 5, 90));
              setFilesScanned((prev) => prev + Math.floor(Math.random() * 5) + 1);
            }, 500);

            const response = await api.scanRepository({
              repo_url: request.repo_url,
              github_token: request.github_token,
            });

            clearInterval(progressInterval);
            setScanProgress(100);
            
            const result = transformBackendResponse(response as unknown as BackendScanResponse);
            setScanResult(result);
            setView('results');
          } catch (httpError) {
            console.error('HTTP scan failed:', httpError);
            setScanError(httpError instanceof Error ? httpError.message : 'Scan failed');
            setView('input');
          }
        },
        () => {
          console.log('Scan completed');
        }
      );

      // Set a timeout for the entire operation
      setTimeout(() => {
        if (view === 'scanning') {
          cleanup();
        }
      }, 120000); // 2 minute timeout

    } catch (error) {
      console.error('Scan error:', error);
      setScanError(error instanceof Error ? error.message : 'Failed to start scan');
      setView('input');
    }
  }, [view]);

  const handleNewScan = () => {
    setView('input');
    setScanResult(null);
    setCurrentScan(null);
    setFilesScanned(0);
    setScanProgress(0);
    setScanStatus('');
    setScanError(null);
  };

  return (
    <div className="min-h-screen bg-slate-50">
      <nav className="bg-white border-b border-slate-200 shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-blue-600 rounded-lg">
                <svg
                  className="w-6 h-6 text-white"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                  />
                </svg>
              </div>
              <h1 className="text-2xl font-bold text-slate-900">
                AI Security Scanner
              </h1>
            </div>
            <div className="text-sm text-slate-600">
              Powered by Garak + Gemini AI
            </div>
          </div>
        </div>
      </nav>

      {view === 'hero' && <Hero onStartScan={handleStartScan} />}

      {view === 'input' && (
        <>
          {scanError && (
            <div className="max-w-4xl mx-auto px-4 pt-4">
              <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg">
                <strong className="font-bold">Error: </strong>
                <span>{scanError}</span>
                <button
                  onClick={() => setScanError(null)}
                  className="float-right font-bold"
                >
                  ×
                </button>
              </div>
            </div>
          )}
          <ScanInput onScanStart={handleScanSubmit} isScanning={false} />
        </>
      )}

      {view === 'scanning' && currentScan && (
        <ScanProgress
          repoUrl={currentScan.repo_url}
          filesScanned={filesScanned}
          progress={scanProgress}
          status={scanStatus}
        />
      )}

      {view === 'results' && scanResult && (
        <ScanResults result={scanResult} onNewScan={handleNewScan} />
      )}

      <footer className="bg-white border-t border-slate-200 mt-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="text-center text-slate-600 text-sm">
            <p className="mb-2">
              Built for educational purposes | Hackathon PoC
            </p>
            <p className="text-slate-500">
              Detects: Prompt Injection • Jailbreaks • DAN Attacks • Encoding Attacks • Hardcoded Secrets • SQL Injection • XSS • Malware
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
