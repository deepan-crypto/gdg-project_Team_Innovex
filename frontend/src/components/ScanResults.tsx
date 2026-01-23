import { CheckCircle2, AlertTriangle, FileSearch, Download, RotateCcw } from 'lucide-react';
import type { ScanResult } from '../types/scan';
import VulnerabilityCard from './VulnerabilityCard';

interface ScanResultsProps {
  result: ScanResult;
  onNewScan: () => void;
}

export default function ScanResults({ result, onNewScan }: ScanResultsProps) {
  const repoName = result.repo_url.split('/').slice(-2).join('/');
  const totalVulnerabilities = result.vulnerabilities.length;
  const hasVulnerabilities = totalVulnerabilities > 0;

  const handleExportReport = () => {
    // Create a comprehensive report
    const report = {
      scan_summary: {
        repository: repoName,
        scan_date: result.scan_date,
        total_files_scanned: result.total_files_scanned,
        status: result.status,
        vulnerability_summary: result.summary,
        total_vulnerabilities: totalVulnerabilities
      },
      vulnerabilities: result.vulnerabilities.map(vuln => ({
        id: vuln.id,
        type: vuln.type,
        severity: vuln.severity,
        title: vuln.title,
        description: vuln.description,
        file_path: vuln.file_path,
        line_number: vuln.line_number,
        code_snippet: vuln.code_snippet,
        explanation: vuln.explanation,
        risk: vuln.risk,
        fix: vuln.fix,
        references: vuln.references || []
      }))
    };

    // Convert to JSON string
    const reportJson = JSON.stringify(report, null, 2);
    
    // Create blob and download
    const blob = new Blob([reportJson], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    
    // Create temporary link and trigger download
    const link = document.createElement('a');
    link.href = url;
    link.download = `security-scan-report-${repoName.replace('/', '-')}-${new Date(result.scan_date).toISOString().split('T')[0]}.json`;
    document.body.appendChild(link);
    link.click();
    
    // Cleanup
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const summaryItems = [
    { label: 'Critical', count: result.summary.critical, color: 'text-red-600' },
    { label: 'High', count: result.summary.high, color: 'text-orange-600' },
    { label: 'Medium', count: result.summary.medium, color: 'text-yellow-600' },
    { label: 'Low', count: result.summary.low, color: 'text-blue-600' },
    { label: 'Info', count: result.summary.info, color: 'text-slate-600' },
  ];

  return (
    <div className="max-w-7xl mx-auto px-4 py-12">
      <div className="bg-white rounded-2xl shadow-xl border border-slate-200 p-8 mb-8">
        <div className="flex items-start justify-between mb-6">
          <div>
            <h2 className="text-3xl font-bold text-slate-900 mb-2">
              Scan Results
            </h2>
            <p className="text-lg text-slate-600">
              {repoName}
            </p>
            <p className="text-sm text-slate-500 mt-1">
              Scanned {result.total_files_scanned} files on {new Date(result.scan_date).toLocaleDateString()}
            </p>
          </div>
          <div className="flex space-x-3">
            <button
              onClick={onNewScan}
              className="flex items-center space-x-2 px-4 py-2 border-2 border-slate-300 text-slate-700 font-semibold rounded-lg hover:bg-slate-50 transition-colors"
            >
              <RotateCcw className="w-4 h-4" />
              <span>New Scan</span>
            </button>
            <button 
              onClick={handleExportReport}
              className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white font-semibold rounded-lg hover:bg-blue-700 transition-colors"
            >
              <Download className="w-4 h-4" />
              <span>Export Report</span>
            </button>
          </div>
        </div>

        {hasVulnerabilities ? (
          <div className="bg-red-50 border-2 border-red-200 rounded-xl p-6 mb-6">
            <div className="flex items-start space-x-3">
              <AlertTriangle className="w-6 h-6 text-red-600 flex-shrink-0 mt-1" />
              <div>
                <h3 className="text-xl font-bold text-red-900 mb-1">
                  {totalVulnerabilities} Security {totalVulnerabilities === 1 ? 'Issue' : 'Issues'} Found
                </h3>
                <p className="text-red-700">
                  This repository contains security vulnerabilities that need attention.
                  Review each issue below to understand the risks and fixes.
                </p>
              </div>
            </div>
          </div>
        ) : (
          <div className="bg-green-50 border-2 border-green-200 rounded-xl p-6 mb-6">
            <div className="flex items-start space-x-3">
              <CheckCircle2 className="w-6 h-6 text-green-600 flex-shrink-0 mt-1" />
              <div>
                <h3 className="text-xl font-bold text-green-900 mb-1">
                  No Vulnerabilities Detected
                </h3>
                <p className="text-green-700">
                  Great job! This repository passed all security checks.
                </p>
              </div>
            </div>
          </div>
        )}

        <div className="grid grid-cols-2 sm:grid-cols-5 gap-4">
          {summaryItems.map((item) => (
            <div
              key={item.label}
              className="bg-slate-50 rounded-lg p-4 border border-slate-200"
            >
              <div className={`text-3xl font-bold ${item.color} mb-1`}>
                {item.count}
              </div>
              <div className="text-sm text-slate-600 font-medium">
                {item.label}
              </div>
            </div>
          ))}
        </div>
      </div>

      {hasVulnerabilities ? (
        <div className="space-y-6">
          <div className="flex items-center space-x-2 mb-4">
            <FileSearch className="w-6 h-6 text-slate-700" />
            <h3 className="text-2xl font-bold text-slate-900">
              Vulnerability Details
            </h3>
          </div>

          {result.vulnerabilities.map((vuln) => (
            <VulnerabilityCard key={vuln.id} vulnerability={vuln} />
          ))}
        </div>
      ) : (
        <div className="text-center py-12 bg-slate-50 rounded-xl border border-slate-200">
          <CheckCircle2 className="w-16 h-16 text-green-600 mx-auto mb-4" />
          <p className="text-slate-600 text-lg">
            Keep up the good security practices!
          </p>
        </div>
      )}
    </div>
  );
}
