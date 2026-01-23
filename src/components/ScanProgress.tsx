import { Loader2, FileSearch, Shield, CheckCircle2 } from 'lucide-react';

interface ScanProgressProps {
  repoUrl: string;
  filesScanned: number;
  progress?: number;
  status?: string;
}

export default function ScanProgress({ 
  repoUrl, 
  filesScanned, 
  progress = 0, 
  status = 'Scanning...' 
}: ScanProgressProps) {
  const repoName = repoUrl.split('/').slice(-2).join('/');

  // Determine which steps are complete based on progress
  const isCloned = progress >= 10;
  const isAnalyzing = progress >= 20 && progress < 80;
  const isSecurityCheck = progress >= 80;
  const isComplete = progress >= 100;

  return (
    <div className="max-w-4xl mx-auto px-4 py-12">
      <div className="bg-white rounded-2xl shadow-xl border border-slate-200 p-8">
        <div className="text-center">
          <div className="flex justify-center mb-6">
            <div className="relative">
              <Shield className="w-16 h-16 text-blue-600" />
              {!isComplete && (
                <Loader2 className="w-8 h-8 text-blue-600 absolute -top-1 -right-1 animate-spin" />
              )}
              {isComplete && (
                <CheckCircle2 className="w-8 h-8 text-green-600 absolute -top-1 -right-1" />
              )}
            </div>
          </div>

          <h2 className="text-3xl font-bold text-slate-900 mb-3">
            {isComplete ? 'Scan Complete' : 'Scanning Repository'}
          </h2>

          <p className="text-lg text-slate-600 mb-2">
            {repoName}
          </p>

          {status && (
            <p className="text-sm text-blue-600 mb-6">
              {status}
            </p>
          )}

          {/* Progress bar */}
          <div className="max-w-md mx-auto mb-6">
            <div className="w-full bg-slate-200 rounded-full h-2.5">
              <div 
                className="bg-blue-600 h-2.5 rounded-full transition-all duration-300"
                style={{ width: `${progress}%` }}
              />
            </div>
            <div className="text-right text-sm text-slate-500 mt-1">{progress}%</div>
          </div>

          <div className="space-y-4 max-w-md mx-auto">
            <div className={`flex items-center justify-between p-4 rounded-lg border ${
              isCloned 
                ? 'bg-green-50 border-green-200' 
                : 'bg-blue-50 border-blue-200'
            }`}>
              <div className="flex items-center">
                {isCloned ? (
                  <CheckCircle2 className="w-5 h-5 text-green-600 mr-3" />
                ) : (
                  <Loader2 className="w-5 h-5 text-blue-600 mr-3 animate-spin" />
                )}
                <span className="text-slate-700 font-medium">Repository cloned</span>
              </div>
            </div>

            <div className={`flex items-center justify-between p-4 rounded-lg border ${
              isSecurityCheck
                ? 'bg-green-50 border-green-200'
                : isAnalyzing 
                  ? 'bg-blue-50 border-blue-200' 
                  : 'bg-slate-50 border-slate-200 opacity-50'
            }`}>
              <div className="flex items-center">
                {isSecurityCheck ? (
                  <CheckCircle2 className="w-5 h-5 text-green-600 mr-3" />
                ) : isAnalyzing ? (
                  <Loader2 className="w-5 h-5 text-blue-600 mr-3 animate-spin" />
                ) : (
                  <FileSearch className="w-5 h-5 text-slate-400 mr-3" />
                )}
                <span className={`font-medium ${isAnalyzing || isSecurityCheck ? 'text-slate-700' : 'text-slate-500'}`}>
                  Analyzing files
                </span>
              </div>
              {(isAnalyzing || isSecurityCheck) && (
                <span className="text-blue-600 font-semibold">{filesScanned}</span>
              )}
            </div>

            <div className={`flex items-center justify-between p-4 rounded-lg border ${
              isComplete
                ? 'bg-green-50 border-green-200'
                : isSecurityCheck 
                  ? 'bg-blue-50 border-blue-200' 
                  : 'bg-slate-50 border-slate-200 opacity-50'
            }`}>
              <div className="flex items-center">
                {isComplete ? (
                  <CheckCircle2 className="w-5 h-5 text-green-600 mr-3" />
                ) : isSecurityCheck ? (
                  <Loader2 className="w-5 h-5 text-blue-600 mr-3 animate-spin" />
                ) : (
                  <Shield className="w-5 h-5 text-slate-400 mr-3" />
                )}
                <span className={`font-medium ${isSecurityCheck || isComplete ? 'text-slate-700' : 'text-slate-500'}`}>
                  Running security checks (Garak + ML)
                </span>
              </div>
            </div>
          </div>

          {!isComplete && (
            <div className="mt-8 text-sm text-slate-500">
              This may take a few minutes depending on repository size...
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
