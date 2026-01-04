import { Loader2, FileSearch, Shield, CheckCircle2 } from 'lucide-react';

interface ScanProgressProps {
  repoUrl: string;
  filesScanned: number;
}

export default function ScanProgress({ repoUrl, filesScanned }: ScanProgressProps) {
  const repoName = repoUrl.split('/').slice(-2).join('/');

  return (
    <div className="max-w-4xl mx-auto px-4 py-12">
      <div className="bg-white rounded-2xl shadow-xl border border-slate-200 p-8">
        <div className="text-center">
          <div className="flex justify-center mb-6">
            <div className="relative">
              <Shield className="w-16 h-16 text-blue-600" />
              <Loader2 className="w-8 h-8 text-blue-600 absolute -top-1 -right-1 animate-spin" />
            </div>
          </div>

          <h2 className="text-3xl font-bold text-slate-900 mb-3">
            Scanning Repository
          </h2>

          <p className="text-lg text-slate-600 mb-8">
            {repoName}
          </p>

          <div className="space-y-4 max-w-md mx-auto">
            <div className="flex items-center justify-between p-4 bg-blue-50 rounded-lg border border-blue-200">
              <div className="flex items-center">
                <CheckCircle2 className="w-5 h-5 text-blue-600 mr-3" />
                <span className="text-slate-700 font-medium">Repository cloned</span>
              </div>
            </div>

            <div className="flex items-center justify-between p-4 bg-blue-50 rounded-lg border border-blue-200">
              <div className="flex items-center">
                <Loader2 className="w-5 h-5 text-blue-600 mr-3 animate-spin" />
                <span className="text-slate-700 font-medium">Analyzing files</span>
              </div>
              <span className="text-blue-600 font-semibold">{filesScanned}</span>
            </div>

            <div className="flex items-center justify-between p-4 bg-slate-50 rounded-lg border border-slate-200 opacity-50">
              <div className="flex items-center">
                <FileSearch className="w-5 h-5 text-slate-400 mr-3" />
                <span className="text-slate-500 font-medium">Running security checks</span>
              </div>
            </div>
          </div>

          <div className="mt-8 text-sm text-slate-500">
            This may take a few minutes depending on repository size...
          </div>
        </div>
      </div>
    </div>
  );
}
