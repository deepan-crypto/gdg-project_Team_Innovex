import { Shield, Github, Zap, BookOpen } from 'lucide-react';

interface HeroProps {
  onStartScan: () => void;
}

export default function Hero({ onStartScan }: HeroProps) {
  return (
    <div className="bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20">
        <div className="text-center">
          <div className="flex justify-center mb-6">
            <div className="p-3 bg-blue-600 rounded-2xl">
              <Shield className="w-12 h-12" />
            </div>
          </div>

          <h1 className="text-5xl font-bold mb-6 tracking-tight">
            AI/ML Security Pentesting Platform
          </h1>

          <p className="text-xl text-slate-300 mb-4 max-w-3xl mx-auto">
            Metasploit for AI: Scan GitHub repositories for security vulnerabilities
            in machine learning and LLM projects
          </p>

          <p className="text-lg text-slate-400 mb-10 max-w-2xl mx-auto">
            Educational security analysis designed to help students and developers
            learn secure AI development practices
          </p>

          <button
            onClick={onStartScan}
            className="bg-blue-600 hover:bg-blue-700 text-white font-semibold px-8 py-4 rounded-lg text-lg transition-all transform hover:scale-105 shadow-lg"
          >
            Start Security Scan
          </button>
        </div>

        <div className="grid md:grid-cols-3 gap-8 mt-20">
          <div className="bg-slate-800/50 p-6 rounded-xl border border-slate-700">
            <Github className="w-10 h-10 text-blue-500 mb-4" />
            <h3 className="text-xl font-semibold mb-3">GitHub Integration</h3>
            <p className="text-slate-400">
              Automatically scan public and private repositories for security issues
              across your entire codebase
            </p>
          </div>

          <div className="bg-slate-800/50 p-6 rounded-xl border border-slate-700">
            <Zap className="w-10 h-10 text-blue-500 mb-4" />
            <h3 className="text-xl font-semibold mb-3">6 Vulnerability Types</h3>
            <p className="text-slate-400">
            Detect prompt injection, hardcoded secrets, SQL injection,Jailbreaks,DAN Attacks ,Encoding Attacks, XSS, Malwares

            </p>
          </div>

          <div className="bg-slate-800/50 p-6 rounded-xl border border-slate-700">
            <BookOpen className="w-10 h-10 text-blue-500 mb-4" />
            <h3 className="text-xl font-semibold mb-3">Educational Reports</h3>
            <p className="text-slate-400">
              Learn why vulnerabilities are dangerous, where they exist, and
              exactly how to fix them
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
