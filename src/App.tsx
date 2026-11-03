import { useState, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield, Search, AlertTriangle, XCircle,
  Info, ChevronDown, ChevronRight, Activity, Globe,
  Zap, Lock, Bug, FileText, Terminal,
  BarChart3, Target, Radio, Wifi
} from 'lucide-react';
import { ScanResult, ScanStatus, Severity, Vulnerability } from './types';
import { simulateScan } from './scanEngine';

const severityConfig: Record<Severity, { color: string; bg: string; border: string; icon: React.ReactNode; label: string }> = {
  critical: { color: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/30', icon: <XCircle size={16} />, label: 'Critical' },
  high: { color: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/30', icon: <AlertTriangle size={16} />, label: 'High' },
  medium: { color: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/30', icon: <AlertTriangle size={16} />, label: 'Medium' },
  low: { color: 'text-blue-400', bg: 'bg-blue-500/10', border: 'border-blue-500/30', icon: <Info size={16} />, label: 'Low' },
  info: { color: 'text-gray-400', bg: 'bg-gray-500/10', border: 'border-gray-500/30', icon: <Info size={16} />, label: 'Info' },
};

function ScanInput({ onScan, isScanning }: { onScan: (url: string, type: string) => void; isScanning: boolean }) {
  const [url, setUrl] = useState('');
  const [scanType, setScanType] = useState('full');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (url.trim()) {
      onScan(url.trim(), scanType);
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="max-w-3xl mx-auto"
    >
      <div className="text-center mb-8">
        <div className="inline-flex items-center justify-center w-20 h-20 rounded-2xl bg-gradient-to-br from-cyan-500/20 to-blue-600/20 border border-cyan-500/30 mb-4">
          <Shield className="text-cyan-400" size={40} />
        </div>
        <h1 className="text-4xl font-bold text-white mb-2">VulnScan Pro</h1>
        <p className="text-gray-400 text-lg">Advanced Web Vulnerability Scanner</p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="relative">
          <Globe className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-500" size={20} />
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="Enter target URL (e.g., https://example.com)"
            className="w-full pl-12 pr-4 py-4 bg-gray-800/50 border border-gray-700 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500/50 focus:ring-2 focus:ring-cyan-500/20 transition-all text-lg"
            disabled={isScanning}
          />
        </div>

        <div className="flex flex-wrap gap-3 mb-4">
          {[
            { value: 'quick', label: 'Quick Scan', icon: <Zap size={16} />, desc: 'Fast surface-level check' },
            { value: 'full', label: 'Full Scan', icon: <Target size={16} />, desc: 'Comprehensive deep analysis' },
            { value: 'passive', label: 'Passive Scan', icon: <Radio size={16} />, desc: 'Non-intrusive observation' },
          ].map((type) => (
            <button
              key={type.value}
              type="button"
              onClick={() => setScanType(type.value)}
              className={`flex items-center gap-2 px-4 py-2.5 rounded-lg border transition-all ${
                scanType === type.value
                  ? 'bg-cyan-500/10 border-cyan-500/50 text-cyan-400'
                  : 'bg-gray-800/30 border-gray-700 text-gray-400 hover:border-gray-600'
              }`}
            >
              {type.icon}
              <span className="font-medium">{type.label}</span>
            </button>
          ))}
        </div>

        <button
          type="submit"
          disabled={isScanning || !url.trim()}
          className="w-full py-4 bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-semibold rounded-xl hover:from-cyan-400 hover:to-blue-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all flex items-center justify-center gap-3 text-lg shadow-lg shadow-cyan-500/20"
        >
          {isScanning ? (
            <>
              <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              Scanning...
            </>
          ) : (
            <>
              <Search size={20} />
              Start Vulnerability Scan
            </>
          )}
        </button>
      </form>
    </motion.div>
  );
}

function ScanProgress({ url, progress, currentCheck }: { url: string; progress: number; currentCheck: string }) {
  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      className="max-w-2xl mx-auto"
    >
      <div className="bg-gray-800/50 border border-gray-700 rounded-2xl p-8">
        <div className="flex items-center gap-4 mb-6">
          <div className="relative">
            <div className="w-14 h-14 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center">
              <Activity className="text-cyan-400 animate-pulse" size={28} />
            </div>
            <div className="absolute -top-1 -right-1 w-4 h-4 bg-cyan-500 rounded-full animate-ping" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white">Scanning Target</h2>
            <p className="text-cyan-400 font-mono text-sm">{url}</p>
          </div>
        </div>

        <div className="mb-4">
          <div className="flex justify-between text-sm mb-2">
            <span className="text-gray-400">Progress</span>
            <span className="text-cyan-400 font-mono">{Math.round(progress)}%</span>
          </div>
          <div className="h-3 bg-gray-700 rounded-full overflow-hidden">
            <motion.div
              className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 rounded-full"
              initial={{ width: 0 }}
              animate={{ width: `${progress}%` }}
              transition={{ duration: 0.3 }}
            />
          </div>
        </div>

        <div className="bg-gray-900/50 rounded-lg p-4 font-mono text-sm">
          <div className="flex items-center gap-2 text-green-400 mb-2">
            <Terminal size={14} />
            <span>Active Scan Module</span>
          </div>
          <AnimatePresence mode="wait">
            <motion.p
              key={currentCheck}
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 10 }}
              className="text-gray-300"
            >
              {currentCheck}
            </motion.p>
          </AnimatePresence>
        </div>

        <div className="grid grid-cols-3 gap-4 mt-6">
          <div className="text-center p-3 bg-gray-900/30 rounded-lg">
            <div className="text-2xl font-bold text-white font-mono">{Math.floor(progress * 0.5)}</div>
            <div className="text-xs text-gray-500">Requests</div>
          </div>
          <div className="text-center p-3 bg-gray-900/30 rounded-lg">
            <div className="text-2xl font-bold text-white font-mono">{Math.floor(progress * 0.1)}</div>
            <div className="text-xs text-gray-500">Pages</div>
          </div>
          <div className="text-center p-3 bg-gray-900/30 rounded-lg">
            <div className="text-2xl font-bold text-yellow-400 font-mono">{Math.floor(progress * 0.03)}</div>
            <div className="text-xs text-gray-500">Findings</div>
          </div>
        </div>
      </div>
    </motion.div>
  );
}

function VulnerabilityCard({ vuln, index }: { vuln: Vulnerability; index: number }) {
  const [expanded, setExpanded] = useState(false);
  const config = severityConfig[vuln.severity];

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.05 }}
      className={`border rounded-xl overflow-hidden transition-all ${config.border} ${config.bg}`}
    >
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full p-4 flex items-center gap-4 text-left hover:bg-white/5 transition-colors"
      >
        <div className={`${config.color} flex-shrink-0`}>
          {config.icon}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <h3 className="font-semibold text-white text-sm">{vuln.title}</h3>
            <span className={`px-2 py-0.5 rounded text-xs font-medium ${config.color} ${config.bg} border ${config.border}`}>
              {config.label}
            </span>
            {vuln.cvss !== undefined && vuln.cvss > 0 && (
              <span className="px-2 py-0.5 rounded text-xs font-mono bg-gray-800 text-gray-300 border border-gray-700">
                CVSS: {vuln.cvss}
              </span>
            )}
          </div>
          <p className="text-gray-500 text-xs mt-1 font-mono truncate">{vuln.location}</p>
        </div>
        <div className="flex-shrink-0 text-gray-500">
          {expanded ? <ChevronDown size={18} /> : <ChevronRight size={18} />}
        </div>
      </button>

      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <div className="px-4 pb-4 space-y-3 border-t border-gray-700/50 pt-3">
              <div>
                <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1">Description</h4>
                <p className="text-gray-300 text-sm">{vuln.description}</p>
              </div>
              <div>
                <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1">Location</h4>
                <code className="text-cyan-400 text-sm bg-gray-900/50 px-2 py-1 rounded block font-mono">{vuln.location}</code>
              </div>
              <div>
                <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1">Evidence</h4>
                <code className="text-green-400 text-sm bg-gray-900/50 px-2 py-1 rounded block font-mono whitespace-pre-wrap">{vuln.evidence}</code>
              </div>
              <div>
                <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1">Remediation</h4>
                <p className="text-gray-300 text-sm">{vuln.remediation}</p>
              </div>
              {vuln.cwe && (
                <div className="flex items-center gap-4">
                  <span className="px-2 py-1 rounded text-xs font-mono bg-purple-500/10 text-purple-400 border border-purple-500/30">
                    {vuln.cwe}
                  </span>
                  <span className="text-xs text-gray-500">Category: {vuln.category}</span>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

function SeverityChart({ breakdown }: { breakdown: Record<Severity, number> }) {
  const total = Object.values(breakdown).reduce((a, b) => a + b, 0);
  const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

  return (
    <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6">
      <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
        <BarChart3 size={20} className="text-cyan-400" />
        Severity Distribution
      </h3>
      <div className="space-y-3">
        {severities.map((sev) => {
          const count = breakdown[sev];
          const percentage = total > 0 ? (count / total) * 100 : 0;
          const config = severityConfig[sev];
          return (
            <div key={sev} className="flex items-center gap-3">
              <span className={`w-20 text-sm font-medium ${config.color}`}>{config.label}</span>
              <div className="flex-1 h-6 bg-gray-700/50 rounded-full overflow-hidden">
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${percentage}%` }}
                  transition={{ duration: 0.8, delay: 0.2 }}
                  className={`h-full rounded-full ${
                    sev === 'critical' ? 'bg-red-500' :
                    sev === 'high' ? 'bg-orange-500' :
                    sev === 'medium' ? 'bg-yellow-500' :
                    sev === 'low' ? 'bg-blue-500' : 'bg-gray-500'
                  }`}
                />
              </div>
              <span className="w-8 text-right text-sm font-mono text-gray-400">{count}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function ScanResults({ result, onNewScan }: { result: ScanResult; onNewScan: () => void }) {
  const [filter, setFilter] = useState<Severity | 'all'>('all');

  const filteredVulns = filter === 'all'
    ? result.vulnerabilities
    : result.vulnerabilities.filter((v) => v.severity === filter);

  const riskScore = Math.max(0, 100 - (
    result.severityBreakdown.critical * 25 +
    result.severityBreakdown.high * 15 +
    result.severityBreakdown.medium * 8 +
    result.severityBreakdown.low * 3 +
    result.severityBreakdown.info * 1
  ));

  const getRiskColor = () => {
    if (riskScore >= 80) return 'text-green-400';
    if (riskScore >= 60) return 'text-yellow-400';
    if (riskScore >= 40) return 'text-orange-400';
    return 'text-red-400';
  };

  const getRiskLabel = () => {
    if (riskScore >= 80) return 'Low Risk';
    if (riskScore >= 60) return 'Medium Risk';
    if (riskScore >= 40) return 'High Risk';
    return 'Critical Risk';
  };

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      className="max-w-6xl mx-auto"
    >
      {/* Header */}
      <div className="flex items-center justify-between mb-6 flex-wrap gap-4">
        <div>
          <h2 className="text-2xl font-bold text-white">Scan Results</h2>
          <p className="text-gray-400 font-mono text-sm mt-1">{result.target}</p>
        </div>
        <button
          onClick={onNewScan}
          className="px-4 py-2 bg-gray-800 border border-gray-700 text-gray-300 rounded-lg hover:bg-gray-700 transition-colors flex items-center gap-2"
        >
          <Search size={16} />
          New Scan
        </button>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3 mb-6">
        <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-4 text-center">
          <div className={`text-3xl font-bold font-mono ${getRiskColor()}`}>{riskScore}</div>
          <div className="text-xs text-gray-500 mt-1">{getRiskLabel()}</div>
        </div>
        <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-4 text-center">
          <div className="text-3xl font-bold font-mono text-white">{result.totalVulnerabilities}</div>
          <div className="text-xs text-gray-500 mt-1">Total Issues</div>
        </div>
        <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-4 text-center">
          <div className="text-3xl font-bold font-mono text-red-400">{result.severityBreakdown.critical}</div>
          <div className="text-xs text-gray-500 mt-1">Critical</div>
        </div>
        <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-4 text-center">
          <div className="text-3xl font-bold font-mono text-orange-400">{result.severityBreakdown.high}</div>
          <div className="text-xs text-gray-500 mt-1">High</div>
        </div>
        <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-4 text-center">
          <div className="text-3xl font-bold font-mono text-white">{result.pagesScanned}</div>
          <div className="text-xs text-gray-500 mt-1">Pages</div>
        </div>
        <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-4 text-center">
          <div className="text-3xl font-bold font-mono text-white">{result.requestsMade}</div>
          <div className="text-xs text-gray-500 mt-1">Requests</div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Chart + Info */}
        <div className="space-y-6">
          <SeverityChart breakdown={result.severityBreakdown} />

          <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
              <FileText size={20} className="text-cyan-400" />
              Scan Details
            </h3>
            <div className="space-y-3 text-sm">
              <div className="flex justify-between">
                <span className="text-gray-400">Duration</span>
                <span className="text-white font-mono">{(result.duration / 1000).toFixed(1)}s</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Categories</span>
                <span className="text-white font-mono">{result.categoriesScanned.length}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Start Time</span>
                <span className="text-white font-mono">{result.startTime.toLocaleTimeString()}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">End Time</span>
                <span className="text-white font-mono">{result.endTime.toLocaleTimeString()}</span>
              </div>
            </div>
          </div>

          <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
              <Wifi size={20} className="text-cyan-400" />
              Modules Scanned
            </h3>
            <div className="flex flex-wrap gap-2">
              {result.categoriesScanned.map((cat) => (
                <span key={cat} className="px-2 py-1 text-xs bg-gray-700/50 text-gray-300 rounded-md border border-gray-600">
                  {cat}
                </span>
              ))}
            </div>
          </div>
        </div>

        {/* Right: Vulnerability List */}
        <div className="lg:col-span-2">
          <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6">
            <div className="flex items-center justify-between mb-4 flex-wrap gap-3">
              <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                <Bug size={20} className="text-cyan-400" />
                Findings ({filteredVulns.length})
              </h3>
              <div className="flex gap-1 flex-wrap">
                {(['all', 'critical', 'high', 'medium', 'low', 'info'] as const).map((sev) => (
                  <button
                    key={sev}
                    onClick={() => setFilter(sev)}
                    className={`px-3 py-1 rounded-md text-xs font-medium transition-all ${
                      filter === sev
                        ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/50'
                        : 'text-gray-400 hover:text-gray-200 border border-transparent'
                    }`}
                  >
                    {sev === 'all' ? 'All' : severityConfig[sev].label}
                  </button>
                ))}
              </div>
            </div>

            <div className="space-y-2 max-h-[600px] overflow-y-auto pr-2 custom-scrollbar">
              {filteredVulns.map((vuln, index) => (
                <VulnerabilityCard key={vuln.id} vuln={vuln} index={index} />
              ))}
            </div>
          </div>
        </div>
      </div>
    </motion.div>
  );
}

export default function App() {
  const [status, setStatus] = useState<ScanStatus>('idle');
  const [result, setResult] = useState<ScanResult | null>(null);
  const [progress, setProgress] = useState(0);
  const [currentCheck, setCurrentCheck] = useState('');
  const [scanTarget, setScanTarget] = useState('');

  const scanChecks = [
    'Enumerating endpoints and crawling pages...',
    'Testing for SQL injection vectors...',
    'Checking for XSS vulnerabilities...',
    'Analyzing authentication mechanisms...',
    'Testing CSRF protections...',
    'Scanning for information disclosure...',
    'Checking SSL/TLS configuration...',
    'Analyzing HTTP security headers...',
    'Testing for path traversal...',
    'Checking CORS configuration...',
    'Analyzing cookie security flags...',
    'Testing for XXE vulnerabilities...',
    'Checking for open redirects...',
    'Analyzing API security controls...',
    'Testing JWT implementation...',
    'Finalizing scan and generating report...',
  ];

  const handleScan = useCallback(async (url: string, scanType: string) => {
    setStatus('scanning');
    setProgress(0);
    setResult(null);
    setScanTarget(url);

    const duration = scanType === 'quick' ? 5000 : scanType === 'full' ? 8000 : 3000;
    const startTime = Date.now();

    const progressInterval = setInterval(() => {
      const elapsed = Date.now() - startTime;
      const newProgress = Math.min((elapsed / duration) * 100, 99);
      setProgress(newProgress);

      const checkIndex = Math.floor((newProgress / 100) * scanChecks.length);
      setCurrentCheck(scanChecks[Math.min(checkIndex, scanChecks.length - 1)]);
    }, 100);

    const scanResult = await simulateScan(url, scanType);
    clearInterval(progressInterval);
    setProgress(100);

    setTimeout(() => {
      setResult(scanResult);
      setStatus('complete');
    }, 500);
  }, []);

  const handleNewScan = () => {
    setStatus('idle');
    setResult(null);
    setProgress(0);
    setScanTarget('');
  };

  return (
    <div className="min-h-screen bg-gray-950 text-white">
      {/* Background effects */}
      <div className="fixed inset-0 pointer-events-none">
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl" />
        <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-blue-500/5 rounded-full blur-3xl" />
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,_var(--tw-gradient-stops))] from-gray-900 via-gray-950 to-black" />
      </div>

      {/* Header */}
      <header className="relative z-10 border-b border-gray-800/50 backdrop-blur-sm">
        <div className="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center">
              <Shield size={18} className="text-white" />
            </div>
            <span className="font-bold text-lg text-white">VulnScan<span className="text-cyan-400">Pro</span></span>
          </div>
          <div className="flex items-center gap-4 text-sm">
            <span className="flex items-center gap-2 text-gray-400">
              <Lock size={14} className="text-green-400" />
              Secure Connection
            </span>
            <span className="text-gray-600">v2.4.1</span>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="relative z-10 max-w-7xl mx-auto px-4 py-8">
        <AnimatePresence mode="wait">
          {status === 'idle' && (
            <motion.div
              key="input"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="py-12"
            >
              <ScanInput onScan={handleScan} isScanning={false} />

              {/* Features */}
              <div className="max-w-4xl mx-auto mt-16 grid grid-cols-1 md:grid-cols-3 gap-6">
                {[
                  { icon: <Search size={24} />, title: 'Deep Scanning', desc: 'Comprehensive analysis of web applications for security vulnerabilities' },
                  { icon: <Shield size={24} />, title: '15+ OWASP Checks', desc: 'Tests for all major OWASP Top 10 vulnerabilities and more' },
                  { icon: <FileText size={24} />, title: 'Detailed Reports', desc: 'Actionable remediation guidance with evidence and CVSS scores' },
                ].map((feature, i) => (
                  <motion.div
                    key={i}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.3 + i * 0.1 }}
                    className="bg-gray-800/30 border border-gray-700/50 rounded-xl p-6 text-center"
                  >
                    <div className="inline-flex items-center justify-center w-12 h-12 rounded-lg bg-cyan-500/10 text-cyan-400 mb-3">
                      {feature.icon}
                    </div>
                    <h3 className="font-semibold text-white mb-1">{feature.title}</h3>
                    <p className="text-gray-400 text-sm">{feature.desc}</p>
                  </motion.div>
                ))}
              </div>
            </motion.div>
          )}

          {status === 'scanning' && (
            <motion.div
              key="scanning"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="py-12"
            >
              <ScanProgress url={scanTarget} progress={progress} currentCheck={currentCheck} />
            </motion.div>
          )}

          {status === 'complete' && result && (
            <motion.div
              key="results"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
            >
              <ScanResults result={result} onNewScan={handleNewScan} />
            </motion.div>
          )}
        </AnimatePresence>
      </main>
    </div>
  );
}
