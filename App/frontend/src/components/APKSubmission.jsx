import React, { useState } from 'react';
import { 
  UploadCloud, 
  Link as LinkIcon, 
  ShieldAlert, 
  AlertCircle, 
  Loader2, 
  Play, 
  Cpu,
  ArrowRight
} from 'lucide-react';
import { apiClient } from '../api/client';

export default function APKSubmission({ onInvestigationStarted }) {
  const [activeMode, setActiveMode] = useState('upload'); // 'upload' | 'url' | 'samples'
  const [file, setFile] = useState(null);
  const [url, setUrl] = useState('');
  const [appName, setAppName] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState(null);

  const handleFileDrop = (e) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileUpload = async (e) => {
    e.preventDefault();
    if (!file) {
      setError('Please select an APK file to upload.');
      return;
    }

    setIsSubmitting(true);
    setError(null);
    try {
      const formData = new FormData();
      formData.append('file', file);
      const res = await apiClient.uploadAPK(formData);
      if (res.investigation_id) {
        onInvestigationStarted(res.investigation_id);
      }
    } catch (err) {
      setError(err.message || 'Failed to initialize analysis pipeline.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleUrlSubmit = async (e) => {
    e.preventDefault();
    if (!url) {
      setError('Please enter a valid suspicious APK URL.');
      return;
    }

    setIsSubmitting(true);
    setError(null);
    try {
      const res = await apiClient.submitURL({
        apk_url: url,
        apk_name: appName || 'url_ingested_sample.apk'
      });
      if (res.investigation_id) {
        onInvestigationStarted(res.investigation_id);
      }
    } catch (err) {
      setError(err.message || 'Failed to submit URL for analysis.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleQuickSample = async (sampleType) => {
    setIsSubmitting(true);
    setError(null);
    try {
      const res = await apiClient.triggerSyntheticSample(sampleType);
      if (res.investigation_id) {
        onInvestigationStarted(res.investigation_id);
      }
    } catch (err) {
      setError(err.message || 'Failed to generate test sample.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div className="text-center space-y-2">
        <h2 className="text-2xl font-black tracking-tight text-white">
          Submit Untrusted Android Application
        </h2>
        <p className="text-sm text-slate-400 max-w-xl mx-auto">
          Automated multi-layer forensic inspection including JADX decompilation, runtime Frida instrumentation,
          network C2 extraction, and GenAI risk scoring.
        </p>
      </div>

      {/* Mode Switcher */}
      <div className="flex justify-center">
        <div className="inline-flex p-1 bg-slate-900 border border-slate-800 rounded-xl space-x-1">
          <button
            onClick={() => setActiveMode('upload')}
            className={`px-4 py-2 rounded-lg text-xs font-bold transition flex items-center space-x-2 ${
              activeMode === 'upload' ? 'bg-cyan-950 text-cyan-400 border border-cyan-800' : 'text-slate-400 hover:text-white'
            }`}
          >
            <UploadCloud className="w-4 h-4" />
            <span>Upload APK File</span>
          </button>
          <button
            onClick={() => setActiveMode('url')}
            className={`px-4 py-2 rounded-lg text-xs font-bold transition flex items-center space-x-2 ${
              activeMode === 'url' ? 'bg-cyan-950 text-cyan-400 border border-cyan-800' : 'text-slate-400 hover:text-white'
            }`}
          >
            <LinkIcon className="w-4 h-4" />
            <span>Suspicious URL</span>
          </button>
          <button
            onClick={() => setActiveMode('samples')}
            className={`px-4 py-2 rounded-lg text-xs font-bold transition flex items-center space-x-2 ${
              activeMode === 'samples' ? 'bg-cyan-950 text-cyan-400 border border-cyan-800' : 'text-slate-400 hover:text-white'
            }`}
          >
            <Cpu className="w-4 h-4" />
            <span>Pre-Loaded Test APKs</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 bg-rose-950/60 border border-rose-800 rounded-xl flex items-center space-x-3 text-rose-300 text-xs">
          <AlertCircle className="w-5 h-5 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Upload Mode */}
      {activeMode === 'upload' && (
        <form onSubmit={handleFileUpload} className="space-y-4">
          <div
            onDragOver={(e) => e.preventDefault()}
            onDrop={handleFileDrop}
            className="border-2 border-dashed border-slate-700 hover:border-cyan-500/80 bg-slate-900/40 rounded-2xl p-10 text-center transition cursor-pointer flex flex-col items-center justify-center space-y-4"
            onClick={() => document.getElementById('apk-file-input').click()}
          >
            <input
              id="apk-file-input"
              type="file"
              accept=".apk"
              className="hidden"
              onChange={(e) => setFile(e.target.files[0])}
            />
            <div className="p-4 bg-cyan-950/60 rounded-full border border-cyan-800/60 text-cyan-400">
              <UploadCloud className="w-8 h-8" />
            </div>
            <div>
              <p className="text-sm font-bold text-slate-200">
                {file ? file.name : 'Click to select or drag & drop an APK'}
              </p>
              <p className="text-xs text-slate-500 mt-1">
                {file ? `${(file.size / (1024 * 1024)).toFixed(2)} MB` : 'Supports standard Android .apk binaries up to 100MB'}
              </p>
            </div>
          </div>

          <button
            type="submit"
            disabled={!file || isSubmitting}
            className="w-full py-3.5 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 disabled:opacity-50 text-white font-bold text-sm shadow-lg shadow-cyan-900/30 flex items-center justify-center space-x-2 transition"
          >
            {isSubmitting ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>Launching Isolated Sandbox Analysis...</span>
              </>
            ) : (
              <>
                <Play className="w-4 h-4" />
                <span>Start Forensic Analysis Pipeline</span>
              </>
            )}
          </button>
        </form>
      )}

      {/* URL Mode */}
      {activeMode === 'url' && (
        <form onSubmit={handleUrlSubmit} className="cyber-card p-6 space-y-4">
          <div className="space-y-2">
            <label className="text-xs font-bold text-slate-300 uppercase">Suspicious Download / Phishing URL</label>
            <input
              type="url"
              placeholder="https://sbi-rewards-update.top/download/yono_rewards.apk"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="w-full px-4 py-3 bg-slate-900 border border-slate-800 rounded-xl text-slate-200 text-sm focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>

          <div className="space-y-2">
            <label className="text-xs font-bold text-slate-300 uppercase">Custom Sample Tag (Optional)</label>
            <input
              type="text"
              placeholder="SBI_Rewards_Phish_Campaign"
              value={appName}
              onChange={(e) => setAppName(e.target.value)}
              className="w-full px-4 py-3 bg-slate-900 border border-slate-800 rounded-xl text-slate-200 text-sm focus:outline-none focus:border-cyan-500"
            />
          </div>

          <button
            type="submit"
            disabled={!url || isSubmitting}
            className="w-full py-3.5 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 disabled:opacity-50 text-white font-bold text-sm shadow-lg shadow-cyan-900/30 flex items-center justify-center space-x-2 transition"
          >
            {isSubmitting ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>Fetching & Analyzing...</span>
              </>
            ) : (
              <>
                <Play className="w-4 h-4" />
                <span>Ingest & Analyze URL</span>
              </>
            )}
          </button>
        </form>
      )}

      {/* Samples Mode */}
      {activeMode === 'samples' && (
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div className="cyber-card p-5 space-y-3 flex flex-col justify-between border-rose-900/40">
            <div>
              <span className="badge-critical px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase">Banking Trojan</span>
              <h3 className="text-sm font-bold text-slate-100 mt-2">SBI YONO Phish / SharkBot</h3>
              <p className="text-xs text-slate-400 mt-1">
                Accessibility abuse, overlay injection, SMS OTP interception, and C2 exfiltration.
              </p>
            </div>
            <button
              onClick={() => handleQuickSample('banking_trojan')}
              disabled={isSubmitting}
              className="w-full py-2 bg-rose-950/60 hover:bg-rose-900/80 border border-rose-800 text-rose-300 rounded-lg text-xs font-bold transition flex items-center justify-center space-x-1"
            >
              <span>Launch Test</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="cyber-card p-5 space-y-3 flex flex-col justify-between border-amber-900/40">
            <div>
              <span className="badge-high px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase">Predatory Spyware</span>
              <h3 className="text-sm font-bold text-slate-100 mt-2">FastCash Instant Loan</h3>
              <p className="text-xs text-slate-400 mt-1">
                Contact harvesting (380+ contacts), background camera activation, and blackmail C2 channel.
              </p>
            </div>
            <button
              onClick={() => handleQuickSample('loan_spyware')}
              disabled={isSubmitting}
              className="w-full py-2 bg-amber-950/60 hover:bg-amber-900/80 border border-amber-800 text-amber-300 rounded-lg text-xs font-bold transition flex items-center justify-center space-x-1"
            >
              <span>Launch Test</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="cyber-card p-5 space-y-3 flex flex-col justify-between border-emerald-900/40">
            <div>
              <span className="badge-low px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase">Benign Utility</span>
              <h3 className="text-sm font-bold text-slate-100 mt-2">SafeCalculator Pro</h3>
              <p className="text-xs text-slate-400 mt-1">
                Standard clean utility APK without dangerous permissions or suspicious network activity.
              </p>
            </div>
            <button
              onClick={() => handleQuickSample('clean')}
              disabled={isSubmitting}
              className="w-full py-2 bg-emerald-950/60 hover:bg-emerald-900/80 border border-emerald-800 text-emerald-300 rounded-lg text-xs font-bold transition flex items-center justify-center space-x-1"
            >
              <span>Launch Test</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      )}

      {/* Safety Notice */}
      <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl flex items-start space-x-3 text-xs text-slate-400">
        <ShieldAlert className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
        <div>
          <strong className="text-slate-200">Forensic Isolation Guarantee:</strong> Untrusted Android binaries are analyzed inside a strictly sandboxed container. No malicious code is ever executed on the host system.
        </div>
      </div>
    </div>
  );
}
