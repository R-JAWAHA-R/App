import React from 'react';
import { Shield, RefreshCw, Cpu } from 'lucide-react';

export default function Header({ systemStatus: _systemStatus, onResetDemo, isResetting }) {
  return (
    <header className="h-16 border-b border-slate-800 bg-slate-950/80 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-50">
      <div className="flex items-center space-x-3">
        <div className="p-2 bg-gradient-to-tr from-cyan-600 to-blue-600 rounded-lg shadow-lg shadow-cyan-500/20">
          <Shield className="w-5 h-5 text-white" />
        </div>
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="font-extrabold text-slate-100 tracking-tight text-base sm:text-lg">
              APK SENTINEL <span className="text-cyan-400 font-mono text-xs px-2 py-0.5 rounded bg-cyan-950/60 border border-cyan-800/60">GENAI SOC</span>
            </h1>
          </div>
          <p className="text-xs text-slate-400">Automated Forensic Analysis & Risk Scoring Engine</p>
        </div>
      </div>

      <div className="flex items-center space-x-4">
        {/* Live Engine Status */}
        <div className="hidden md:flex items-center space-x-2 px-3 py-1.5 rounded-full bg-slate-900 border border-slate-800 text-xs">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
          </span>
          <span className="text-slate-300 font-medium">Sandbox Pipeline: Ready</span>
        </div>

        {/* Demo Mode Indicator */}
        <div className="hidden sm:flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-cyan-950/40 border border-cyan-800/40 text-xs text-cyan-300">
          <Cpu className="w-3.5 h-3.5" />
          <span>Demo Mode (Safe Replay)</span>
        </div>

        {/* Reset Database Button */}
        <button
          onClick={onResetDemo}
          disabled={isResetting}
          className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 active:scale-95 text-slate-200 text-xs font-semibold border border-slate-700 transition"
          title="Reset database to initial clean seed state"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isResetting ? 'animate-spin text-cyan-400' : ''}`} />
          <span>Reset Demo</span>
        </button>
      </div>
    </header>
  );
}
