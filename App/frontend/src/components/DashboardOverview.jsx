import React from 'react';
import { 
  ShieldAlert, 
  AlertTriangle, 
  FileSearch, 
  Activity, 
  ArrowRight,
  Zap
} from 'lucide-react';

export default function DashboardOverview({ investigations, campaigns, onSelectInvestigation, onQuickLaunch, isLaunching }) {
  const total = investigations.length;
  const critical = investigations.filter(i => i.severity === 'CRITICAL').length;
  
  const avgScore = total > 0 
    ? Math.round(investigations.reduce((acc, curr) => acc + (curr.risk_score || 0), 0) / total)
    : 0;

  return (
    <div className="space-y-6">
      {/* Top Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="cyber-card p-5">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Total Scanned APKs</span>
            <FileSearch className="w-5 h-5 text-cyan-400" />
          </div>
          <div className="mt-3 flex items-baseline space-x-2">
            <span className="text-3xl font-extrabold text-white font-mono">{total}</span>
            <span className="text-xs text-emerald-400 font-medium">100% Isolated</span>
          </div>
          <div className="mt-2 text-xs text-slate-400">Static, Dynamic & Network profiled</div>
        </div>

        <div className="cyber-card p-5 border-rose-900/30">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Critical Threats</span>
            <ShieldAlert className="w-5 h-5 text-rose-500" />
          </div>
          <div className="mt-3 flex items-baseline space-x-2">
            <span className="text-3xl font-extrabold text-rose-400 font-mono">{critical}</span>
            <span className="text-xs text-rose-400 font-medium">Immediate Action</span>
          </div>
          <div className="mt-2 text-xs text-slate-400">Banking Trojans & Stealers</div>
        </div>

        <div className="cyber-card p-5 border-amber-900/30">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Active Campaigns</span>
            <AlertTriangle className="w-5 h-5 text-amber-400" />
          </div>
          <div className="mt-3 flex items-baseline space-x-2">
            <span className="text-3xl font-extrabold text-amber-300 font-mono">{campaigns.length}</span>
            <span className="text-xs text-amber-400 font-medium">India & Global</span>
          </div>
          <div className="mt-2 text-xs text-slate-400">FakeYONO & ShadowLender</div>
        </div>

        <div className="cyber-card p-5">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Avg Forensic Risk</span>
            <Activity className="w-5 h-5 text-purple-400" />
          </div>
          <div className="mt-3 flex items-baseline space-x-2">
            <span className="text-3xl font-extrabold text-purple-300 font-mono">{avgScore}</span>
            <span className="text-xs text-slate-400 font-mono">/ 100</span>
          </div>
          <div className="mt-2 text-xs text-slate-400">Evidence-weighted score</div>
        </div>
      </div>

      {/* Quick Launch Test Samples */}
      <div className="cyber-card p-5 bg-gradient-to-r from-slate-900 via-slate-900/90 to-cyan-950/40 border-cyan-900/40">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2 text-cyan-400 font-bold text-sm">
              <Zap className="w-4 h-4" />
              <span>Instant Hackathon Evaluation Samples</span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Trigger isolated synthetic APK tests to evaluate pipeline stages in real-time.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => onQuickLaunch('banking_trojan')}
              disabled={isLaunching}
              className="px-3 py-1.5 rounded-lg bg-rose-950/60 hover:bg-rose-900/80 border border-rose-800 text-rose-300 text-xs font-semibold transition"
            >
              + Test Banking Trojan
            </button>
            <button
              onClick={() => onQuickLaunch('loan_spyware')}
              disabled={isLaunching}
              className="px-3 py-1.5 rounded-lg bg-amber-950/60 hover:bg-amber-900/80 border border-amber-800 text-amber-300 text-xs font-semibold transition"
            >
              + Test Loan Spyware
            </button>
            <button
              onClick={() => onQuickLaunch('clean')}
              disabled={isLaunching}
              className="px-3 py-1.5 rounded-lg bg-emerald-950/60 hover:bg-emerald-900/80 border border-emerald-800 text-emerald-300 text-xs font-semibold transition"
            >
              + Test Clean App
            </button>
          </div>
        </div>
      </div>

      {/* Recent Investigations Table */}
      <div className="cyber-card overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <FileSearch className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-bold text-slate-100 uppercase tracking-wider">Recent Forensic Dossiers</h2>
          </div>
          <span className="text-xs text-slate-500">{investigations.length} items logged</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-900/90 text-slate-400 font-semibold border-b border-slate-800">
              <tr>
                <th className="p-3.5 pl-5">Sample Name / Package</th>
                <th className="p-3.5">SHA-256 Hash</th>
                <th className="p-3.5">Risk Score</th>
                <th className="p-3.5">Severity</th>
                <th className="p-3.5">Status</th>
                <th className="p-3.5 text-right pr-5">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {investigations.map((inv) => {
                const isCrit = inv.severity === 'CRITICAL';
                const isHigh = inv.severity === 'HIGH';
                const isMed = inv.severity === 'MEDIUM';

                return (
                  <tr 
                    key={inv.id} 
                    onClick={() => onSelectInvestigation(inv.id)}
                    className="hover:bg-slate-800/40 cursor-pointer transition"
                  >
                    <td className="p-3.5 pl-5">
                      <div className="font-bold text-slate-100">{inv.apk_name}</div>
                      <div className="text-[11px] font-mono text-slate-500">{inv.package_name}</div>
                    </td>
                    <td className="p-3.5 font-mono text-[11px] text-slate-400">
                      {inv.sha256 ? `${inv.sha256.substring(0, 14)}...` : 'Pending'}
                    </td>
                    <td className="p-3.5">
                      <div className="flex items-center space-x-2">
                        <span className="font-mono font-bold text-slate-100">{inv.risk_score}</span>
                        <div className="w-16 bg-slate-800 h-1.5 rounded-full overflow-hidden">
                          <div 
                            className={`h-full ${isCrit ? 'bg-rose-500' : (isHigh ? 'bg-amber-500' : 'bg-emerald-500')}`}
                            style={{ width: `${Math.min(100, inv.risk_score)}%` }}
                          />
                        </div>
                      </div>
                    </td>
                    <td className="p-3.5">
                      <span className={`px-2.5 py-1 rounded-full text-[10px] font-extrabold uppercase ${
                        isCrit ? 'badge-critical' : (isHigh ? 'badge-high' : (isMed ? 'badge-medium' : 'badge-low'))
                      }`}>
                        {inv.severity}
                      </span>
                    </td>
                    <td className="p-3.5">
                      <span className="flex items-center space-x-1.5 text-[11px] text-slate-400">
                        <span className={`w-1.5 h-1.5 rounded-full ${inv.status === 'COMPLETED' ? 'bg-emerald-400' : 'bg-amber-400 animate-pulse'}`} />
                        <span>{inv.status}</span>
                      </span>
                    </td>
                    <td className="p-3.5 text-right pr-5">
                      <button 
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectInvestigation(inv.id);
                        }}
                        className="p-1.5 text-slate-400 hover:text-cyan-400 hover:bg-slate-800 rounded-lg transition"
                      >
                        <ArrowRight className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
