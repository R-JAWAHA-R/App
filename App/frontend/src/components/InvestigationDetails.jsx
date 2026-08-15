import React, { useState, useEffect, useCallback, useRef } from 'react';
import { 
  ShieldAlert, 
  AlertTriangle, 
  Copy, 
  Check, 
  FileText, 
  Layers, 
  Activity, 
  Network as NetworkIcon, 
  Database, 
  GitBranch, 
  RefreshCw, 
  ExternalLink,
  Bot,
  Terminal
} from 'lucide-react';
import { apiClient } from '../api/client';

export default function InvestigationDetails({ investigationId, onOpenAIChat }) {
  const [data, setData] = useState(null);
  const [activeTab, setActiveTab] = useState('summary');
  const [copiedSha, setCopiedSha] = useState(false);
  const dataRef = useRef(data);

  useEffect(() => {
    dataRef.current = data;
  }, [data]);

  const fetchDetails = useCallback(async () => {
    try {
      const res = await apiClient.getInvestigation(investigationId);
      setData(res);
    } catch (err) {
      console.error('Failed to load investigation details', err);
    }
  }, [investigationId]);

  useEffect(() => {
    fetchDetails();
    // Poll if in progress
    const interval = setInterval(() => {
      const current = dataRef.current;
      if (current && (current.status === 'QUEUED' || current.status === 'STATIC_ANALYSIS' || current.status === 'DYNAMIC_ANALYSIS' || current.status === 'NETWORK_ANALYSIS')) {
        fetchDetails();
      }
    }, 2000);
    return () => clearInterval(interval);
  }, [investigationId, fetchDetails]);

  if (!data) {
    return (
      <div className="flex flex-col items-center justify-center h-96 space-y-3">
        <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
        <span className="text-slate-400 text-sm">Loading forensic investigation dossier...</span>
      </div>
    );
  }

  const isCompleted = data.status === 'COMPLETED';
  const isCrit = data.severity === 'CRITICAL';
  const isHigh = data.severity === 'HIGH';
  const isMed = data.severity === 'MEDIUM';

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setCopiedSha(true);
    setTimeout(() => setCopiedSha(false), 2000);
  };

  const tabs = [
    { id: 'summary', label: 'Risk & Summary', icon: Activity },
    { id: 'static', label: 'Static Analysis', icon: Layers, badge: data.static_findings?.length },
    { id: 'dynamic', label: 'Dynamic Tracing', icon: Terminal, badge: data.dynamic_findings?.length },
    { id: 'network', label: 'Network & C2', icon: NetworkIcon, badge: data.network_findings?.length },
    { id: 'iocs', label: 'IOCs', icon: ShieldAlert, badge: data.iocs?.length },
    { id: 'similarity', label: 'Malware Similarity', icon: GitBranch, badge: data.similarity_matches?.length },
    { id: 'mitre', label: 'MITRE ATT&CK', icon: Database, badge: data.mitre_techniques?.length },
    { id: 'report', label: 'Forensic Report', icon: FileText }
  ];

  return (
    <div className="space-y-6">
      {/* Top Sample Header Card */}
      <div className="cyber-card p-6 border-slate-700/60 relative overflow-hidden">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <span className={`px-3 py-1 rounded-full text-xs font-black uppercase tracking-wider ${
                isCrit ? 'badge-critical' : (isHigh ? 'badge-high' : (isMed ? 'badge-medium' : 'badge-low'))
              }`}>
                {data.severity} RISK
              </span>
              <span className="text-xs font-mono text-slate-400 px-2 py-0.5 rounded bg-slate-900 border border-slate-800">
                v{data.version_name} (SDK {data.target_sdk})
              </span>
              {data.is_demo && (
                <span className="text-[10px] font-bold text-cyan-400 px-2 py-0.5 rounded bg-cyan-950/60 border border-cyan-800">
                  DEMO PROFILE
                </span>
              )}
            </div>

            <h1 className="text-xl sm:text-2xl font-black text-white tracking-tight">
              {data.apk_name}
            </h1>
            <p className="text-xs font-mono text-cyan-400">{data.package_name}</p>

            <div className="flex items-center space-x-2 pt-1">
              <span className="text-xs text-slate-500 font-semibold">SHA-256:</span>
              <code className="text-xs font-mono text-slate-300 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                {data.sha256}
              </code>
              <button
                onClick={() => copyToClipboard(data.sha256)}
                className="p-1 text-slate-400 hover:text-cyan-400 transition"
                title="Copy SHA-256"
              >
                {copiedSha ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>

          {/* Quick Actions & Risk Gauge Metric */}
          <div className="flex items-center space-x-6">
            <div className="text-right hidden sm:block">
              <div className="text-[11px] font-bold text-slate-400 uppercase">Analysis Status</div>
              <div className="text-sm font-extrabold text-slate-100 flex items-center justify-end space-x-1.5 mt-0.5">
                <span className={`w-2 h-2 rounded-full ${isCompleted ? 'bg-emerald-400' : 'bg-amber-400 animate-ping'}`} />
                <span>{data.current_stage_label || data.status}</span>
              </div>
              <div className="text-[11px] text-slate-500 mt-1">Confidence: {(data.confidence * 100).toFixed(0)}%</div>
            </div>

            {/* Circular Risk Score Gauge */}
            <div className="flex flex-col items-center">
              <div className="relative w-24 h-24 flex items-center justify-center">
                <svg className="w-full h-full transform -rotate-90" viewBox="0 0 36 36">
                  <path
                    className="text-slate-800"
                    strokeWidth="3.5"
                    stroke="currentColor"
                    fill="none"
                    d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                  />
                  <path
                    className={isCrit ? 'text-rose-500' : (isHigh ? 'text-amber-500' : 'text-emerald-400')}
                    strokeDasharray={`${data.risk_score}, 100`}
                    strokeWidth="3.5"
                    strokeLinecap="round"
                    stroke="currentColor"
                    fill="none"
                    d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                  />
                </svg>
                <div className="absolute flex flex-col items-center justify-center text-center">
                  <span className="text-2xl font-black font-mono text-white leading-none">{data.risk_score}</span>
                  <span className="text-[9px] font-bold text-slate-400 uppercase">Risk</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Live Progress Bar (if still scanning) */}
        {!isCompleted && (
          <div className="mt-4 pt-4 border-t border-slate-800">
            <div className="flex justify-between text-xs text-slate-400 mb-1">
              <span>Pipeline Stage: {data.current_stage_label}</span>
              <span className="font-mono font-bold text-cyan-400">{data.progress}%</span>
            </div>
            <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
              <div 
                className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 transition-all duration-500" 
                style={{ width: `${data.progress}%` }} 
              />
            </div>
          </div>
        )}
      </div>

      {/* Forensic Tabs Navigation */}
      <div className="flex space-x-1 border-b border-slate-800 overflow-x-auto pb-1">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center space-x-2 px-4 py-2.5 rounded-t-lg text-xs font-bold transition whitespace-nowrap ${
                isActive
                  ? 'bg-slate-900 text-cyan-400 border-t-2 border-cyan-500 border-x border-slate-800'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/40'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{tab.label}</span>
              {tab.badge > 0 && (
                <span className="px-1.5 py-0.2 text-[10px] rounded-full bg-slate-800 text-slate-300 font-mono">
                  {tab.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Tab Content 1: Summary & Risk Breakdown */}
      {activeTab === 'summary' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Executive & AI Threat Briefing */}
          <div className="lg:col-span-2 space-y-6">
            <div className="cyber-card p-5 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2 text-sm font-bold text-white uppercase tracking-wider">
                  <Bot className="w-4 h-4 text-cyan-400" />
                  <span>GenAI Threat Synthesis & Verdict</span>
                </div>
                <button
                  onClick={() => onOpenAIChat(data.id)}
                  className="px-2.5 py-1 bg-cyan-950 hover:bg-cyan-900 border border-cyan-800 text-cyan-300 rounded text-xs font-semibold flex items-center space-x-1 transition"
                >
                  <Bot className="w-3 h-3" />
                  <span>Ask Copilot</span>
                </button>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed bg-slate-900/80 p-4 rounded-xl border border-slate-800">
                {data.summary || data.ai_verdict || 'Awaiting final AI verdict synthesis...'}
              </p>
            </div>

            {/* Top Score Contributing Factors */}
            <div className="cyber-card p-5 space-y-3">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                Primary Risk Indicators
              </h3>
              <div className="space-y-2">
                {data.top_reasons && data.top_reasons.map((reason, idx) => (
                  <div key={idx} className="flex items-start space-x-2.5 p-3 rounded-lg bg-slate-900/60 border border-slate-800/80 text-xs">
                    <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                    <span className="text-slate-200">{reason}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Category Contributions */}
            <div className="cyber-card p-5 space-y-3">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                Weighted Category Contributions
              </h3>
              <div className="space-y-3">
                {data.risk_components && data.risk_components.map((comp, idx) => (
                  <div key={idx} className="space-y-1">
                    <div className="flex justify-between text-xs">
                      <span className="font-semibold text-slate-300">{comp.category} ({(comp.weight * 100).toFixed(0)}%)</span>
                      <span className="font-mono font-bold text-cyan-400">+{comp.weighted_contribution} pts</span>
                    </div>
                    <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-gradient-to-r from-cyan-500 to-rose-500"
                        style={{ width: `${Math.min(100, comp.raw_score)}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Quick Metadata & Limitations Sidebar */}
          <div className="space-y-6">
            <div className="cyber-card p-5 space-y-4">
              <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider">
                Sample Properties
              </h3>
              <div className="space-y-2 text-xs divide-y divide-slate-800/60 text-slate-300">
                <div className="flex justify-between py-1.5">
                  <span className="text-slate-500">File Size:</span>
                  <span className="font-mono">{(data.file_size / 1024).toFixed(1)} KB</span>
                </div>
                <div className="flex justify-between py-1.5">
                  <span className="text-slate-500">Target SDK:</span>
                  <span className="font-mono">Android {data.target_sdk}</span>
                </div>
                <div className="flex justify-between py-1.5">
                  <span className="text-slate-500">Min SDK:</span>
                  <span className="font-mono">Android {data.min_sdk}</span>
                </div>
                <div className="flex justify-between py-1.5">
                  <span className="text-slate-500">Analysis Mode:</span>
                  <span className="text-cyan-400 font-semibold">{data.is_demo ? 'Isolated Sandbox' : 'Live Frida Sandbox'}</span>
                </div>
              </div>
            </div>

            <div className="cyber-card p-5 space-y-3 bg-slate-950/40">
              <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider">
                Forensic Limitations
              </h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                {data.limitations || 'Dynamic hooks executed within safe simulated emulator harness.'}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Tab Content 2: Static Analysis */}
      {activeTab === 'static' && (
        <div className="space-y-6">
          <div className="cyber-card p-5 space-y-4">
            <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider">
              Extracted Permissions & Manifest Findings
            </h3>
            <div className="space-y-2">
              {data.static_findings?.filter(f => f.category === 'SUSPICIOUS_PERMISSION' || f.category === 'PERMISSION').map((perm, idx) => (
                <div key={idx} className="p-3.5 bg-slate-900/60 border border-slate-800 rounded-xl flex items-start justify-between gap-4">
                  <div className="space-y-1">
                    <code className="text-xs font-bold text-slate-100">{perm.title}</code>
                    <p className="text-xs text-slate-400">{perm.description}</p>
                    {perm.evidence && <p className="text-[11px] text-slate-500 font-mono mt-1">{perm.evidence}</p>}
                  </div>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-extrabold uppercase shrink-0 ${
                    perm.severity === 'CRITICAL' ? 'badge-critical' : (perm.severity === 'HIGH' ? 'badge-high' : 'badge-low')
                  }`}>
                    {perm.severity}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Obfuscation & YARA Findings */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="cyber-card p-5 space-y-3">
              <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider">
                Obfuscation & Evasion
              </h3>
              <div className="space-y-2">
                {data.static_findings?.filter(f => f.category === 'OBFUSCATION').map((obf, idx) => (
                  <div key={idx} className="p-3 bg-slate-900 border border-slate-800 rounded-lg text-xs space-y-1">
                    <div className="font-bold text-slate-200">{obf.title}</div>
                    <p className="text-slate-400">{obf.description}</p>
                    <code className="text-[11px] text-cyan-400 font-mono block">{obf.evidence}</code>
                  </div>
                ))}
              </div>
            </div>

            <div className="cyber-card p-5 space-y-3">
              <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider">
                YARA Signature Matches
              </h3>
              <div className="space-y-2">
                {data.static_findings?.filter(f => f.category === 'YARA_MATCH' || f.category === 'FRAUD_HEURISTIC').map((yara, idx) => (
                  <div key={idx} className="p-3 bg-slate-900 border border-slate-800 rounded-lg text-xs space-y-1">
                    <div className="flex justify-between items-center">
                      <span className="font-bold text-rose-300">{yara.title}</span>
                      <span className="badge-critical text-[10px] px-2 py-0.5 rounded">{yara.severity}</span>
                    </div>
                    <p className="text-slate-400">{yara.description}</p>
                    <code className="text-[11px] text-slate-500 font-mono block">{yara.evidence}</code>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab Content 3: Dynamic Runtime Tracing */}
      {activeTab === 'dynamic' && (
        <div className="cyber-card p-5 space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider">
              Frida & Emulator Runtime Instrumentation Log
            </h3>
            <span className="text-xs text-slate-400 font-mono">{data.dynamic_findings?.length} events captured</span>
          </div>

          <div className="space-y-2 font-mono text-xs">
            {data.dynamic_findings?.map((trace, idx) => (
              <div key={idx} className="p-3 bg-slate-900/80 border border-slate-800/80 rounded-xl space-y-1.5">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <span className="text-cyan-400 font-bold">[{trace.timestamp_offset.toFixed(2)}s]</span>
                    <span className="text-slate-200 font-semibold">{trace.api_class}.{trace.method}</span>
                  </div>
                  {trace.is_sensitive && (
                    <span className="badge-critical text-[10px] px-2 py-0.5 rounded font-extrabold uppercase">
                      SENSITIVE HOOK
                    </span>
                  )}
                </div>
                <div className="text-slate-400 text-[11px]">Params: {trace.parameters}</div>
                <div className="text-slate-500 text-[11px] font-sans italic">{trace.description}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab Content 4: Network & C2 Traffic */}
      {activeTab === 'network' && (
        <div className="cyber-card p-5 space-y-4">
          <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider">
            Captured Network Endpoints & C2 Infrastructure
          </h3>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900 text-slate-400 font-semibold border-b border-slate-800">
                <tr>
                  <th className="p-3">Domain / URL</th>
                  <th className="p-3">Resolved IP</th>
                  <th className="p-3">Protocol</th>
                  <th className="p-3">Classification</th>
                  <th className="p-3">Exfiltration Channel</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 text-slate-300 font-mono">
                {data.network_findings?.map((net, idx) => (
                  <tr key={idx} className="hover:bg-slate-800/30">
                    <td className="p-3 font-semibold text-slate-100">{net.domain || net.url}</td>
                    <td className="p-3 text-cyan-400">{net.ip || 'N/A'}</td>
                    <td className="p-3 text-slate-400">{net.protocol}:{net.port}</td>
                    <td className="p-3">
                      {net.is_c2 ? (
                        <span className="badge-critical px-2 py-0.5 rounded text-[10px] font-extrabold uppercase">C2 SERVER</span>
                      ) : (net.is_phishing ? (
                        <span className="badge-high px-2 py-0.5 rounded text-[10px] font-extrabold uppercase">PHISHING</span>
                      ) : (
                        <span className="badge-low px-2 py-0.5 rounded text-[10px]">BENIGN</span>
                      ))}
                    </td>
                    <td className="p-3 font-sans text-slate-400">
                      {net.exfiltration_type !== 'NONE' ? (
                        <span className="text-rose-400 font-bold">{net.exfiltration_type}</span>
                      ) : (
                        <span className="text-slate-500">None</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Tab Content 5: IOCs */}
      {activeTab === 'iocs' && (
        <div className="cyber-card p-5 space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider">
              Actionable Indicators of Compromise (IOCs)
            </h3>
            <button
              onClick={() => {
                const iocText = data.iocs.map(i => `${i.ioc_type},${i.value},${i.severity},${i.recommended_action}`).join('\n');
                copyToClipboard(iocText);
              }}
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold flex items-center space-x-1.5"
            >
              <Copy className="w-3.5 h-3.5" />
              <span>Export Blocklist CSV</span>
            </button>
          </div>

          <div className="space-y-2">
            {data.iocs?.map((ioc, idx) => (
              <div key={idx} className="p-3.5 bg-slate-900/60 border border-slate-800 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
                <div className="space-y-1">
                  <div className="flex items-center space-x-2">
                    <span className="px-2 py-0.5 rounded bg-slate-800 text-cyan-400 font-mono text-[10px] font-bold">
                      {ioc.ioc_type}
                    </span>
                    <code className="font-mono font-bold text-slate-100 text-xs">{ioc.value}</code>
                  </div>
                  <p className="text-slate-400 text-[11px]">{ioc.description}</p>
                </div>
                <div className="flex items-center space-x-3 shrink-0">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-extrabold uppercase ${
                    ioc.severity === 'CRITICAL' ? 'badge-critical' : 'badge-high'
                  }`}>
                    {ioc.severity}
                  </span>
                  <span className="text-[11px] font-mono text-slate-400">
                    Action: <strong className="text-rose-400">{ioc.recommended_action}</strong>
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab Content 6: Malware Family Similarity */}
      {activeTab === 'similarity' && (
        <div className="cyber-card p-5 space-y-4">
          <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider">
            Hybrid Vector Similarity Matches
          </h3>
          <p className="text-xs text-slate-400">
            Calculated via hybrid embedding vectors of permissions, API calls, strings, and behavioral signatures.
          </p>

          <div className="space-y-4">
            {data.similarity_matches?.map((match, idx) => (
              <div key={idx} className="p-4 bg-slate-900/70 border border-slate-800 rounded-xl space-y-3">
                <div className="flex justify-between items-center">
                  <div>
                    <h4 className="font-bold text-slate-100 text-sm">{match.family_name}</h4>
                    <span className="text-[11px] text-slate-500 font-mono">Vector Distance: {match.vector_distance}</span>
                  </div>
                  <div className="text-right">
                    <span className="text-lg font-mono font-extrabold text-cyan-400">{match.similarity_score}%</span>
                    <div className="text-[10px] text-slate-400 uppercase">Match Score</div>
                  </div>
                </div>

                <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-gradient-to-r from-cyan-500 to-rose-500" 
                    style={{ width: `${match.similarity_score}%` }} 
                  />
                </div>

                <p className="text-xs text-slate-300">{match.explanation}</p>

                {match.matched_features && match.matched_features.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 pt-1">
                    {match.matched_features.map((feat, fidx) => (
                      <span key={fidx} className="px-2 py-0.5 rounded bg-slate-800/80 border border-slate-700 text-[10px] font-mono text-cyan-300">
                        {feat}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab Content 7: MITRE ATT&CK Matrix */}
      {activeTab === 'mitre' && (
        <div className="cyber-card p-5 space-y-4">
          <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider">
            MITRE ATT&CK for Mobile Technique Auto-Mapping
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {data.mitre_techniques?.map((tech, idx) => (
              <div key={idx} className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl space-y-2">
                <div className="flex items-center justify-between">
                  <span className="px-2.5 py-0.5 rounded bg-cyan-950 border border-cyan-800 font-mono text-xs font-bold text-cyan-400">
                    {tech.technique_id}
                  </span>
                  <span className="text-[11px] font-bold uppercase text-slate-400">{tech.tactic}</span>
                </div>
                <h4 className="font-bold text-slate-100 text-sm">{tech.technique_name}</h4>
                <p className="text-xs text-slate-400 leading-relaxed">{tech.evidence}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab Content 8: Forensic Report Viewer */}
      {activeTab === 'report' && (
        <div className="cyber-card p-5 space-y-4">
          <div className="flex justify-between items-center">
            <div>
              <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider">
                Forensic Dossier Preview
              </h3>
              <p className="text-xs text-slate-400">Analyst & Executive grade report</p>
            </div>
            <a
              href={`/api/investigations/${data.id}/report/html`}
              target="_blank"
              rel="noreferrer"
              className="px-4 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-lg text-xs font-bold shadow-lg shadow-cyan-900/30 flex items-center space-x-1.5 transition"
            >
              <ExternalLink className="w-3.5 h-3.5" />
              <span>Open Printable Dossier</span>
            </a>
          </div>

          <div className="border border-slate-800 rounded-xl overflow-hidden bg-white p-6 text-slate-900 max-h-[600px] overflow-y-auto">
            <iframe
              src={`/api/investigations/${data.id}/report/html`}
              title="Forensic Report"
              className="w-full h-[540px] border-0"
            />
          </div>
        </div>
      )}
    </div>
  );
}
