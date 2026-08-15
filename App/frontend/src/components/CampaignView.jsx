import React from 'react';
import { 
  Calendar, 
  MapPin, 
  Target, 
  Users, 
  GitCommit
} from 'lucide-react';

export default function CampaignView({ campaigns, onSelectInvestigation: _onSelectInvestigation }) {
  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-black text-white tracking-tight">
            Threat Campaign Attribution & Clustering
          </h2>
          <p className="text-xs text-slate-400">
            Cross-investigation tracking connecting distributed fraudulent APKs by shared C2 domains, certificates, and code fingerprints.
          </p>
        </div>
        <span className="px-3 py-1 bg-amber-950/60 border border-amber-800 text-amber-300 rounded-full text-xs font-bold font-mono">
          {campaigns.length} Active Campaigns Tracked
        </span>
      </div>

      <div className="space-y-6">
        {campaigns.map((camp) => (
          <div key={camp.id} className="cyber-card p-6 space-y-6 border-slate-700/60">
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800 pb-4">
              <div className="space-y-1">
                <div className="flex items-center space-x-2">
                  <span className="badge-critical px-2.5 py-0.5 rounded-full text-[10px] font-extrabold uppercase">
                    {camp.severity} SEVERITY
                  </span>
                  <span className="text-xs font-mono text-slate-400">
                    Campaign ID #{camp.id}
                  </span>
                </div>
                <h3 className="text-lg font-black text-white">{camp.name}</h3>
                <p className="text-xs text-cyan-400 font-semibold flex items-center space-x-1">
                  <Users className="w-3.5 h-3.5" />
                  <span>Threat Actor: {camp.threat_actor}</span>
                </p>
              </div>

              <div className="grid grid-cols-2 gap-4 text-xs text-slate-300">
                <div className="p-3 bg-slate-900/80 rounded-xl border border-slate-800 space-y-1">
                  <span className="text-[10px] text-slate-500 font-bold uppercase flex items-center space-x-1">
                    <Target className="w-3 h-3 text-rose-400" />
                    <span>Target Sector</span>
                  </span>
                  <p className="font-semibold text-slate-200">{camp.target_sector}</p>
                </div>
                <div className="p-3 bg-slate-900/80 rounded-xl border border-slate-800 space-y-1">
                  <span className="text-[10px] text-slate-500 font-bold uppercase flex items-center space-x-1">
                    <MapPin className="w-3 h-3 text-cyan-400" />
                    <span>Region</span>
                  </span>
                  <p className="font-semibold text-slate-200">{camp.target_region}</p>
                </div>
              </div>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">
              {camp.description}
            </p>

            {/* Shared Infrastructure & Tactics */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl space-y-2">
                <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider">
                  Observed TTPs & Vectors
                </h4>
                <div className="flex flex-wrap gap-1.5">
                  {camp.tactics?.map((tactic, idx) => (
                    <span key={idx} className="px-2.5 py-1 rounded bg-slate-800 border border-slate-700 text-xs text-slate-200">
                      {tactic}
                    </span>
                  ))}
                </div>
              </div>

              <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl space-y-2">
                <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider">
                  Shared Infrastructure IOCs
                </h4>
                <div className="space-y-1 font-mono text-xs">
                  {camp.shared_iocs?.map((ioc, idx) => (
                    <div key={idx} className="flex justify-between items-center bg-slate-950/60 px-2 py-1 rounded border border-slate-800/80">
                      <span className="text-slate-300">{ioc.value}</span>
                      <span className="text-[10px] text-cyan-400">{ioc.type}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Campaign Evolution Timeline */}
            <div className="p-4 bg-slate-900/40 border border-slate-800 rounded-xl space-y-3">
              <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center space-x-1.5">
                <Calendar className="w-3.5 h-3.5 text-cyan-400" />
                <span>Campaign Operational Timeline</span>
              </h4>
              <div className="space-y-2 text-xs">
                <div className="flex items-center space-x-3 text-slate-300">
                  <GitCommit className="w-4 h-4 text-cyan-400 shrink-0" />
                  <span className="font-mono text-slate-500">2024-01-10:</span>
                  <span>Initial weaponized hosting and phishing domain registration.</span>
                </div>
                <div className="flex items-center space-x-3 text-slate-300">
                  <GitCommit className="w-4 h-4 text-amber-400 shrink-0" />
                  <span className="font-mono text-slate-500">2024-04-15:</span>
                  <span>Mass SMS & WhatsApp phishing distribution across regional carrier gateways.</span>
                </div>
                <div className="flex items-center space-x-3 text-slate-300">
                  <GitCommit className="w-4 h-4 text-rose-400 shrink-0" />
                  <span className="font-mono text-slate-500">2024-08-14:</span>
                  <span>Automated extraction, MITRE mapping, and SOC containment initiated.</span>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
