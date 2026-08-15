import React from 'react';
import { 
  LayoutDashboard, 
  UploadCloud, 
  FileSearch, 
  Network, 
  Bot, 
  BookOpen, 
  Radio
} from 'lucide-react';

export default function Sidebar({ activeTab, onSelectTab, investigationCount, campaignCount }) {
  const menuItems = [
    { id: 'dashboard', label: 'SOC Overview', icon: LayoutDashboard, badge: null },
    { id: 'submit', label: 'Analyze APK / URL', icon: UploadCloud, badge: 'New' },
    { id: 'investigations', label: 'Investigations', icon: FileSearch, badge: investigationCount },
    { id: 'campaigns', label: 'Threat Campaigns', icon: Network, badge: campaignCount },
    { id: 'ai-assistant', label: 'AI Investigation Copilot', icon: Bot, badge: 'GenAI' },
    { id: 'docs', label: 'Architecture & Eval', icon: BookOpen, badge: null },
  ];

  return (
    <aside className="w-64 border-r border-slate-800 bg-slate-950/60 p-4 flex flex-col justify-between shrink-0">
      <div className="space-y-1">
        <div className="px-3 py-2 text-xs font-bold text-slate-500 uppercase tracking-wider">
          Forensic Operations
        </div>
        {menuItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                isActive
                  ? 'bg-gradient-to-r from-cyan-950/80 to-slate-900 text-cyan-400 border border-cyan-800/60 shadow-md shadow-cyan-950/40'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
              }`}
            >
              <div className="flex items-center space-x-3">
                <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                <span>{item.label}</span>
              </div>
              {item.badge !== null && (
                <span
                  className={`text-xs px-2 py-0.5 rounded-full font-mono font-semibold ${
                    isActive
                      ? 'bg-cyan-500/20 text-cyan-300'
                      : 'bg-slate-800 text-slate-400'
                  }`}
                >
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      <div className="p-3 bg-slate-900/80 border border-slate-800 rounded-xl space-y-2">
        <div className="flex items-center space-x-2 text-xs font-semibold text-slate-300">
          <Radio className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
          <span>Threat Feeds Active</span>
        </div>
        <p className="text-[11px] text-slate-400 leading-tight">
          VirusTotal, AbuseIPDB, MITRE Mobile ATT&CK & Vector Similarity Index online.
        </p>
      </div>
    </aside>
  );
}
