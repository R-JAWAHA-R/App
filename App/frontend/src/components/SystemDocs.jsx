import React from 'react';
import { 
  Layers, 
  ShieldCheck, 
  CheckCircle2
} from 'lucide-react';

export default function SystemDocs() {
  return (
    <div className="max-w-4xl mx-auto space-y-8">
      <div className="text-center space-y-2">
        <h2 className="text-2xl font-black tracking-tight text-white">
          System Architecture & Evaluation Guide
        </h2>
        <p className="text-xs text-slate-400 max-w-xl mx-auto">
          Generative AI-Based Automated Analysis and Risk Scoring of Fraudulent APKs — Full Technical Specification
        </p>
      </div>

      {/* Pipeline Stages */}
      <div className="cyber-card p-6 space-y-6">
        <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center space-x-2">
          <Layers className="w-4 h-4 text-cyan-400" />
          <span>End-to-End Forensic Pipeline Workflow</span>
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl space-y-1.5">
            <span className="font-bold text-cyan-400">1. APK Extraction & Static Analysis</span>
            <p className="text-slate-300">
              Parses AndroidManifest.xml, identifies dangerous permission combinations, extracts DEX strings, detects obfuscation/reflection, and fires YARA heuristic rules.
            </p>
          </div>

          <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl space-y-1.5">
            <span className="font-bold text-cyan-400">2. Isolated Sandbox Dynamic Tracing</span>
            <p className="text-slate-300">
              Executes APK inside an isolated Android emulator with Frida hooks to trace sensitive runtime API calls (Accessibility, WindowManager, SMSManager, SharedPreferences).
            </p>
          </div>

          <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl space-y-1.5">
            <span className="font-bold text-cyan-400">3. Automated UI Interaction Engine</span>
            <p className="text-slate-300">
              Injects ADB Monkey events and scripted UI action sequences to navigate login/permission screens and record interaction coverage metrics.
            </p>
          </div>

          <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl space-y-1.5">
            <span className="font-bold text-cyan-400">4. Network & Threat Intel Enrichment</span>
            <p className="text-slate-300">
              Detects C2 domains, Telegram bot exfiltration channels, and queries VirusTotal / AbuseIPDB reputation feeds with seamless demo fallbacks.
            </p>
          </div>

          <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl space-y-1.5">
            <span className="font-bold text-cyan-400">5. Hybrid Malware Similarity & MITRE</span>
            <p className="text-slate-300">
              Computes feature vectors matching known malware families (Fake SBI Trojan, SharkBot, LoanShark) and auto-maps observed TTPs to MITRE Mobile ATT&CK.
            </p>
          </div>

          <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl space-y-1.5">
            <span className="font-bold text-cyan-400">6. Evidence-Based 0-100 Risk Scoring & GenAI</span>
            <p className="text-slate-300">
              Calculates weighted risk score with transparent audit trails, followed by Gemini GenAI threat synthesis and interactive SOC assistant grounding.
            </p>
          </div>
        </div>
      </div>

      {/* Safety & Isolation */}
      <div className="cyber-card p-6 space-y-4 border-emerald-900/40">
        <h3 className="text-sm font-bold text-emerald-400 uppercase tracking-wider flex items-center space-x-2">
          <ShieldCheck className="w-4 h-4" />
          <span>Safety & Hackathon Demonstration Guarantees</span>
        </h3>
        <ul className="space-y-2 text-xs text-slate-300">
          <li className="flex items-start space-x-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
            <span><strong>Host Isolation:</strong> Untrusted binaries are never executed directly on the host machine.</span>
          </li>
          <li className="flex items-start space-x-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
            <span><strong>Safe Simulation Fallback:</strong> Operates seamlessly in demo mode with high-fidelity synthetic profiles when emulators or external API keys are unavailable.</span>
          </li>
          <li className="flex items-start space-x-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
            <span><strong>Zero Hallucination AI:</strong> The GenAI assistant is strictly grounded in database findings and refuses to fabricate unobserved evidence.</span>
          </li>
        </ul>
      </div>
    </div>
  );
}
