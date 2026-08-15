import React, { useState, useEffect, useRef } from 'react';
import { 
  Bot, 
  Send, 
  User, 
  Loader2
} from 'lucide-react';
import { apiClient } from '../api/client';

export default function AIAssistant({ investigations, selectedInvestigationId }) {
  const [currentInvId, setCurrentInvId] = useState(selectedInvestigationId || (investigations[0]?.id || 1));
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      content: 'Hello Analyst. I am your Generative AI Forensic Copilot. Ask me anything about the analyzed APK, malicious attack vectors, permissions, or mitigation recommendations.',
      citations: []
    }
  ]);
  const [query, setQuery] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const messagesEndRef = useRef(null);

  useEffect(() => {
    if (selectedInvestigationId) {
      setCurrentInvId(selectedInvestigationId);
    }
  }, [selectedInvestigationId]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isLoading]);

  const currentInv = investigations.find(i => i.id === Number(currentInvId)) || investigations[0];

  const suggestedQueries = [
    'Why was this APK classified as high risk?',
    'Which permissions are suspicious?',
    'What evidence suggests credential theft?',
    'Which IOCs should be blocked?',
    'Which MITRE techniques were observed?',
    'Is this sample similar to previous investigations?'
  ];

  const handleSendQuery = async (queryText) => {
    const textToSend = queryText || query;
    if (!textToSend.trim() || isLoading) return;

    const userMessage = { role: 'user', content: textToSend };
    setMessages(prev => [...prev, userMessage]);
    setQuery('');
    setIsLoading(true);

    try {
      const res = await apiClient.queryAIAssistant(Number(currentInvId), textToSend);
      setMessages(prev => [
        ...prev,
        {
          role: 'assistant',
          content: res.answer,
          citations: res.grounded_evidence || []
        }
      ]);
    } catch {
      setMessages(prev => [
        ...prev,
        {
          role: 'assistant',
          content: 'Sorry, I encountered an error querying the forensic analysis database.',
          citations: []
        }
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-4">
      {/* Target Sample Selector */}
      <div className="cyber-card p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center space-x-2">
          <Bot className="w-5 h-5 text-cyan-400" />
          <div>
            <h2 className="text-sm font-bold text-slate-100">AI Forensic Copilot</h2>
            <p className="text-xs text-slate-400">Strictly grounded in database findings with zero hallucinations</p>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <label className="text-xs font-semibold text-slate-400">Target Sample:</label>
          <select
            value={currentInvId}
            onChange={(e) => {
              setCurrentInvId(Number(e.target.value));
              setMessages([
                {
                  role: 'assistant',
                  content: `Switched context to ${investigations.find(i => i.id === Number(e.target.value))?.apk_name}. How can I assist you with this forensic dossier?`,
                  citations: []
                }
              ]);
            }}
            className="px-3 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-medium"
          >
            {investigations.map((inv) => (
              <option key={inv.id} value={inv.id}>
                {inv.apk_name} ({inv.severity} - {inv.risk_score})
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Suggested Prompt Chips */}
      <div className="flex flex-wrap gap-2">
        {suggestedQueries.map((prompt, idx) => (
          <button
            key={idx}
            onClick={() => handleSendQuery(prompt)}
            disabled={isLoading}
            className="px-3 py-1.5 bg-slate-900/80 hover:bg-cyan-950/80 border border-slate-800 hover:border-cyan-800 text-slate-300 hover:text-cyan-300 rounded-full text-xs font-medium transition"
          >
            {prompt}
          </button>
        ))}
      </div>

      {/* Chat Messages Container */}
      <div className="cyber-card p-5 h-[480px] flex flex-col justify-between">
        <div className="overflow-y-auto space-y-4 pr-2">
          {messages.map((msg, idx) => (
            <div
              key={idx}
              className={`flex space-x-3 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
            >
              {msg.role === 'assistant' && (
                <div className="w-8 h-8 rounded-full bg-cyan-950 border border-cyan-800 flex items-center justify-center shrink-0">
                  <Bot className="w-4 h-4 text-cyan-400" />
                </div>
              )}

              <div
                className={`max-w-[80%] rounded-2xl p-4 text-xs leading-relaxed ${
                  msg.role === 'user'
                    ? 'bg-gradient-to-r from-cyan-600 to-blue-600 text-white rounded-tr-none'
                    : 'bg-slate-900/90 border border-slate-800 text-slate-200 rounded-tl-none space-y-2'
                }`}
              >
                <div className="whitespace-pre-line font-sans">{msg.content}</div>

                {msg.citations && msg.citations.length > 0 && (
                  <div className="pt-2 border-t border-slate-800/80 space-y-1">
                    <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">
                      Verified Evidence Grounding:
                    </span>
                    <div className="flex flex-wrap gap-1">
                      {msg.citations.map((cite, cidx) => (
                        <span key={cidx} className="px-2 py-0.5 rounded bg-slate-800 text-[10px] font-mono text-cyan-300">
                          {cite}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {msg.role === 'user' && (
                <div className="w-8 h-8 rounded-full bg-blue-900/80 border border-blue-700 flex items-center justify-center shrink-0">
                  <User className="w-4 h-4 text-blue-200" />
                </div>
              )}
            </div>
          ))}

          {isLoading && (
            <div className="flex items-center space-x-2 text-slate-400 text-xs pl-11">
              <Loader2 className="w-4 h-4 animate-spin text-cyan-400" />
              <span>Analyzing forensic evidence graph...</span>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* Input bar */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSendQuery();
          }}
          className="mt-4 pt-3 border-t border-slate-800 flex items-center space-x-2"
        >
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={`Ask a question about ${currentInv?.apk_name || 'this APK'}...`}
            className="flex-1 px-4 py-2.5 bg-slate-900 border border-slate-800 rounded-xl text-slate-200 text-xs focus:outline-none focus:border-cyan-500 font-medium"
          />
          <button
            type="submit"
            disabled={!query.trim() || isLoading}
            className="p-2.5 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 disabled:opacity-50 text-white transition shadow-md shadow-cyan-900/30"
          >
            <Send className="w-4 h-4" />
          </button>
        </form>
      </div>
    </div>
  );
}
