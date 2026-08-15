import React, { useState, useEffect } from 'react';
import Header from './components/Header';
import Sidebar from './components/Sidebar';
import DashboardOverview from './components/DashboardOverview';
import APKSubmission from './components/APKSubmission';
import InvestigationDetails from './components/InvestigationDetails';
import AIAssistant from './components/AIAssistant';
import CampaignView from './components/CampaignView';
import SystemDocs from './components/SystemDocs';
import { apiClient } from './api/client';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [investigations, setInvestigations] = useState([]);
  const [campaigns, setCampaigns] = useState([]);
  const [systemStatus, setSystemStatus] = useState(null);
  const [selectedInvestigationId, setSelectedInvestigationId] = useState(null);
  const [isResetting, setIsResetting] = useState(false);
  const [isLaunching, setIsLaunching] = useState(false);
  const [notification, setNotification] = useState(null);

  const loadData = async () => {
    try {
      const [invs, camps, status] = await Promise.all([
        apiClient.getInvestigations(),
        apiClient.getCampaigns(),
        apiClient.getSystemStatus()
      ]);
      setInvestigations(invs);
      setCampaigns(camps);
      setSystemStatus(status);
    } catch (err) {
      console.error('Error fetching data', err);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 5000);
    return () => clearInterval(interval);
  }, []);

  const showNotification = (message) => {
    setNotification(message);
    setTimeout(() => setNotification(null), 3000);
  };

  const handleSelectInvestigation = (id) => {
    setSelectedInvestigationId(id);
    setActiveTab('investigation-detail');
  };

  const handleInvestigationStarted = (newId) => {
    setSelectedInvestigationId(newId);
    setActiveTab('investigation-detail');
    loadData();
    showNotification('Analysis pipeline initialized for new sample!');
  };

  const handleQuickLaunch = async (sampleType) => {
    setIsLaunching(true);
    try {
      const res = await apiClient.triggerSyntheticSample(sampleType);
      if (res.investigation_id) {
        handleInvestigationStarted(res.investigation_id);
      }
    } catch {
      showNotification('Failed to launch quick sample.');
    } finally {
      setIsLaunching(false);
    }
  };

  const handleResetDemo = async () => {
    setIsResetting(true);
    try {
      await apiClient.resetDemoDatabase();
      await loadData();
      showNotification('Demo database re-seeded successfully.');
      if (activeTab === 'investigation-detail') {
        setActiveTab('dashboard');
      }
    } catch {
      showNotification('Failed to reset demo database.');
    } finally {
      setIsResetting(false);
    }
  };

  const handleOpenAIChat = (invId) => {
    setSelectedInvestigationId(invId);
    setActiveTab('ai-assistant');
  };

  return (
    <div className="min-h-screen bg-[#090d16] text-slate-100 flex flex-col font-sans selection:bg-cyan-500 selection:text-white">
      {/* Top Application Header */}
      <Header 
        systemStatus={systemStatus} 
        onResetDemo={handleResetDemo} 
        isResetting={isResetting} 
      />

      {/* Main Layout Container */}
      <div className="flex flex-1 overflow-hidden">
        {/* Left Sidebar */}
        <Sidebar
          activeTab={activeTab === 'investigation-detail' ? 'investigations' : activeTab}
          onSelectTab={(tab) => {
            if (tab === 'investigations') {
              if (investigations.length > 0) {
                setSelectedInvestigationId(investigations[0].id);
                setActiveTab('investigation-detail');
              } else {
                setActiveTab('dashboard');
              }
            } else {
              setActiveTab(tab);
            }
          }}
          investigationCount={investigations.length}
          campaignCount={campaigns.length}
        />

        {/* Dynamic Center Stage */}
        <main className="flex-1 p-6 overflow-y-auto max-w-7xl mx-auto w-full">
          {/* Toast Notification */}
          {notification && (
            <div className="mb-4 p-3 bg-cyan-950/90 border border-cyan-800 text-cyan-300 rounded-xl text-xs font-semibold shadow-lg animate-bounce">
              {notification}
            </div>
          )}

          {activeTab === 'dashboard' && (
            <DashboardOverview
              investigations={investigations}
              campaigns={campaigns}
              onSelectInvestigation={handleSelectInvestigation}
              onQuickLaunch={handleQuickLaunch}
              isLaunching={isLaunching}
            />
          )}

          {activeTab === 'submit' && (
            <APKSubmission onInvestigationStarted={handleInvestigationStarted} />
          )}

          {activeTab === 'investigation-detail' && (
            <InvestigationDetails
              investigationId={selectedInvestigationId || (investigations[0]?.id || 1)}
              onOpenAIChat={handleOpenAIChat}
            />
          )}

          {activeTab === 'campaigns' && (
            <CampaignView
              campaigns={campaigns}
              onSelectInvestigation={handleSelectInvestigation}
            />
          )}

          {activeTab === 'ai-assistant' && (
            <AIAssistant
              investigations={investigations}
              selectedInvestigationId={selectedInvestigationId}
            />
          )}

          {activeTab === 'docs' && <SystemDocs />}
        </main>
      </div>
    </div>
  );
}
