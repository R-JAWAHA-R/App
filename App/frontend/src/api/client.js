const API_BASE = '/api';

export const apiClient = {
  async getSystemStatus() {
    const res = await fetch(`${API_BASE}/system/status`);
    return res.json();
  },

  async getInvestigations() {
    const res = await fetch(`${API_BASE}/investigations`);
    return res.json();
  },

  async getInvestigation(id) {
    const res = await fetch(`${API_BASE}/investigations/${id}`);
    return res.json();
  },

  async getInvestigationStatus(id) {
    const res = await fetch(`${API_BASE}/investigations/${id}/status`);
    return res.json();
  },

  async uploadAPK(formData) {
    const res = await fetch(`${API_BASE}/investigations`, {
      method: 'POST',
      body: formData,
    });
    return res.json();
  },

  async submitURL(payload) {
    const formData = new FormData();
    formData.append('apk_url', payload.apk_url);
    if (payload.apk_name) formData.append('apk_name', payload.apk_name);

    const res = await fetch(`${API_BASE}/investigations`, {
      method: 'POST',
      body: formData,
    });
    return res.json();
  },

  async triggerReanalysis(id) {
    const res = await fetch(`${API_BASE}/investigations/${id}/analyze`, {
      method: 'POST',
    });
    return res.json();
  },

  async queryAIAssistant(investigationId, query) {
    const res = await fetch(`${API_BASE}/assistant/query`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        investigation_id: investigationId,
        query: query,
      }),
    });
    return res.json();
  },

  async getCampaigns() {
    const res = await fetch(`${API_BASE}/campaigns`);
    return res.json();
  },

  async triggerSyntheticSample(sampleType) {
    const res = await fetch(`${API_BASE}/demo/create-sample?sample_type=${sampleType}`, {
      method: 'POST',
    });
    return res.json();
  },

  async resetDemoDatabase() {
    const res = await fetch(`${API_BASE}/demo/reset`, {
      method: 'POST',
    });
    return res.json();
  }
};
