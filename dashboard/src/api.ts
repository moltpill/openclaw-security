/**
 * API Client for ClawGuard Dashboard
 */

const BASE_URL = '/api';

async function fetchAPI(endpoint: string, apiKey: string, options: RequestInit = {}) {
  const response = await fetch(`${BASE_URL}${endpoint}`, {
    ...options,
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
      ...options.headers,
    },
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Request failed' }));
    throw new Error(error.message || error.error || 'Request failed');
  }

  return response.json();
}

export const api = {
  // Stats
  getStats: (apiKey: string) => fetchAPI('/stats', apiKey),

  // Audit Logs
  getLogs: (apiKey: string, params?: { limit?: number; since?: string; eventType?: string }) => {
    const query = new URLSearchParams();
    if (params?.limit) query.set('limit', String(params.limit));
    if (params?.since) query.set('since', params.since);
    if (params?.eventType) query.set('eventType', params.eventType);
    return fetchAPI(`/logs?${query}`, apiKey);
  },

  searchLogs: (apiKey: string, q: string, limit = 50) => 
    fetchAPI(`/logs/search?q=${encodeURIComponent(q)}&limit=${limit}`, apiKey),

  // Policies
  getPolicies: (apiKey: string) => fetchAPI('/policies', apiKey),
  
  updatePolicies: (apiKey: string, config: any) => 
    fetchAPI('/policies', apiKey, {
      method: 'PUT',
      body: JSON.stringify(config),
    }),

  // Enclave
  getEnclaveFiles: (apiKey: string) => fetchAPI('/enclave/files', apiKey),
  
  getPendingRequests: (apiKey: string) => fetchAPI('/enclave/pending', apiKey),
  
  approveRequest: (apiKey: string, requestId: string, approved: boolean) =>
    fetchAPI(`/enclave/approve/${requestId}`, apiKey, {
      method: 'POST',
      body: JSON.stringify({ approved }),
    }),
  
  checkIntegrity: (apiKey: string) => fetchAPI('/enclave/integrity', apiKey),
};
