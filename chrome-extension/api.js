// SafePay API Client — Centralized backend communication
const SafePayAPI = (() => {
  const BASE_URL = 'http://127.0.0.1:8000';
  const TIMEOUT_MS = 8000;
  const MAX_RETRIES = 2;

  // Token management via chrome.storage.local
  function getAuthData() {
    return new Promise(resolve => {
      chrome.storage.local.get(['accessToken', 'userName', 'userEmail'], resolve);
    });
  }

  function saveAuthData(token, userName, userEmail) {
    return new Promise(resolve => {
      chrome.storage.local.set({ accessToken: token, userName, userEmail }, resolve);
    });
  }

  function clearAuthData() {
    return new Promise(resolve => {
      chrome.storage.local.remove(['accessToken', 'userName', 'userEmail'], resolve);
    });
  }

  // Core request wrapper with retry + timeout
  async function request(method, path, { body = null, auth = true, isFormData = false, retries = MAX_RETRIES, skipRefresh = false } = {}) {
    for (let attempt = 0; attempt <= retries; attempt++) {
      try {
        const authData = await getAuthData();
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);

        const headers = {};
        if (!isFormData) headers['Content-Type'] = 'application/json';
        if (auth && authData.accessToken) headers['Authorization'] = `Bearer ${authData.accessToken}`;

        const options = { method, headers, signal: controller.signal };
        if (body) {
          options.body = isFormData ? body : JSON.stringify(body);
        }

        const response = await fetch(`${BASE_URL}${path}`, options);
        clearTimeout(timeoutId);

        const data = await response.json();

        if (
          response.status === 401 &&
          auth &&
          attempt === 0 &&
          !skipRefresh &&
          path !== '/auth/refresh-token'
        ) {
          const refreshed = await refreshToken();
          if (refreshed) continue;
        }

        if (!response.ok) {
          throw new APIError(data.detail || data.message || data.error || `Request failed (${response.status})`, response.status);
        }

        return data;
      } catch (err) {
        if (err instanceof APIError) throw err;
        if (err.name === 'AbortError') {
          if (attempt < retries) { await delay(1000 * (attempt + 1)); continue; }
          throw new APIError('Request timed out. Is the backend running?', 0);
        }
        if (attempt < retries) { await delay(1000 * (attempt + 1)); continue; }
        throw new APIError('Network error. Check your connection and backend.', 0);
      }
    }
  }

  function delay(ms) { return new Promise(r => setTimeout(r, ms)); }

  class APIError extends Error {
    constructor(message, status) {
      super(message);
      this.name = 'APIError';
      this.status = status;
    }
  }

  // Auth endpoints
  async function login(phone, password) {
    const data = await request('POST', '/auth/login', { body: { phone, password }, auth: false });
    if (data.access_token) {
      await saveAuthData(data.access_token, data.user?.name || 'User', data.user?.email || '');
    }
    return data;
  }

  async function register(name, email, phone, password) {
    const data = await request('POST', '/auth/register', { body: { name, email, phone, password }, auth: false });
    if (data.access_token) {
      await saveAuthData(data.access_token, data.user?.name || 'User', data.user?.email || '');
    }
    return data;
  }

  async function getProfile() {
    return request('GET', '/auth/profile');
  }

  async function refreshToken() {
    try {
      const data = await request('POST', '/auth/refresh-token', { auth: true, retries: 0, skipRefresh: true });
      if (data.access_token) {
        const authData = await getAuthData();
        await saveAuthData(data.access_token, authData.userName, authData.userEmail);
        return true;
      }
    } catch (err) {
      await clearAuthData();
      return false;
    }
    return false;
  }

  async function logout() {
    try { await request('POST', '/auth/logout', { auth: false, retries: 0 }); } catch {}
    await clearAuthData();
  }

  // Scan endpoints
  async function scanText(text) {
    return request('POST', '/fraud/scan-text', { body: { text } });
  }

  async function scanSMS(message, sender) {
    const body = { message };
    if (sender) body.sender = sender;
    return request('POST', '/sms/scan', { body });
  }

  async function scanUPI(upi_id, amount, merchant_name) {
    const body = { upi_id, amount };
    if (merchant_name) body.merchant_name = merchant_name;
    return request('POST', '/fraud/scan-qr', { body });
  }

  async function scanQRImage(file) {
    const formData = new FormData();
    formData.append('file', file);
    return request('POST', '/qr/scan-image', { body: formData, isFormData: true });
  }

  async function scanQRPayload(payload) {
    return request('POST', '/qr/analyze-payload', { body: { payload } });
  }

  async function getFraudStats() {
    return request('GET', '/fraud/stats');
  }

  // Report endpoints
  async function reportUPI(upi_id, reason) {
    return request('POST', `/fraud/report-upi?upi_id=${encodeURIComponent(upi_id)}&reason=${encodeURIComponent(reason)}`);
  }

  async function reportSMS(sender, message, reason) {
    return request('POST', `/sms/report?sender=${encodeURIComponent(sender)}&message=${encodeURIComponent(message)}&reason=${encodeURIComponent(reason)}`);
  }

  // History endpoints
  async function getFraudHistory() {
    return request('GET', '/fraud/history');
  }

  async function getSMSHistory() {
    return request('GET', '/sms/history');
  }

  async function getQRHistory() {
    return request('GET', '/qr/history');
  }

  // Health endpoints
  async function ping() {
    return request('GET', '/ping', { auth: false, retries: 0 });
  }

  async function getHealthReport() {
    return request('GET', '/health/full-report', { auth: false, retries: 0 });
  }

  async function getMLHealth() {
    return request('GET', '/health/ml', { auth: false, retries: 0 });
  }

  async function getSystemInfo() {
    return request('GET', '/system/info', { auth: false, retries: 0 });
  }

  // Bulk endpoints
  async function bulkScanUPI(items) {
    return request('POST', '/fraud/bulk-scan', { body: items });
  }

  async function bulkScanSMS(messages) {
    return request('POST', '/sms/bulk-scan', { body: { messages } });
  }

  return {
    getAuthData, saveAuthData, clearAuthData, APIError,
    login, register, getProfile, refreshToken, logout,
    scanText, scanSMS, scanUPI, scanQRImage, scanQRPayload,
    reportUPI, reportSMS,
    getFraudHistory, getSMSHistory, getQRHistory, getFraudStats,
    ping, getHealthReport, getMLHealth, getSystemInfo,
    bulkScanUPI, bulkScanSMS
  };
})();
