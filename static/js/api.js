/**
 * SafePay API client — connects dashboard to FastAPI backend.
 */
window.SafePayAPI = (() => {
  const STORAGE_KEY = 'safepay_token';
  const USER_KEY = 'safepay_user';

  function resolveBaseUrl() {
    const params = new URLSearchParams(window.location.search);
    const override = params.get('api');
    if (override) return override.replace(/\/$/, '');
    const origin = window.location.origin;
    if (origin.includes('5500') || origin.startsWith('file:')) {
      return 'http://127.0.0.1:8000';
    }
    return origin;
  }

  let baseUrl = resolveBaseUrl();

  function getToken() {
    return localStorage.getItem(STORAGE_KEY);
  }

  function setSession(token, user) {
    if (token) localStorage.setItem(STORAGE_KEY, token);
    if (user) localStorage.setItem(USER_KEY, JSON.stringify(user));
  }

  function clearSession() {
    localStorage.removeItem(STORAGE_KEY);
    localStorage.removeItem(USER_KEY);
  }

  function getUser() {
    try {
      return JSON.parse(localStorage.getItem(USER_KEY) || 'null');
    } catch {
      return null;
    }
  }

  function formatError(data, fallback) {
    if (!data) return fallback;
    const msg = data.message ?? data.detail;
    if (Array.isArray(msg)) {
      return msg.map((e) => e.msg || JSON.stringify(e)).join('; ');
    }
    if (typeof msg === 'object') return JSON.stringify(msg);
    return msg || fallback;
  }

  async function request(path, options = {}) {
    const headers = { ...(options.headers || {}) };
    if (!options.isFormData) {
      headers['Content-Type'] = 'application/json';
    }
    const token = getToken();
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const res = await fetch(`${baseUrl}${path}`, {
      method: options.method || 'GET',
      headers: options.isFormData && token
        ? { Authorization: `Bearer ${token}` }
        : headers,
      body: options.isFormData
        ? options.body
        : options.body
          ? JSON.stringify(options.body)
          : undefined,
    });

    const text = await res.text();
    let data = {};
    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      data = { message: text };
    }

    if (!res.ok) {
      throw new Error(formatError(data, res.statusText));
    }
    return data;
  }

  /** Normalize fraud/QR/SMS analysis payloads. */
  function pickAnalysis(payload) {
    const a = payload?.analysis ?? payload;
    if (!a) return { risk_score: 0, risk_level: 'UNKNOWN', status: 'UNKNOWN' };
    return {
      risk_score: a.risk_score ?? a.details?.risk_score ?? 0,
      risk_level: a.risk_level ?? a.details?.risk_level ?? 'UNKNOWN',
      status: a.status ?? a.details?.status ?? 'UNKNOWN',
      confidence: a.confidence ?? a.details?.confidence ?? a.details?.confidence_level ?? 'Normal',
      summary: a.summary ?? a.details?.summary,
      recommendation: a.recommendation ?? a.details?.recommendation,
      ml_probability: a.ml_probability ?? a.details?.ml_probability,
      reasons: a.reasons ?? a.details?.reasons ?? a.explanation ?? [],
      raw: a,
    };
  }

  return {
    get baseUrl() {
      return baseUrl;
    },
    setBaseUrl(url) {
      baseUrl = url.replace(/\/$/, '');
    },
    getToken,
    getUser,
    setSession,
    clearSession,
    pickAnalysis,

    ping: () => request('/ping'),
    healthReport: () => request('/health/full-report'),
    systemInfo: () => request('/system/info'),

    login: (phone, password) =>
      request('/auth/login', { method: 'POST', body: { phone, password } }),
    register: (body) =>
      request('/auth/register', { method: 'POST', body }),
    profile: () => request('/auth/profile'),
    logout: () => request('/auth/logout', { method: 'POST' }).catch(() => {}),

    scanQrImage: (file) => {
      const fd = new FormData();
      fd.append('file', file);
      return request('/qr/scan-image', { method: 'POST', body: fd, isFormData: true });
    },
    scanUpi: (upi_id, amount, merchant_name = null) =>
      request('/fraud/scan-qr', {
        method: 'POST',
        body: { upi_id, amount, merchant_name },
      }),
    scanSms: (message, sender = null) =>
      request('/sms/scan', { method: 'POST', body: { message, sender } }),
    scanText: (text) =>
      request('/fraud/scan-text', { method: 'POST', body: { text } }),

    qrHistory: () => request('/qr/history'),
    fraudHistory: () => request('/fraud/history'),
    smsHistory: () => request('/sms/history'),
  };
})();
