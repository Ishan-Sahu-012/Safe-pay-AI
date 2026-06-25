/**
 * SafePay Dashboard — UI wired to FastAPI backend.
 */
(function () {
  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => document.querySelectorAll(sel);

  const els = {
    connLabel: $('#conn-label'),
    connDot: $('#conn-dot'),
    authPill: $('#auth-pill'),
    userChip: $('#user-chip'),
    log: $('#log-output'),
    historyBody: $('#history-body'),
    lastResult: $('#last-result'),
    apiUrl: $('#api-url'),
    metricQr: $('#metric-qr-count'),
    metricUpi: $('#metric-upi-count'),
    metricSms: $('#metric-sms-count'),
    metricThreat: $('#metric-threat-score'),
    dbStatus: $('#db-status'),
    modelStatus: $('#model-status'),
    backendPill: $('#backend-status-pill'),
    uptimeLabel: $('#uptime-label'),
    uptimeBar: $('#uptime-bar'),
  };

  const MAX_LOG_LINES = 30;
  const state = { history: [], lastAnalysis: null };

  function pillClass(level) {
    const l = (level || '').toUpperCase();
    if (l === 'HIGH' || l === 'FRAUD' || l === 'SCAM') return 'pill-high';
    if (l === 'MEDIUM' || l === 'SUSPICIOUS') return 'pill-medium';
    return 'pill-safe';
  }

  function toast(msg, type = 'info') {
    const box = $('#toast-container') || (() => {
      const c = document.createElement('div');
      c.id = 'toast-container';
      c.className = 'toast-container';
      document.body.appendChild(c);
      return c;
    })();
    const t = document.createElement('div');
    t.className = `toast ${type}`;
    t.textContent = msg;
    box.appendChild(t);
    setTimeout(() => t.remove(), 4500);
  }

  function parseTimestamp(value) {
    if (value instanceof Date) return value;
    if (typeof value === 'number' && Number.isFinite(value)) {
      return new Date(value < 1e12 ? value * 1000 : value);
    }
    if (typeof value !== 'string') return null;

    const trimmed = value.trim();
    if (!trimmed) return null;

    if (/^[0-9]+$/.test(trimmed)) {
      const numeric = Number(trimmed);
      return new Date(numeric < 1e12 ? numeric * 1000 : numeric);
    }

    const normalized = trimmed.replace(/\s+/, 'T');
    const utcSafe = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?$/.test(normalized)
      ? `${normalized}Z`
      : normalized;

    const date = new Date(utcSafe);
    return Number.isNaN(date.getTime()) ? null : date;
  }

  function formatIST(timestamp, options = {}) {
    const date = parseTimestamp(timestamp);
    if (!date) return 'Invalid time';

    const formatter = new Intl.DateTimeFormat('en-IN', {
      timeZone: 'Asia/Kolkata',
      hour12: true,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      ...options
    });

    return `${formatter.format(date)} IST`;
  }

  function log(msg, type = 'info') {
    const time = formatIST(new Date());
    const line = document.createElement('div');
    line.className = `log-line ${type}`;
    line.textContent = `[${time}] ${msg}`;
    els.log.prepend(line);
    while (els.log.childElementCount > MAX_LOG_LINES) {
      els.log.removeChild(els.log.lastElementChild);
    }
  }

  function setLoading(btn, loading) {
    if (!btn) return;
    btn.disabled = loading;
    const label = btn.dataset.label || btn.textContent;
    if (loading) {
      btn.dataset.label = label;
      btn.innerHTML = '<span class="spinner"></span> Working…';
    } else {
      btn.textContent = btn.dataset.label || label;
    }
  }

  function updateAuthUI() {
    const user = SafePayAPI.getUser();
    const token = SafePayAPI.getToken();
    if (user && token) {
      els.authPill.textContent = 'Authenticated';
      els.authPill.className = 'pill pill-ok';
      els.userChip.innerHTML = `Signed in as <strong>${user.name}</strong> · ${user.phone}`;
    } else {
      els.authPill.textContent = 'Sign in required';
      els.authPill.className = 'pill pill-auth';
      els.userChip.textContent = 'Not signed in';
    }
  }

  function escapeHtml(value) {
    return String(value ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function parseUpiQrPayload(rawQr) {
    if (!rawQr) return null;
    const trimmed = rawQr.trim();
    if (!trimmed.toLowerCase().startsWith('upi://') && !trimmed.includes('pa=')) {
      return null;
    }
    
    let queryStr = '';
    const qIndex = trimmed.indexOf('?');
    if (qIndex !== -1) {
      queryStr = trimmed.slice(qIndex + 1);
    } else {
      queryStr = trimmed;
    }
    
    const params = new URLSearchParams(queryStr);
    const getVal = (key) => {
      const val = params.get(key);
      return (val && val.trim()) ? decodeURIComponent(val.trim()) : 'Not Specified';
    };
    
    return {
      upiId: getVal('pa'),
      name: getVal('pn'),
      amount: getVal('am'),
      currency: getVal('cu'),
      note: getVal('tn'),
      raw: trimmed
    };
  }

  function renderLastResult(analysis, title, qrData) {
    if (!analysis || !els.lastResult) return;
    const reasons = Array.isArray(analysis.reasons) ? analysis.reasons : [];
    const confidence = analysis.confidence || 'Normal';
    
    const rawQr = qrData?.raw_qr || analysis.raw_qr || (typeof qrData === 'string' ? qrData : null);
    const upiDetails = parseUpiQrPayload(rawQr);
    
    let upiHtml = '';
    let advancedHtml = '';
    
    if (upiDetails) {
      upiHtml = `
        <div class="upi-details-table-wrapper" style="margin-top: 1rem;">
          <h5 style="margin: 0 0 0.5rem 0; font-size: 0.9rem; color: var(--text);">UPI Payment Details</h5>
          <table style="width: 100%; border-collapse: collapse; margin-bottom: 1rem; border: 1px solid var(--border); border-radius: 8px; overflow: hidden; background: var(--surface-2);">
            <tbody>
              <tr style="border-bottom: 1px solid var(--border);">
                <td style="padding: 0.65rem 0.75rem; font-weight: 600; color: var(--muted); width: 35%;">UPI ID</td>
                <td style="padding: 0.65rem 0.75rem; color: var(--text); word-break: break-all;">${escapeHtml(upiDetails.upiId)}</td>
              </tr>
              <tr style="border-bottom: 1px solid var(--border);">
                <td style="padding: 0.65rem 0.75rem; font-weight: 600; color: var(--muted);">Name</td>
                <td style="padding: 0.65rem 0.75rem; color: var(--text);">${escapeHtml(upiDetails.name)}</td>
              </tr>
              <tr style="border-bottom: 1px solid var(--border);">
                <td style="padding: 0.65rem 0.75rem; font-weight: 600; color: var(--muted);">Amount</td>
                <td style="padding: 0.65rem 0.75rem; color: var(--text);">${escapeHtml(upiDetails.amount)}</td>
              </tr>
              <tr style="border-bottom: 1px solid var(--border);">
                <td style="padding: 0.65rem 0.75rem; font-weight: 600; color: var(--muted);">Currency</td>
                <td style="padding: 0.65rem 0.75rem; color: var(--text);">${escapeHtml(upiDetails.currency)}</td>
              </tr>
              <tr>
                <td style="padding: 0.65rem 0.75rem; font-weight: 600; color: var(--muted);">Note</td>
                <td style="padding: 0.65rem 0.75rem; color: var(--text);">${escapeHtml(upiDetails.note)}</td>
              </tr>
            </tbody>
          </table>
        </div>
      `;
      
      advancedHtml = `
        <details class="advanced-details-accordion" style="margin-top: 1rem; border: 1px solid var(--border); border-radius: 10px; background: var(--surface); overflow: hidden;">
          <summary style="padding: 0.75rem 1rem; color: var(--text); font-weight: 600; font-size: 0.85rem; cursor: pointer; outline: none; list-style: none;">
            Advanced Details
          </summary>
          <div style="padding: 1rem; border-top: 1px solid var(--border); background: var(--surface-2); font-size: 0.82rem; font-family: monospace; color: var(--muted); word-break: break-all;">
            <strong>Raw Payload:</strong><br/>
            <span style="color: var(--text);">${escapeHtml(upiDetails.raw)}</span>
          </div>
        </details>
      `;
    } else if (rawQr) {
      advancedHtml = `
        <details class="advanced-details-accordion" style="margin-top: 1rem; border: 1px solid var(--border); border-radius: 10px; background: var(--surface); overflow: hidden;">
          <summary style="padding: 0.75rem 1rem; color: var(--text); font-weight: 600; font-size: 0.85rem; cursor: pointer; outline: none; list-style: none;">
            Advanced Details
          </summary>
          <div style="padding: 1rem; border-top: 1px solid var(--border); background: var(--surface-2); font-size: 0.82rem; font-family: monospace; color: var(--muted); word-break: break-all;">
            <strong>Raw Payload:</strong><br/>
            <span style="color: var(--text);">${escapeHtml(rawQr)}</span>
          </div>
        </details>
      `;
    }

    els.lastResult.innerHTML = `
      <div class="result-card">
        <h4>${title}</h4>
        <div class="result-meta">
          <span class="pill ${pillClass(analysis.risk_level)}">${analysis.risk_level}</span>
          <span class="muted">Score: <strong>${analysis.risk_score}%</strong></span>
          <span class="muted">Status: <strong>${analysis.status}</strong></span>
          <span class="muted">Confidence: <strong>${confidence}</strong></span>
        </div>
        ${analysis.summary ? `<p class="result-summary">${analysis.summary}</p>` : ''}
        ${reasons.length ? `<ul class="result-reasons">${reasons.map((r) => `<li>${r}</li>`).join('')}</ul>` : ''}
        ${upiHtml}
        ${advancedHtml}
      </div>`;
    els.lastResult.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  function renderHistory(history) {
    if (!history.length) {
      els.historyBody.innerHTML =
        '<tr><td colspan="5" class="muted" style="text-align:center;padding:1.5rem">No scans yet. Run a check after signing in.</td></tr>';
      return;
    }
    els.historyBody.innerHTML = history
      .slice(0, 15)
      .map((item) => {
        const input = item.input_value || item.upi_id || item.message || '—';
        const type = item.source || item.scan_type || '—';
        const risk = item.risk_score != null ? `${Number(item.risk_score).toFixed(1)}%` : '—';
        const status = item.status || item.risk_level || '—';
        const ts = item.created_at ? formatIST(item.created_at) : '—';
        return `<tr>
          <td>${type}</td>
          <td title="${String(input).replace(/"/g, '&quot;')}">${String(input).slice(0, 48)}${input.length > 48 ? '…' : ''}</td>
          <td><span class="pill ${pillClass(status)}">${status}</span></td>
          <td>${risk}</td>
          <td class="muted">${ts}</td>
        </tr>`;
      })
      .join('');
  }

  function updateMetrics(history) {
    const qr = history.filter((h) => h.source === 'QR').length;
    const upi = history.filter((h) => h.source === 'FRAUD' && h.scan_type === 'QR').length;
    const sms = history.filter((h) => h.source === 'SMS' || h.scan_type === 'TEXT').length;
    const high = history.filter((h) => Number(h.risk_score) >= 75).length;
    const total = history.length || 1;
    const threat = Math.round((high / total) * 100);
    els.metricQr.textContent = qr;
    els.metricUpi.textContent = upi;
    els.metricSms.textContent = sms;
    els.metricThreat.textContent = `${threat}%`;
  }

  async function refreshHealth() {
    try {
      await SafePayAPI.ping();
      els.connDot.className = 'conn-dot online';
      els.connLabel.textContent = 'Backend online';
      const report = await SafePayAPI.healthReport();
      const overall = report.overall_status || 'HEALTHY';
      els.backendPill.textContent = overall;
      els.backendPill.className = `pill ${overall === 'HEALTHY' ? 'pill-safe' : overall === 'CRITICAL' ? 'pill-high' : 'pill-medium'}`;
      els.dbStatus.textContent = report.services?.database || '—';
      els.modelStatus.textContent = `${report.services?.upi_model || '—'} / ${report.services?.text_model || '—'}`;
      if (report.uptime_seconds != null) {
        const h = Math.floor(report.uptime_seconds / 3600);
        els.uptimeLabel.textContent = `${h}h uptime`;
        els.uptimeBar.style.width = `${Math.min(100, (report.uptime_seconds / 86400) * 100)}%`;
      }
    } catch (e) {
      els.connDot.className = 'conn-dot offline';
      els.connLabel.textContent = 'Backend offline';
      els.backendPill.textContent = 'Offline';
      els.backendPill.className = 'pill pill-high';
      log(`Health check failed: ${e.message}`, 'error');
    }
  }

  async function loadHistory() {
    if (!SafePayAPI.getToken()) return;
    try {
      const [qr, fraud, sms] = await Promise.all([
        SafePayAPI.qrHistory().catch(() => ({ history: [] })),
        SafePayAPI.fraudHistory().catch(() => ({ history: [] })),
        SafePayAPI.smsHistory().catch(() => ({ history: [] })),
      ]);
      state.history = [
        ...(qr.history || []).map((i) => ({ ...i, source: 'QR' })),
        ...(fraud.history || []).map((i) => ({ ...i, source: 'FRAUD' })),
        ...(sms.history || []).map((i) => ({ ...i, source: 'SMS' })),
      ].sort((a, b) => (parseTimestamp(b.created_at)?.getTime() || 0) - (parseTimestamp(a.created_at)?.getTime() || 0));
      renderHistory(state.history);
      updateMetrics(state.history);
    } catch (e) {
      log(`History: ${e.message}`, 'error');
    }
  }

  async function ensureSession() {
    if (!SafePayAPI.getToken()) {
      updateAuthUI();
      return false;
    }
    try {
      const p = await SafePayAPI.profile();
      SafePayAPI.setSession(SafePayAPI.getToken(), p.user);
      updateAuthUI();
      return true;
    } catch {
      SafePayAPI.clearSession();
      updateAuthUI();
      return false;
    }
  }

  // ——— Auth ———
  $('#btn-login')?.addEventListener('click', async () => {
    const btn = $('#btn-login');
    const phone = $('#login-phone').value.trim();
    const password = $('#login-password').value;
    if (!phone || !password) return toast('Phone and password required', 'error');
    setLoading(btn, true);
    try {
      const res = await SafePayAPI.login(phone, password);
      SafePayAPI.setSession(res.access_token, res.user);
      updateAuthUI();
      toast(`Welcome, ${res.user.name}!`, 'success');
      log('Login successful', 'success');
      await loadHistory();
      showPanel('scan');
    } catch (e) {
      toast(e.message, 'error');
      log(`Login failed: ${e.message}`, 'error');
    } finally {
      setLoading(btn, false);
    }
  });

  $('#btn-register')?.addEventListener('click', async () => {
    const btn = $('#btn-register');
    const body = {
      name: $('#register-name').value.trim(),
      email: $('#register-email').value.trim(),
      phone: $('#register-phone').value.trim(),
      password: $('#register-password').value,
    };
    if (!body.name || !body.email || !body.phone || !body.password) {
      return toast('Fill all registration fields', 'error');
    }
    setLoading(btn, true);
    try {
      const res = await SafePayAPI.register(body);
      SafePayAPI.setSession(res.access_token, res.user);
      updateAuthUI();
      toast('Account created!', 'success');
      log('Registered and signed in', 'success');
      await loadHistory();
      showPanel('scan');
    } catch (e) {
      toast(e.message, 'error');
      log(`Register failed: ${e.message}`, 'error');
    } finally {
      setLoading(btn, false);
    }
  });

  $('#btn-logout')?.addEventListener('click', async () => {
    await SafePayAPI.logout();
    SafePayAPI.clearSession();
    updateAuthUI();
    state.history = [];
    renderHistory([]);
    updateMetrics([]);
    els.lastResult.innerHTML = '';
    toast('Logged out', 'info');
    log('Logged out', 'info');
  });

  // ——— Scans ———
  $('#btn-qr-scan')?.addEventListener('click', async () => {
    if (!SafePayAPI.getToken()) return toast('Please sign in first', 'error');
    const file = $('#qr-file').files?.[0];
    if (!file) return toast('Select a QR image', 'error');
    const btn = $('#btn-qr-scan');
    setLoading(btn, true);
    try {
      const res = await SafePayAPI.scanQrImage(file);
      const a = SafePayAPI.pickAnalysis(res);
      renderLastResult(a, `QR scan · ${res.qr_data?.upi_id || 'UPI'}`, res.qr_data);
      toast(`${a.status} — risk ${a.risk_score}%`, a.risk_level === 'LOW' ? 'success' : 'error');
      log(`QR: ${a.status} (${a.risk_score}%)`, 'success');
      $('#qr-file').value = '';
      await loadHistory();
    } catch (e) {
      toast(e.message, 'error');
      log(`QR failed: ${e.message}`, 'error');
    } finally {
      setLoading(btn, false);
    }
  });

  $('#btn-upi-verify')?.addEventListener('click', async () => {
    if (!SafePayAPI.getToken()) return toast('Please sign in first', 'error');
    const upi_id = $('#upi-id').value.trim();
    const amount = Number($('#upi-amount').value);
    if (!upi_id || !amount) return toast('UPI ID and amount required', 'error');
    const btn = $('#btn-upi-verify');
    setLoading(btn, true);
    try {
      const res = await SafePayAPI.scanUpi(upi_id, amount);
      const a = SafePayAPI.pickAnalysis(res);
      renderLastResult(a, `UPI check · ${upi_id}`);
      toast(`${a.status} — risk ${a.risk_score}%`, a.risk_level === 'LOW' ? 'success' : 'error');
      log(`UPI: ${a.status} (${a.risk_score}%)`, 'success');
      await loadHistory();
    } catch (e) {
      toast(e.message, 'error');
      log(`UPI failed: ${e.message}`, 'error');
    } finally {
      setLoading(btn, false);
    }
  });

  $('#btn-sms-scan')?.addEventListener('click', async () => {
    if (!SafePayAPI.getToken()) return toast('Please sign in first', 'error');
    const message = $('#sms-message').value.trim();
    if (message.length < 5) return toast('Enter at least 5 characters', 'error');
    const btn = $('#btn-sms-scan');
    setLoading(btn, true);
    try {
      const res = await SafePayAPI.scanSms(message, $('#sms-sender')?.value?.trim() || null);
      const a = SafePayAPI.pickAnalysis({ analysis: res.analysis });
      renderLastResult(a, 'SMS / link analysis');
      const toastType = a.risk_level === 'LOW' ? 'success' : a.risk_level === 'MEDIUM' ? 'warning' : 'error';
      toast(`${res.analysis?.status || a.status} — ${a.risk_score}%`, toastType);
      log(`SMS scan complete (${a.risk_score}%)`, 'success');
      $('#sms-message').value = '';
      await loadHistory();
    } catch (e) {
      toast(e.message, 'error');
      log(`SMS failed: ${e.message}`, 'error');
    } finally {
      setLoading(btn, false);
    }
  });

  $('#btn-refresh')?.addEventListener('click', async () => {
    await refreshHealth();
    if (SafePayAPI.getToken()) await loadHistory();
    toast('Data refreshed', 'success');
  });

  $('#btn-save-api')?.addEventListener('click', () => {
    const url = els.apiUrl?.value?.trim();
    if (url) {
      SafePayAPI.setBaseUrl(url);
      toast(`API set to ${url}`, 'success');
      refreshHealth();
    }
  });

  function showPanel(id) {
    $$('.panel').forEach((p) => p.classList.remove('active'));
    $$('.nav-tab').forEach((t) => t.classList.remove('active'));
    $(`#panel-${id}`)?.classList.add('active');
    $(`.nav-tab[data-panel="${id}"]`)?.classList.add('active');
  }

  $$('.nav-tab').forEach((tab) => {
    tab.addEventListener('click', () => showPanel(tab.dataset.panel));
  });

  // ——— Help Center Inner Nav ———
  $$('.help-tab').forEach((tab) => {
    tab.addEventListener('click', () => {
      $$('.help-tab').forEach((t) => t.classList.remove('active'));
      $$('.help-section').forEach((s) => s.classList.remove('active'));
      tab.classList.add('active');
      const target = document.getElementById(tab.dataset.target);
      if (target) target.classList.add('active');
    });
  });

  // ——— Accordions ———
  $$('.accordion-header').forEach((header) => {
    header.addEventListener('click', () => {
      const item = header.parentElement;
      item.classList.toggle('open');
    });
  });

  async function init() {
    if (typeof SafePayAPI !== 'object') {
      toast('Dashboard initialization failed: API client unavailable', 'error');
      console.error('SafePayAPI is not defined');
      return;
    }

    if (els.apiUrl) els.apiUrl.value = SafePayAPI.baseUrl;
    updateAuthUI();
    log('Dashboard ready — connect via Sign In tab', 'info');
    await refreshHealth();
    if (await ensureSession()) await loadHistory();
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) refreshHealth();
    });
    setInterval(() => {
      if (!document.hidden) refreshHealth();
    }, 20000);
    showPanel('home');
  }

  if (document.readyState === 'loading') {
    window.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
