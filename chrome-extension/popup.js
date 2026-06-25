// SafePay UI Controller
document.addEventListener('DOMContentLoaded', () => {
  const els = {
    authContainer: document.getElementById('auth-container'),
    mainContent: document.getElementById('main-content'),
    loginForm: document.getElementById('login-form'),
    registerForm: document.getElementById('register-form'),
    showRegister: document.getElementById('show-register'),
    showLogin: document.getElementById('show-login'),
    loginBtn: document.getElementById('login-btn'),
    registerBtn: document.getElementById('register-btn'),
    loginPhone: document.getElementById('login-phone'),
    loginPass: document.getElementById('login-password'),
    regName: document.getElementById('reg-name'),
    regEmail: document.getElementById('reg-email'),
    regPhone: document.getElementById('reg-phone'),
    regPass: document.getElementById('reg-password'),
    passwordMeter: document.getElementById('password-meter'),
    statusDot: document.getElementById('status-dot'),
    statusText: document.getElementById('status-text'),
    userBar: document.getElementById('user-bar'),
    userAvatar: document.getElementById('user-avatar'),
    userName: document.getElementById('user-name'),
    userEmail: document.getElementById('user-email'),
    logoutBtn: document.getElementById('logout-btn'),
    mainNav: document.getElementById('main-nav'),
    navTabs: document.querySelectorAll('.nav-tab'),
    tabContents: document.querySelectorAll('.tab-content'),
    scannerTabs: document.querySelectorAll('.scanner-tab'),
    scannerPanels: document.querySelectorAll('.scanner-panel'),
    scanStatusPill: document.getElementById('scan-status-pill'),
    btnScanSms: document.getElementById('btn-scan-sms'),
    btnScanUpi: document.getElementById('btn-scan-upi'),
    btnScanQr: document.getElementById('btn-scan-qr'),
    scanSmsText: document.getElementById('scan-sms-text'),
    scanSmsSender: document.getElementById('scan-sms-sender'),
    smsCharCount: document.getElementById('sms-char-count'),
    scanUpiId: document.getElementById('scan-upi-id'),
    scanUpiAmt: document.getElementById('scan-upi-amount'),
    scanUpiMerchant: document.getElementById('scan-upi-merchant'),
    qrDropzone: document.getElementById('qr-dropzone'),
    qrFileInput: document.getElementById('qr-file-input'),
    qrPreview: document.getElementById('qr-preview'),
    qrPreviewContainer: document.getElementById('qr-preview-container'),
    qrFileMeta: document.getElementById('qr-file-meta'),
    btnCaptureSnapshot: document.getElementById('btn-capture-snapshot'),
    btnAnalyzeSnapshot: document.getElementById('btn-analyze-snapshot'),
    snapshotPreview: document.getElementById('snapshot-preview'),
    snapshotPreviewContainer: document.getElementById('snapshot-preview-container'),
    snapshotPlaceholder: document.getElementById('snapshot-placeholder'),
    snapshotResult: document.getElementById('snapshot-result'),
    resContainer: document.getElementById('result-container'),
    resGauge: document.getElementById('res-gauge'),
    resGaugeFill: document.getElementById('res-gauge-fill'),
    resScore: document.getElementById('res-score'),
    resBadge: document.getElementById('res-badge'),
    resLevel: document.getElementById('res-level'),
    resMlRow: document.getElementById('res-ml-row'),
    resMl: document.getElementById('res-ml'),
    resTime: document.getElementById('res-time'),
    resDynamic: document.getElementById('res-dynamic-details'),
    historyList: document.getElementById('history-list'),
    historyChips: document.querySelectorAll('.filter-chip'),
    statTotal: document.getElementById('stat-total'),
    statThreats: document.getElementById('stat-threats'),
    healthApi: document.getElementById('health-api'),
    healthDb: document.getElementById('health-db'),
    healthMl: document.getElementById('health-ml'),
    distSafe: document.getElementById('dist-safe'),
    distSusp: document.getElementById('dist-suspicious'),
    distFraud: document.getElementById('dist-fraud'),
    distSafePct: document.getElementById('dist-safe-pct'),
    distSuspPct: document.getElementById('dist-suspicious-pct'),
    distFraudPct: document.getElementById('dist-fraud-pct'),
    toastContainer: document.getElementById('toast-container'),
    liveVideo: document.getElementById('live-video'),
    liveCanvas: document.getElementById('live-canvas'),
    liveScannerContainer: document.getElementById('live-scanner-container'),
    scannerOverlay: document.getElementById('scanner-overlay'),
    livePlaceholder: document.getElementById('live-placeholder'),
    btnStartLive: document.getElementById('btn-start-live'),
    btnStopLive: document.getElementById('btn-stop-live'),
    liveStatus: document.getElementById('live-status'),
    liveResult: document.getElementById('live-result'),
    settingContinuousScan: document.getElementById('setting-continuous-scan'),
    settingScanInterval: document.getElementById('setting-scan-interval'),
    settingIntervalVal: document.getElementById('setting-interval-val')
  };

  const MAX_QR_FILE_SIZE = 5 * 1024 * 1024;
  let qrFile = null;
  let snapshotDataUrl = null;
  let historyData = [];
  let liveStream = null;
  let liveScanTimer = null;
  let lastLivePayload = null;
  let liveTimeInterval = null;

  init();

  async function init() {
    wireEvents();
    checkConnectionLoop();
    loadSettings();
    const authData = await SafePayAPI.getAuthData();
    if (!authData.accessToken) return showAuthUI();

    try {
      const profile = await SafePayAPI.getProfile();
      if (profile?.user) {
        await SafePayAPI.saveAuthData(authData.accessToken, profile.user.name, profile.user.email);
        showMainUI(profile.user.name, profile.user.email);
        connectWebSocket(authData.accessToken);
      } else {
        showAuthUI();
      }
    } catch {
      showAuthUI();
    }
  }

  async function loadSettings() {
    chrome.storage.local.get(['continuousScanEnabled', 'continuousScanInterval'], (items) => {
      const enabled = items.continuousScanEnabled ?? true;
      const interval = items.continuousScanInterval ?? 2.0;

      if (els.settingContinuousScan) {
        els.settingContinuousScan.checked = enabled;
      }
      if (els.settingScanInterval) {
        els.settingScanInterval.value = interval;
      }
      if (els.settingIntervalVal) {
        els.settingIntervalVal.textContent = `${Number(interval).toFixed(1)}s`;
      }
    });
  }

  function wireEvents() {
    els.navTabs.forEach(tab => {
      tab.addEventListener('click', () => {
        els.navTabs.forEach(t => t.classList.remove('active'));
        els.tabContents.forEach(c => c.classList.remove('active'));
        tab.classList.add('active');
        document.getElementById(tab.dataset.target).classList.add('active');
        if (tab.dataset.target === 'tab-history') loadHistory();
        if (tab.dataset.target === 'tab-feed') loadActiveTabScans();
        if (tab.dataset.target === 'tab-dashboard') loadDashboardData();
      });
    });

    if (els.settingContinuousScan) {
      els.settingContinuousScan.addEventListener('change', () => {
        const enabled = els.settingContinuousScan.checked;
        chrome.storage.local.set({ continuousScanEnabled: enabled }, () => {
          showToast(`Continuous QR scan ${enabled ? 'enabled' : 'disabled'}.`, 'success');
        });
      });
    }

    if (els.settingScanInterval) {
      els.settingScanInterval.addEventListener('input', () => {
        const val = parseFloat(els.settingScanInterval.value);
        els.settingIntervalVal.textContent = `${val.toFixed(1)}s`;
      });
      els.settingScanInterval.addEventListener('change', () => {
        const val = parseFloat(els.settingScanInterval.value);
        chrome.storage.local.set({ continuousScanInterval: val }, () => {
          showToast(`Scan frequency set to ${val.toFixed(1)}s.`, 'success');
        });
      });
    }

    els.scannerTabs.forEach(tab => {
      tab.addEventListener('click', () => {
        els.scannerTabs.forEach(t => t.classList.remove('active'));
        els.scannerPanels.forEach(p => p.classList.remove('active'));
        tab.classList.add('active');
        document.getElementById(tab.dataset.target).classList.add('active');
        els.resContainer.classList.remove('visible');
        setScanStatus('Ready');
        if (tab.dataset.target !== 'panel-live') stopLiveScanner();
      });
    });

    els.showRegister.addEventListener('click', () => switchAuthMode('register'));
    els.showLogin.addEventListener('click', () => switchAuthMode('login'));
    els.logoutBtn.addEventListener('click', logout);
    els.loginBtn.addEventListener('click', login);
    els.registerBtn.addEventListener('click', register);
    els.loginPass.addEventListener('keydown', event => { if (event.key === 'Enter') login(); });
    els.regPass.addEventListener('keydown', event => { if (event.key === 'Enter') register(); });
    els.regPass.addEventListener('input', updatePasswordMeter);
    els.scanSmsText.addEventListener('input', () => {
      els.smsCharCount.textContent = `${els.scanSmsText.value.length} chars`;
    });

    els.qrDropzone.addEventListener('click', () => els.qrFileInput.click());
    els.qrDropzone.addEventListener('dragover', event => {
      event.preventDefault();
      els.qrDropzone.classList.add('dragover');
    });
    els.qrDropzone.addEventListener('dragleave', () => els.qrDropzone.classList.remove('dragover'));
    els.qrDropzone.addEventListener('drop', event => {
      event.preventDefault();
      els.qrDropzone.classList.remove('dragover');
      if (event.dataTransfer.files?.[0]) handleQrFile(event.dataTransfer.files[0]);
    });
    els.qrFileInput.addEventListener('change', event => {
      if (event.target.files?.[0]) handleQrFile(event.target.files[0]);
    });

    els.btnScanSms.addEventListener('click', scanSms);
    els.btnScanUpi.addEventListener('click', scanUpi);
    els.btnScanQr.addEventListener('click', scanQr);
    els.btnCaptureSnapshot.addEventListener('click', captureSnapshot);
    els.btnAnalyzeSnapshot.addEventListener('click', analyzeSnapshot);
    els.btnStartLive.addEventListener('click', startLiveScanner);
    els.btnStopLive.addEventListener('click', stopLiveScanner);

    els.historyChips.forEach(chip => {
      chip.addEventListener('click', () => {
        els.historyChips.forEach(c => c.classList.remove('active'));
        chip.classList.add('active');
        renderHistory(chip.dataset.type);
      });
    });
  }

  function switchAuthMode(mode) {
    const registering = mode === 'register';
    els.loginForm.classList.toggle('hidden', registering);
    els.registerForm.classList.toggle('hidden', !registering);
  }

  function showAuthUI() {
    els.authContainer.classList.remove('hidden');
    els.mainContent.classList.add('hidden');
    els.userBar.classList.add('hidden');
    els.mainNav.classList.add('hidden');
  }

  function showMainUI(name, email) {
    els.authContainer.classList.add('hidden');
    els.mainContent.classList.remove('hidden');
    els.userBar.classList.remove('hidden');
    els.mainNav.classList.remove('hidden');
    els.userName.textContent = name || 'User';
    els.userEmail.textContent = email || 'Signed in';
    els.userAvatar.textContent = (name || 'U').charAt(0).toUpperCase();
    loadDashboardData();
    startLiveTimeUpdates();
  }

  async function login() {
    const phone = normalizePhone(els.loginPhone.value);
    const pass = els.loginPass.value.trim();
    if (!phone || !pass) return showToast('Enter phone number and password.', 'warning');
    if (!/^\d{10,15}$/.test(phone)) return showToast('Enter a valid phone number.', 'warning');

    setBtnLoading(els.loginBtn, true);
    try {
      const res = await SafePayAPI.login(phone, pass);
      showMainUI(res.user?.name, res.user?.email);
      showToast('Signed in successfully.', 'success');
      const token = res.access_token || res.accessToken;
      if (token) {
        connectWebSocket(token);
      }
    } catch (err) {
      showToast(err.message || 'Login failed.', 'error');
    } finally {
      setBtnLoading(els.loginBtn, false);
    }
  }

  async function register() {
    const name = els.regName.value.trim();
    const email = els.regEmail.value.trim();
    const phone = normalizePhone(els.regPhone.value);
    const pass = els.regPass.value.trim();
    if (!name || !email || !phone || !pass) return showToast('Complete every field to create an account.', 'warning');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return showToast('Enter a valid email address.', 'warning');
    if (!/^\d{10,15}$/.test(phone)) return showToast('Enter a valid phone number.', 'warning');
    if (pass.length < 8) return showToast('Password must be at least 8 characters.', 'warning');

    setBtnLoading(els.registerBtn, true);
    try {
      const res = await SafePayAPI.register(name, email, phone, pass);
      showMainUI(res.user?.name, res.user?.email);
      showToast('Account created successfully.', 'success');
      const token = res.access_token || res.accessToken;
      if (token) {
        connectWebSocket(token);
      }
    } catch (err) {
      showToast(err.message || 'Registration failed.', 'error');
    } finally {
      setBtnLoading(els.registerBtn, false);
    }
  }

  async function logout() {
    if (ws) {
      try { ws.close(); } catch(e) {}
      ws = null;
    }
    await SafePayAPI.logout();
    showAuthUI();
    showToast('Logged out successfully.', 'success');
  }

  async function scanSms() {
    const text = els.scanSmsText.value.trim();
    const sender = els.scanSmsSender.value.trim();
    if (text.length < 8) return showToast('Paste a longer message to analyze.', 'warning');

    await runScan(els.btnScanSms, 'Analyzing message...', async () => {
      const res = await SafePayAPI.scanSMS(text, sender);
      displayResult(res.analysis || res.data || res, 'sms');
      showToast('Message analysis complete.', 'success');
    });
  }

  async function scanUpi() {
    const upiId = els.scanUpiId.value.trim().toLowerCase();
    const amount = Number.parseFloat(els.scanUpiAmt.value);
    const merchant = els.scanUpiMerchant.value.trim();
    if (!/^[a-z0-9._-]{2,256}@[a-z][a-z0-9.-]{1,64}$/i.test(upiId)) return showToast('Enter a valid UPI ID, like name@bank.', 'warning');
    if (!Number.isFinite(amount) || amount <= 0) return showToast('Enter a valid amount greater than zero.', 'warning');

    await runScan(els.btnScanUpi, 'Verifying UPI...', async () => {
      const res = await SafePayAPI.scanUPI(upiId, amount, merchant);
      displayResult(res.analysis || res.data || res, 'upi', { upi_id: upiId, amount, merchant_name: merchant });
      showToast('UPI verification complete.', 'success');
    });
  }

  async function scanQr() {
    if (!qrFile) return showToast('Upload a QR image first.', 'warning');

    await runScan(els.btnScanQr, 'Reading QR image...', async () => {
      const res = await SafePayAPI.scanQRImage(qrFile);
      displayResult(res.analysis || res.data || res, 'qr', res.qr_data);
      showToast('QR analysis complete.', 'success');
    });
  }

  async function analyzeSnapshot() {
    if (!snapshotDataUrl) return showToast('Capture a snapshot first.', 'warning');

    await runScan(els.btnAnalyzeSnapshot, 'Scanning snapshot...', async () => {
      const snapshotFile = dataURLToFile(snapshotDataUrl, 'snapshot.png');
      let qrResult = null;
      let pageScan = null;
      try { qrResult = await SafePayAPI.scanQRImage(snapshotFile); } catch (err) { qrResult = { error: err.message }; }
      try { pageScan = await scanCurrentPageForLinks(); } catch (err) { pageScan = { success: false, error: err.message }; }
      updateSnapshotAnalysis(qrResult, pageScan);
      if (qrResult?.analysis) displayResult(qrResult.analysis, 'qr', qrResult.qr_data);
      showToast('Snapshot scan complete.', 'success');
    });
  }

  // ============================================================================
  // LIVE CAMERA QR SCANNER
  // ============================================================================

  async function startLiveScanner() {
    if (liveStream) return;
    setLiveStatus('Requesting camera...', '');
    try {
      liveStream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: 'environment', width: { ideal: 640 }, height: { ideal: 480 } }
      });
      els.liveVideo.srcObject = liveStream;
      await els.liveVideo.play();
      els.liveScannerContainer.classList.add('scanning');
      els.btnStartLive.classList.add('hidden');
      els.btnStopLive.classList.remove('hidden');
      setLiveStatus('Scanning for QR codes...', 'active');
      lastLivePayload = null;
      els.liveResult.innerHTML = '';
      liveScanLoop();
    } catch (err) {
      console.error('Camera error:', err);
      setLiveStatus('Camera access denied. Allow camera permission and retry.', 'error');
      showToast('Unable to access camera. Check browser permissions.', 'error');
    }
  }

  function stopLiveScanner() {
    if (liveScanTimer) { clearTimeout(liveScanTimer); liveScanTimer = null; }
    if (liveStream) {
      liveStream.getTracks().forEach(track => track.stop());
      liveStream = null;
    }
    els.liveVideo.srcObject = null;
    els.liveScannerContainer.classList.remove('scanning', 'scanner-detected');
    els.btnStartLive.classList.remove('hidden');
    els.btnStopLive.classList.add('hidden');
    setLiveStatus('Camera idle', '');
  }

  function liveScanLoop() {
    if (!liveStream) return;
    const video = els.liveVideo;
    if (video.readyState < video.HAVE_ENOUGH_DATA) {
      liveScanTimer = setTimeout(liveScanLoop, 200);
      return;
    }

    const canvas = els.liveCanvas;
    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    ctx.drawImage(video, 0, 0, canvas.width, canvas.height);

    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    let qrResult = null;
    if (typeof jsQR !== 'undefined') {
      qrResult = jsQR(imageData.data, imageData.width, imageData.height, { inversionAttempts: 'dontInvert' });
    }

    if (qrResult && qrResult.data) {
      const payload = qrResult.data;
      els.liveScannerContainer.classList.add('scanner-detected');

      if (payload !== lastLivePayload) {
        lastLivePayload = payload;
        setLiveStatus('QR Detected! Analyzing...', 'active');
        handleLiveQrDetected(payload);
      }
      // Slow down after detection
      liveScanTimer = setTimeout(liveScanLoop, 800);
    } else {
      els.liveScannerContainer.classList.remove('scanner-detected');
      liveScanTimer = setTimeout(liveScanLoop, 150);
    }
  }

  async function handleLiveQrDetected(payload) {
    els.liveResult.innerHTML = `
      <div class="live-result-card">
        <div class="qr-payload-label">Decoded QR Payload</div>
        <div class="qr-payload-value">${escapeHtml(payload)}</div>
        <div class="qr-action-row">
          <button class="btn btn-primary" id="btn-live-analyze">🛡️ Analyze for Fraud</button>
        </div>
      </div>
    `;

    document.getElementById('btn-live-analyze').addEventListener('click', async () => {
      const btn = document.getElementById('btn-live-analyze');
      setBtnLoading(btn, true);
      try {
        const res = await SafePayAPI.scanQRPayload(payload);
        if (res?.analysis) {
          displayResult(res.analysis, 'qr', res.qr_data);
          showToast('QR analysis complete.', 'success');
          setLiveStatus('Analysis complete — see results below.', 'active');
        } else {
          showToast('Backend returned no analysis data.', 'warning');
        }
      } catch (err) {
        showToast(err.message || 'Analysis failed.', 'error');
        setLiveStatus('Analysis failed.', 'error');
      } finally {
        setBtnLoading(btn, false);
      }
    });

    setLiveStatus('QR detected. Tap Analyze to check for fraud.', 'active');
  }

  function setLiveStatus(text, state) {
    if (!els.liveStatus) return;
    els.liveStatus.textContent = text;
    els.liveStatus.className = `live-status ${state}`.trim();
  }

  async function runScan(button, label, action) {
    setBtnLoading(button, true);
    setScanStatus(label, 'scanning');
    try {
      await action();
      setScanStatus('Complete');
    } catch (err) {
      setScanStatus('Needs attention', 'error');
      showToast(err.message || 'Scan failed.', 'error');
    } finally {
      setBtnLoading(button, false);
    }
  }

  function handleQrFile(file) {
    if (!/^image\/(png|jpeg|jpg)$/i.test(file.type)) return showToast('Use a PNG or JPG image.', 'warning');
    if (file.size > MAX_QR_FILE_SIZE) return showToast('QR image must be under 5 MB.', 'warning');

    qrFile = file;
    els.qrFileMeta.textContent = `${file.name} - ${formatBytes(file.size)}`;
    const reader = new FileReader();
    reader.onload = event => {
      els.qrPreview.src = event.target.result;
      els.qrPreviewContainer.classList.add('has-file');
      els.btnScanQr.disabled = false;
      setScanStatus('QR ready');
    };
    reader.readAsDataURL(file);
  }

  async function captureSnapshot() {
    setBtnLoading(els.btnCaptureSnapshot, true);
    setScanStatus('Capturing page...', 'scanning');
    try {
      const tabs = await new Promise(res => chrome.tabs.query({ active: true, currentWindow: true }, res));
      const activeTab = tabs?.[0];
      
      // Request explicit host permissions to bypass activeTab restrictions
      if (activeTab && activeTab.url && !activeTab.url.startsWith('chrome://') && !activeTab.url.startsWith('edge://')) {
        try {
          const origin = new URL(activeTab.url).origin + '/*';
          const hasHostPerm = await new Promise(res => chrome.permissions.contains({ origins: [origin] }, res));
          if (!hasHostPerm) {
            // This works because we are in a direct user gesture (click event)
            await new Promise(res => chrome.permissions.request({ origins: [origin] }, res));
          }
        } catch (e) {
          // Ignore URL parsing errors
        }
      }

      // Capture directly from popup to preserve execution context
      const dataUrl = await new Promise((resolve, reject) => {
        const windowId = activeTab ? activeTab.windowId : null;
        chrome.tabs.captureVisibleTab(windowId, { format: 'png' }, response => {
          if (chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
          } else if (response) {
            resolve(response);
          } else {
            reject(new Error('Unable to capture snapshot'));
          }
        });
      });

      const compressed = await compressDataUrl(dataUrl, { maxWidth: 1200, maxHeight: 1200, quality: 0.85 });
      snapshotDataUrl = compressed;
      els.snapshotPreview.src = compressed;
      els.snapshotPreviewContainer.classList.add('has-snapshot');
      els.snapshotPlaceholder.style.display = 'none';
      els.btnAnalyzeSnapshot.disabled = false;
      els.snapshotResult.innerHTML = '<div class="snapshot-message">Snapshot captured. Run detection to inspect QR codes and visible page links.</div>';
      setScanStatus('Snapshot ready');
      showToast('Snapshot captured.', 'success');
    } catch (err) {
      setScanStatus('Capture failed', 'error');
      showToast(err.message || 'Could not capture snapshot.', 'error');
    } finally {
      setBtnLoading(els.btnCaptureSnapshot, false);
    }
  }

  async function compressDataUrl(dataUrl, { maxWidth = 1200, maxHeight = 1200, quality = 0.9 } = {}) {
    return new Promise((resolve, reject) => {
      const image = new Image();
      image.onload = () => {
        const ratio = Math.min(maxWidth / image.width, maxHeight / image.height, 1);
        const width = Math.round(image.width * ratio);
        const height = Math.round(image.height * ratio);
        const canvas = document.createElement('canvas');
        canvas.width = width;
        canvas.height = height;
        const ctx = canvas.getContext('2d');
        ctx.drawImage(image, 0, 0, width, height);
        resolve(canvas.toDataURL('image/jpeg', quality));
      };
      image.onerror = () => reject(new Error('Snapshot compression failed'));
      image.src = dataUrl;
    });
  }

  function displayResult(rawAnalysis, type, extraData = null) {
    const analysis = normalizeAnalysis(rawAnalysis);
    const score = clamp(Math.round(analysis.risk_score), 0, 100);
    const level = String(analysis.risk_level || riskLevelFromScore(score)).toUpperCase();
    const status = String(analysis.status || statusFromScore(score)).toUpperCase();
    const mlScore = Number(analysis.ml_score || analysis.ml_probability || 0);

    els.resScore.textContent = score;
    els.resGaugeFill.style.strokeDashoffset = 251.2 - (score / 100) * 251.2;
    els.resGauge.className = 'risk-gauge ' + riskClass(score);
    els.resBadge.className = 'risk-status-badge ' + badgeClass(score);
    els.resBadge.textContent = status;
    els.resLevel.textContent = level;
    els.resTime.textContent = analysis.execution_time_ms ? Number(analysis.execution_time_ms).toFixed(1) : '--';

    if (mlScore > 0) {
      els.resMlRow.classList.remove('hidden');
      els.resMl.textContent = `${Math.round(mlScore * (mlScore <= 1 ? 100 : 1))}%`;
    } else {
      els.resMlRow.classList.add('hidden');
    }

    els.resDynamic.innerHTML = buildResultDetails(analysis, type, extraData);
    els.resContainer.classList.add('visible');
  }

  function normalizeAnalysis(analysis) {
    const source = analysis?.fraud_assessment || analysis?.analysis || analysis || {};
    const issues = source.issues || source.matched_rules || source.reasons || [];
    return {
      ...source,
      risk_score: Number(source.risk_score ?? source.score ?? source.final_score ?? 0),
      risk_level: source.risk_level ?? source.level,
      status: source.status ?? source.verdict,
      matched_rules: Array.isArray(source.matched_rules) ? source.matched_rules : issues,
      matched_keywords: source.matched_keywords || source.keywords || [],
      detected_urls: source.detected_urls || source.urls || [],
      phone_numbers: source.phone_numbers || [],
      recommendations: source.recommendations || source.actions || [],
      upi_schemes: source.upi_schemes || source.upiSchemes || [],
      investment_scams: source.investment_scams || source.investmentScams || false
    };
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

  function buildResultDetails(analysis, type, extraData) {
    const sections = [];
    const rules = normalizeList(analysis.matched_rules);
    const keywords = normalizeList(analysis.matched_keywords);
    const urls = normalizeList(analysis.detected_urls);
    const phones = normalizeList(analysis.phone_numbers);
    const recommendations = normalizeList(analysis.recommendations);
    const upiSchemes = normalizeList(analysis.upi_schemes || analysis.upiSchemes);
    const hasInvestmentScam = !!(analysis.investment_scams || analysis.investmentScams);

    if (type === 'qr' && extraData) {
      const rawQr = extraData.raw_qr;
      const upiDetails = parseUpiQrPayload(rawQr);
      
      if (upiDetails) {
        sections.push(section('Decoded QR data', `
          <ul class="phone-list">
            <li class="phone-item"><strong>UPI ID:</strong> ${escapeHtml(upiDetails.upiId)}</li>
            <li class="phone-item"><strong>Name:</strong> ${escapeHtml(upiDetails.name)}</li>
            <li class="phone-item"><strong>Amount:</strong> ${escapeHtml(upiDetails.amount)}</li>
            <li class="phone-item"><strong>Currency:</strong> ${escapeHtml(upiDetails.currency)}</li>
            <li class="phone-item"><strong>Note:</strong> ${escapeHtml(upiDetails.note)}</li>
          </ul>
          <details style="margin-top: 8px; border: 1px solid var(--border-glass); border-radius: 6px; padding: 4px; background: var(--bg-secondary);">
            <summary style="font-size: 0.8rem; cursor: pointer; color: var(--text-muted); outline: none;">Advanced Details</summary>
            <div style="font-size: 0.75rem; color: var(--text-primary); word-break: break-all; margin-top: 4px; font-family: monospace;">
              ${escapeHtml(upiDetails.raw)}
            </div>
          </details>
        `));
      } else {
        sections.push(section('Decoded QR data', `
          <ul class="phone-list">
            <li class="phone-item"><strong>UPI ID:</strong> ${escapeHtml(extraData.upi_id || 'N/A')}</li>
            <li class="phone-item"><strong>Amount:</strong> INR ${escapeHtml(extraData.amount || '0')}</li>
            ${extraData.merchant_name ? `<li class="phone-item"><strong>Merchant:</strong> ${escapeHtml(extraData.merchant_name)}</li>` : ''}
          </ul>
          ${rawQr ? `
            <details style="margin-top: 8px; border: 1px solid var(--border-glass); border-radius: 6px; padding: 4px; background: var(--bg-secondary);">
              <summary style="font-size: 0.8rem; cursor: pointer; color: var(--text-muted); outline: none;">Advanced Details</summary>
              <div style="font-size: 0.75rem; color: var(--text-primary); word-break: break-all; margin-top: 4px; font-family: monospace;">
                ${escapeHtml(rawQr)}
              </div>
            </details>
          ` : ''}
        `));
      }
    }

    if (type === 'upi' && extraData) {
      sections.push(section('Payment context', `
        <ul class="phone-list">
          <li class="phone-item"><strong>UPI ID:</strong> ${escapeHtml(extraData.upi_id)}</li>
          <li class="phone-item"><strong>Amount:</strong> INR ${escapeHtml(extraData.amount)}</li>
          ${extraData.merchant_name ? `<li class="phone-item"><strong>Merchant:</strong> ${escapeHtml(extraData.merchant_name)}</li>` : ''}
        </ul>
      `));
    }

    if (hasInvestmentScam) {
      sections.push(section('⚠️ High-Risk Activity', `<div class="snapshot-text text-danger" style="color: #d50000; font-weight: bold; padding: 4px 0;">Potential investment scam language detected on the page.</div>`));
    }
    if (upiSchemes.length) {
      sections.push(section('Detected UPI Links', `<ul class="url-list">${upiSchemes.map(sch => `<li class="url-item">${escapeHtml(sch)}</li>`).join('')}</ul>`));
    }
    if (keywords.length) sections.push(section('Suspicious keywords', `<div class="keyword-chips">${keywords.map(k => `<span class="keyword-chip">${escapeHtml(k)}</span>`).join('')}</div>`));
    if (urls.length) sections.push(section('Detected URLs', `<ul class="url-list">${urls.map(url => `<li class="url-item">${escapeHtml(url)}</li>`).join('')}</ul>`));
    if (phones.length) sections.push(section('Detected phone numbers', `<ul class="phone-list">${phones.map(phone => `<li class="phone-item">${escapeHtml(phone)}</li>`).join('')}</ul>`));
    if (rules.length) sections.push(section('Risk signals', `<ul class="phone-list">${rules.map(rule => `<li class="phone-item">${escapeHtml(rule)}</li>`).join('')}</ul>`));
    if (recommendations.length) sections.push(section('Recommended action', `<ul class="phone-list">${recommendations.map(item => `<li class="phone-item">${escapeHtml(item)}</li>`).join('')}</ul>`));

    if (!sections.length) sections.push(section('Summary', '<div class="snapshot-message">No detailed findings were returned by the backend.</div>'));
    return sections.join('');
  }

  function section(title, html) {
    return `<div class="result-section fade-in"><div class="result-section-title">${escapeHtml(title)}</div>${html}</div>`;
  }

  function updateSnapshotAnalysis(res, pageScan) {
    const chunks = [];
    if (res?.qr_data) {
      const rawQr = res.qr_data.raw_qr || 'N/A';
      const upiDetails = parseUpiQrPayload(rawQr);
      
      if (upiDetails) {
        chunks.push(`<div class="snapshot-section"><strong>Decoded QR payload</strong>
          <div class="snapshot-text">UPI ID: ${escapeHtml(upiDetails.upiId)}</div>
          <div class="snapshot-text">Name: ${escapeHtml(upiDetails.name)}</div>
          <div class="snapshot-text">Amount: ${escapeHtml(upiDetails.amount)}</div>
          <div class="snapshot-text">Currency: ${escapeHtml(upiDetails.currency)}</div>
          <div class="snapshot-text">Note: ${escapeHtml(upiDetails.note)}</div>
          <details style="margin-top: 8px; border: 1px solid var(--border-glass); border-radius: 6px; padding: 4px; background: var(--bg-secondary);">
            <summary style="font-size: 0.8rem; cursor: pointer; color: var(--text-muted); outline: none;">Advanced Details</summary>
            <div style="font-size: 0.75rem; color: var(--text-primary); word-break: break-all; margin-top: 4px; font-family: monospace;">
              ${escapeHtml(upiDetails.raw)}
            </div>
          </details>
        </div>`);
      } else {
        chunks.push(`<div class="snapshot-section"><strong>Decoded QR payload</strong>
          <details style="margin-top: 4px; border: 1px solid var(--border); border-radius: 6px; padding: 4px; background: rgba(0,0,0,0.1);">
            <summary style="font-size: 0.8rem; cursor: pointer; color: var(--muted); outline: none;">Advanced Details</summary>
            <div style="font-size: 0.75rem; color: var(--text); word-break: break-all; margin-top: 4px; font-family: monospace;">
              ${escapeHtml(rawQr)}
            </div>
          </details>
        </div>`);
      }
    }
    if (res?.error) chunks.push(`<div class="snapshot-section"><strong>QR scan</strong><div class="snapshot-text">${escapeHtml(res.error)}</div></div>`);
    if (pageScan?.success) {
      const links = pageScan.threats?.suspiciousUrls || [];
      const upiIds = pageScan.threats?.upiIds || [];
      const upiSchemes = pageScan.threats?.upiSchemes || [];
      const investmentScams = pageScan.threats?.investmentScams || false;
      if (links.length) chunks.push(`<div class="snapshot-section"><strong>Page suspicious links</strong>${links.map(link => `<div class="snapshot-text">${escapeHtml(link)}</div>`).join('')}</div>`);
      if (upiIds.length) chunks.push(`<div class="snapshot-section"><strong>Page UPI IDs</strong>${upiIds.map(id => `<div class="snapshot-text">${escapeHtml(id)}</div>`).join('')}</div>`);
      if (upiSchemes.length) chunks.push(`<div class="snapshot-section"><strong>Page UPI Links</strong>${upiSchemes.map(sch => `<div class="snapshot-text">${escapeHtml(sch)}</div>`).join('')}</div>`);
      if (investmentScams) chunks.push(`<div class="snapshot-section"><strong>⚠️ High Risk</strong><div class="snapshot-text text-danger" style="color: #d50000; font-weight: bold;">Potential investment scam language detected on page.</div></div>`);
    } else if (pageScan?.error) {
      chunks.push(`<div class="snapshot-section"><strong>Page scan</strong><div class="snapshot-text">${escapeHtml(pageScan.error)}</div></div>`);
    }
    els.snapshotResult.innerHTML = chunks.join('') || '<div class="snapshot-message">No QR code or suspicious links were detected.</div>';
  }

  async function scanCurrentPageForLinks() {
    return new Promise((resolve, reject) => {
      chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
        if (!tabs?.[0]?.id) return reject(new Error('Unable to locate active tab'));
        let didRespond = false;
        const timeout = setTimeout(() => {
          if (didRespond) return;
          didRespond = true;
          reject(new Error('Page scan timed out. Make sure SafePay content script is active.'));
        }, 2500);

        chrome.tabs.sendMessage(tabs[0].id, { type: 'SCAN_PAGE_LINKS' }, response => {
          if (didRespond) return;
          didRespond = true;
          clearTimeout(timeout);
          if (chrome.runtime.lastError) return reject(new Error(chrome.runtime.lastError.message));
          if (!response) return reject(new Error('No page scan response received'));
          resolve(response);
        });
      });
    });
  }

  function dataURLToFile(dataUrl, filename) {
    const [header, payload] = dataUrl.split(',');
    const mime = header.match(/:(.*?);/)?.[1] || 'image/png';
    const binary = atob(payload);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return new File([bytes], filename, { type: mime });
  }

  async function loadHistory() {
    els.historyList.innerHTML = '<div class="empty-state skeleton" style="height: 200px; width: 100%;"></div>';
    try {
      const [fraud, sms, qr] = await Promise.all([
        SafePayAPI.getFraudHistory().catch(() => ({ history: [] })),
        SafePayAPI.getSMSHistory().catch(() => ({ history: [] })),
        SafePayAPI.getQRHistory().catch(() => ({ history: [] }))
      ]);
      historyData = [
        ...(fraud.history || []).map(i => ({ ...i, source: 'FRAUD' })),
        ...(sms.history || []).map(i => ({ ...i, source: 'SMS' })),
        ...(qr.history || []).map(i => ({ ...i, source: 'QR' }))
      ].sort((a, b) => (parseTimestamp(b.created_at)?.getTime() || 0) - (parseTimestamp(a.created_at)?.getTime() || 0));
      renderHistory('ALL');
    } catch {
      els.historyList.innerHTML = '<div class="history-empty">Failed to load history</div>';
    }
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

  function refreshLiveTimeLabels() {
    document.querySelectorAll('[data-ist-timestamp]').forEach(el => {
      const ts = el.getAttribute('data-ist-timestamp');
      if (!ts) return;
      const options = el.dataset.istOptions ? JSON.parse(el.dataset.istOptions) : {};
      el.textContent = formatIST(ts, options);
    });
  }

  function startLiveTimeUpdates() {
    if (liveTimeInterval) return;
    refreshLiveTimeLabels();
    liveTimeInterval = setInterval(refreshLiveTimeLabels, 30000);
  }

  function renderHistory(filter) {
    let filtered = historyData;
    if (filter === 'QR') filtered = historyData.filter(i => i.source === 'FRAUD' || i.source === 'QR');
    if (filter === 'TEXT') filtered = historyData.filter(i => i.source === 'SMS');
    if (!filtered.length) {
      els.historyList.innerHTML = '<div class="history-empty"><span class="empty-icon">-</span>No scan history found</div>';
      return;
    }
    els.historyList.innerHTML = '';
    filtered.forEach(item => {
      const score = clamp(Math.round(Number(item.risk_score || 0)), 0, 100);
      const date = parseTimestamp(item.created_at);
      const timeStr = date ? formatIST(date) : 'Recent';
      const value = item.upi_id || item.message || item.input_value || item.raw_qr || 'Unknown scan';
      const el = document.createElement('div');
      el.className = 'history-card fade-in';
      el.innerHTML = `
        <div class="history-risk-indicator ${badgeClass(score)}">${score}</div>
        <div class="history-details">
          <div class="history-type">${escapeHtml(item.source)} scan - ${escapeHtml(item.status || statusFromScore(score))}</div>
          <div class="history-value">${escapeHtml(value)}</div>
          <div class="history-time" data-ist-timestamp="${escapeHtml(date?.toISOString() || '')}">${escapeHtml(timeStr)}</div>
        </div>
      `;
      els.historyList.appendChild(el);
    });
    refreshLiveTimeLabels();
  }

  async function loadDashboardData() {
    try {
      const [health, stats] = await Promise.all([
        SafePayAPI.getHealthReport().catch(() => null),
        SafePayAPI.getFraudStats().catch(() => null)
      ]);
      if (health?.overall_status) {
        const apiStatus = health.overall_status;
        const apiOk = apiStatus === 'HEALTHY' || apiStatus === 'WARNING';
        const apiLabel = apiOk ? 'ONLINE' : apiStatus === 'HIGH_LOAD' ? 'DEGRADED' : 'ERROR';
        updateHealthStatus(els.healthApi, apiOk, apiStatus, apiLabel);
        updateHealthStatus(els.healthDb, health.services?.database === 'CONNECTED', health.services?.database || 'UNKNOWN');
        const mlReady = health.services?.upi_model === 'READY' && health.services?.text_model === 'READY';
        updateHealthStatus(els.healthMl, mlReady, `${health.services?.upi_model || 'UNKNOWN'} / ${health.services?.text_model || 'UNKNOWN'}`);
      } else {
        updateHealthStatus(els.healthApi, false, 'OFFLINE');
        updateHealthStatus(els.healthDb, false, 'UNKNOWN');
        updateHealthStatus(els.healthMl, false, 'UNKNOWN');
      }

      if (stats && stats.success) {
        els.statTotal.textContent = stats.total_scans ?? 0;
        els.statThreats.textContent = stats.threats_blocked ?? 0;
        
        const total = stats.total_scans || 1;
        const safe = stats.safe_count || 0;
        const suspicious = stats.suspicious_count || 0;
        const fraud = stats.fraud_count || 0;
        const safePct = (safe / total) * 100;
        const suspPct = (suspicious / total) * 100;
        const fraudPct = (fraud / total) * 100;
        els.distSafe.style.width = `${safePct}%`;
        els.distSusp.style.width = `${suspPct}%`;
        els.distFraud.style.width = `${fraudPct}%`;
        els.distSafePct.textContent = `${Math.round(safePct)}%`;
        els.distSuspPct.textContent = `${Math.round(suspPct)}%`;
        els.distFraudPct.textContent = `${Math.round(fraudPct)}%`;
      } else {
        els.statTotal.textContent = '0';
        els.statThreats.textContent = '0';
        els.distSafe.style.width = '0%';
        els.distSusp.style.width = '0%';
        els.distFraud.style.width = '0%';
        els.distSafePct.textContent = '0%';
        els.distSuspPct.textContent = '0%';
        els.distFraudPct.textContent = '0%';
      }
    } catch (err) {
      console.error('Dashboard error:', err);
    }
  }

  function updateHealthStatus(el, isOk, detail = '', label = '') {
    el.className = `health-value ${isOk ? 'healthy' : 'unhealthy'}`;
    el.textContent = label || (isOk ? 'ONLINE' : 'ERROR');
    if (detail) el.textContent += ` (${detail})`;
  }

  async function checkConnection() {
    try {
      const { online } = await new Promise(resolve => {
        chrome.runtime.sendMessage({ type: 'GET_BACKEND_STATUS' }, res => {
          if (chrome.runtime.lastError) resolve({ online: false });
          else resolve(res || { online: false });
        });
      });
      els.statusDot.className = `status-dot ${online ? 'online' : 'offline'}`;
      els.statusText.textContent = online ? 'Connected' : 'Offline';
    } catch {
      els.statusDot.className = 'status-dot offline';
      els.statusText.textContent = 'Offline';
    }
  }

  function checkConnectionLoop() {
    checkConnection();
    setInterval(checkConnection, 10000);
  }

  function setBtnLoading(btn, isLoading) {
    btn.classList.toggle('loading', isLoading);
    btn.disabled = isLoading;
  }

  function setScanStatus(text, state = '') {
    if (!els.scanStatusPill) return;
    els.scanStatusPill.textContent = text;
    els.scanStatusPill.className = `scan-status-pill ${state}`.trim();
  }

  function updatePasswordMeter() {
    const password = els.regPass.value;
    let score = 0;
    if (password.length >= 8) score += 1;
    if (/[A-Z]/.test(password) && /[a-z]/.test(password)) score += 1;
    if (/\d/.test(password)) score += 1;
    if (/[^A-Za-z0-9]/.test(password)) score += 1;
    els.passwordMeter.className = 'password-meter ' + (score >= 4 ? 'strong' : score >= 2 ? 'medium' : password ? 'weak' : '');
  }

  function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `<div class="toast-message">${escapeHtml(message)}</div><button class="toast-close" aria-label="Dismiss">x</button>`;
    els.toastContainer.appendChild(toast);
    toast.querySelector('.toast-close').addEventListener('click', () => removeToast(toast));
    setTimeout(() => removeToast(toast), 4000);
  }

  function removeToast(toast) {
    if (!toast.parentElement) return;
    toast.classList.add('toast-out');
    setTimeout(() => toast.remove(), 220);
  }

  function normalizePhone(value) { return String(value || '').replace(/\D/g, ''); }
  function normalizeList(value) { return Array.isArray(value) ? value.filter(Boolean) : value ? [value] : []; }
  function clamp(value, min, max) { return Math.max(min, Math.min(max, Number.isFinite(value) ? value : min)); }
  function riskLevelFromScore(score) { return score >= 75 ? 'HIGH' : score >= 45 ? 'MEDIUM' : 'LOW'; }
  function statusFromScore(score) { return score >= 75 ? 'FRAUD' : score >= 45 ? 'SUSPICIOUS' : 'SAFE'; }
  function riskClass(score) { return score >= 90 ? 'risk-critical' : score >= 75 ? 'risk-high' : score >= 45 ? 'risk-medium' : 'risk-safe'; }
  function badgeClass(score) { return score >= 75 ? 'fraud' : score >= 45 ? 'suspicious' : 'safe'; }
  function formatBytes(bytes) { return `${(bytes / 1024 / 1024).toFixed(2)} MB`; }
  function escapeHtml(value) {
    return String(value ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // ============================================================================
  // WEBSOCKET & FEED IMPLEMENTATION
  // ============================================================================
  let ws = null;
  const globalThreats = [];

  function connectWebSocket(token) {
    if (ws) {
      try { ws.close(); } catch(e) {}
    }
    
    const wsUrl = `ws://127.0.0.1:8000/ws/alerts?token=${encodeURIComponent(token)}`;
    ws = new WebSocket(wsUrl);
    
    const statusEl = document.getElementById('feed-status');

    ws.onopen = () => {
      console.log("🔌 Connected to SafePay alert stream.");
      if (statusEl) {
        statusEl.textContent = "● LIVE";
        statusEl.style.color = "#4ade80";
      }
    };

    ws.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data);
        if (message.type === 'NEW_THREAT') {
          handleIncomingGlobalThreat(message.data);
        }
      } catch (e) {
        console.error("Error parsing WebSocket message:", e);
      }
    };

    ws.onclose = () => {
      console.log("🔌 SafePay alert stream disconnected.");
      if (statusEl) {
        statusEl.textContent = "● OFFLINE";
        statusEl.style.color = "#f87171";
      }
      setTimeout(async () => {
        const authData = await SafePayAPI.getAuthData();
        if (authData.accessToken) {
          connectWebSocket(authData.accessToken);
        }
      }, 5000);
    };

    ws.onerror = (err) => {
      console.error("WebSocket error:", err);
    };
  }

  function handleIncomingGlobalThreat(threat) {
    globalThreats.unshift(threat);
    if (globalThreats.length > 50) globalThreats.pop();
    renderGlobalThreats();
  }

  function renderGlobalThreats() {
    const listEl = document.getElementById('threat-feed-list');
    if (!listEl) return;
    
    if (globalThreats.length === 0) {
      listEl.innerHTML = '<div class="feed-empty-state">No global threats reported in this session.</div>';
      return;
    }
    
    listEl.innerHTML = globalThreats.map(threat => {
      const typeClass = (threat.threat_type || 'upi').toLowerCase();
      const scoreClass = threat.risk_score >= 75 ? 'high' : 'medium';
      const riskLevel = threat.risk_level || 'SUSPICIOUS';
      const parsedTimestamp = parseTimestamp(threat.timestamp);
      const timeStr = parsedTimestamp ? formatIST(parsedTimestamp) : 'Unknown time';
      const valStr = escapeHtml(threat.value);
      const merchantSection = threat.merchant_name && threat.merchant_name !== 'Unknown' 
        ? `<div style="font-size: 10px; color: var(--text-muted);">Merchant: ${escapeHtml(threat.merchant_name)}</div>`
        : '';

      return `
        <div class="threat-feed-item ${scoreClass}">
          <div class="threat-feed-header">
            <span class="threat-type ${typeClass}">${escapeHtml(threat.threat_type)}</span>
            <span class="threat-score ${scoreClass}">${threat.risk_score}/100 [${riskLevel}]</span>
          </div>
          <div class="threat-value">${valStr}</div>
          ${merchantSection}
          <div class="threat-meta">
            <span>SafePay Network Alert</span>
            <span data-ist-timestamp="${escapeHtml(parsedTimestamp?.toISOString() || '')}">${escapeHtml(timeStr)}</span>
          </div>
        </div>
      `;
    }).join('');
  }

  async function loadActiveTabScans() {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const activeTab = tabs[0];
      if (!activeTab?.id) return;
      
      chrome.runtime.sendMessage({
        type: 'GET_TAB_RESULTS',
        tabId: activeTab.id
      }, (response) => {
        if (chrome.runtime.lastError) {
          console.warn("Could not fetch active tab results");
          return;
        }
        renderActiveTabScans(response || { upiScans: [], urlScans: [] });
      });
    });
  }

  function renderActiveTabScans(data) {
    const listEl = document.getElementById('active-tab-threats-list');
    if (!listEl) return;

    const upis = data.upiScans || [];
    const urls = data.urlScans || [];
    
    const threats = [];
    upis.forEach(u => {
      const risk = u.analysis?.risk_score || 0;
      if (risk >= 45) {
        threats.push({
          type: 'UPI ID',
          value: u.upi_id,
          score: risk,
          level: u.analysis?.risk_level || 'SUSPICIOUS'
        });
      }
    });

    urls.forEach(u => {
      const risk = u.risk_score || 0;
      if (risk >= 45) {
        threats.push({
          type: 'URL Link',
          value: u.message,
          score: risk,
          level: u.risk_level || 'SUSPICIOUS'
        });
      }
    });

    if (threats.length === 0) {
      listEl.innerHTML = '<div class="feed-empty-state" style="padding: 15px 0;">No active threats scanned on this tab yet.</div>';
      return;
    }

    listEl.innerHTML = threats.map(t => {
      const badgeClass = t.score >= 75 ? 'danger' : 'warning';
      return `
        <div class="active-threat-card ${badgeClass}">
          <div class="active-threat-card-left">
            <span class="active-threat-value">${escapeHtml(t.value)}</span>
            <span class="active-threat-type">${escapeHtml(t.type)}</span>
          </div>
          <span class="active-threat-badge ${badgeClass}">${t.score}/100</span>
        </div>
      `;
    }).join('');
  }

  // Listen for scan updates from the background script
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'TAB_SCANS_UPDATED') {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]?.id === message.tabId) {
          renderActiveTabScans(message.data);
        }
      });
    }
  });
});
