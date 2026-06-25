// SafePay Background Service Worker — Phase 2 Upgrade
'use strict';

const BACKEND_URL = 'http://127.0.0.1:8000';

// Side Panel behavior: open side panel on action button click
if (chrome.sidePanel && chrome.sidePanel.setPanelBehavior) {
  chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch(err => console.error(err));
}

// State for sliding batched scan queue
const upiScanQueue = new Map(); // tabId -> Set of UPI IDs
const urlScanQueue = new Map(); // tabId -> Set of URLs
const queueTimers = new Map();  // tabId -> timerId

// Tab-specific threat results
const tabThreatResults = new Map(); // tabId -> { upiScans: [], urlScans: [] }

// Session-level scanned threats cache to prevent duplicate backend requests (5 min TTL)
const processedThreatsCache = new Set();

// Badge color palette
const BADGE_COLORS = {
  safe:        '#00C853',
  warning:     '#FFD600',
  danger:      '#D50000',
  offline:     '#757575',
  investment:  '#7B1FA2'  // purple for investment scam alerts
};

// ============================================================================
// INSTALL — context menus + badge init + alarms
// ============================================================================
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'safepay-scan-selection',
    title: 'Scan with SafePay AI',
    contexts: ['selection']
  });
  chrome.contextMenus.create({
    id: 'safepay-scan-link',
    title: 'Check link with SafePay',
    contexts: ['link']
  });

  chrome.action.setBadgeBackgroundColor({ color: BADGE_COLORS.safe });
  chrome.action.setBadgeText({ text: '' });

  // Periodic backend health check every 2 minutes using alarms (battery-friendly)
  chrome.alarms.create('safepay-health-check', { periodInMinutes: 2 });
});

// ============================================================================
// ALARMS — periodic health check
// ============================================================================
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'safepay-health-check') {
    checkBackendStatus().then(({ online }) => {
      // If backend goes offline, grey out the badge on all tabs
      if (!online) {
        chrome.tabs.query({}, (tabs) => {
          tabs.forEach(tab => {
            chrome.action.setBadgeBackgroundColor({ color: BADGE_COLORS.offline, tabId: tab.id });
            chrome.action.setBadgeText({ text: '!', tabId: tab.id });
          });
        });
      }
    });
  }
});

// ============================================================================
// TAB ACTIVATION — trigger content scan when user switches to a tab
// ============================================================================
chrome.tabs.onActivated.addListener(({ tabId }) => {
  // Small delay to let the page settle before scanning
  setTimeout(() => {
    chrome.tabs.sendMessage(tabId, { type: 'SCAN_NOW' }, () => {
      // Suppress errors (content script may not be injected yet)
      if (chrome.runtime.lastError) { /* silent */ }
    });
  }, 800);
});

// ============================================================================
// TAB UPDATE — rescan when a page finishes loading (URL navigation)
// ============================================================================
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'complete') {
    // Reset badge on navigation
    chrome.action.setBadgeText({ text: '', tabId });
    // Allow content script to initialise before sending message
    setTimeout(() => {
      chrome.tabs.sendMessage(tabId, { type: 'SCAN_NOW' }, () => {
        if (chrome.runtime.lastError) { /* content script not ready yet — ok */ }
      });
    }, 1500);
  }
});

// ============================================================================
// CONTEXT MENU CLICKS
// ============================================================================
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === 'safepay-scan-selection' && info.selectionText) {
    await scanAndNotify('text', info.selectionText, tab);
  }
  if (info.menuItemId === 'safepay-scan-link' && info.linkUrl) {
    await scanAndNotify('url', info.linkUrl, tab);
  }
});

// ============================================================================
// MESSAGE HANDLING — from content script and popup
// ============================================================================
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

  if (message.type === 'PAGE_THREATS_FOUND') {
    // Phase 2: Enqueue threats to the sliding batched scan queue
    enqueueThreatScan(sender.tab?.id, message.data);
    sendResponse({ received: true });
    return false;
  }

  if (message.type === 'GET_TAB_RESULTS') {
    const tabId = message.tabId || sender.tab?.id;
    if (tabId) {
      sendResponse(tabThreatResults.get(tabId) || { upiScans: [], urlScans: [] });
    } else {
      sendResponse({ upiScans: [], urlScans: [] });
    }
    return false;
  }

  if (message.type === 'SUSPECTED_QR_FOUND') {
    console.log("Suspected QR detected in tab", sender.tab?.id, message.data);
    sendResponse({ received: true });
    return false;
  }

  if (message.type === 'CLEAR_BADGE') {
    chrome.action.setBadgeText({ text: '', tabId: sender.tab?.id });
    sendResponse({ received: true });
    return false;
  }

  if (message.type === 'SCAN_TEXT') {
    scanAndNotify('text', message.text, sender.tab).then(result => sendResponse(result));
    return true; // async
  }

  if (message.type === 'GET_BACKEND_STATUS') {
    checkBackendStatus().then(status => sendResponse(status));
    return true; // async
  }

  if (message.type === 'SCAN_QR_PAYLOAD') {
    scanQRPayload(message.payload, sender.tab).then(result => sendResponse(result));
    return true;
  }

  if (message.type === 'CAPTURE_VISIBLE_TAB') {
    const windowId = sender.tab ? sender.tab.windowId : null;
    const captureOptions = { format: 'png' };
    
    if (windowId !== null) {
      chrome.tabs.captureVisibleTab(windowId, captureOptions, src => {
        if (chrome.runtime.lastError || !src) {
          sendResponse({ success: false, error: chrome.runtime.lastError?.message || 'Unable to capture snapshot' });
        } else {
          sendResponse({ success: true, dataUrl: src });
        }
      });
    } else {
      chrome.windows.getLastFocused({ populate: false }, (win) => {
        const targetWinId = win ? win.id : chrome.windows.WINDOW_ID_CURRENT;
        chrome.tabs.captureVisibleTab(targetWinId, captureOptions, src => {
          if (chrome.runtime.lastError || !src) {
            sendResponse({ success: false, error: chrome.runtime.lastError?.message || 'Unable to capture snapshot' });
          } else {
            sendResponse({ success: true, dataUrl: src });
          }
        });
      });
    }
    return true; // async
  }

  if (message.type === 'CONTINUOUS_QR_DETECTED') {
    const payload = message.payload;
    console.log("🛡️ Continuous QR Code Detected in tab", sender.tab?.id, "Payload:", payload);
    
    // Stage 1 Notification: Instant notification that a QR has been detected
    const scanNotifId = `qr-scan-${Date.now()}`;
    chrome.notifications.create(scanNotifId, {
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title: '🔍 SafePay: QR Code Detected',
      message: `Analyzing safety of payload: ${payload.length > 50 ? payload.substring(0, 50) + '...' : payload}`,
      priority: 1
    });

    // Run backend analysis
    scanQRPayload(payload, sender.tab).then(data => {
      // Clear initial notification
      chrome.notifications.clear(scanNotifId, () => {});

      if (!data || !data.success) {
        // SafePay Backend failed or was offline
        chrome.notifications.create(`qr-error-${Date.now()}`, {
          type: 'basic',
          iconUrl: 'icons/icon128.png',
          title: '⚠️ SafePay: Scan Interrupted',
          message: `Could not verify QR code. ${data?.error || 'Backend service offline.'}`,
          priority: 1
        });
        return;
      }

      const analysis = data.analysis || {};
      const score = analysis.risk_score || 0;
      const level = analysis.risk_level || 'LOW';
      const upiId = data.qr_data?.upi_id || '';
      const merchant = data.qr_data?.merchant_name || '';

      const details = upiId ? `UPI ID: ${upiId}${merchant ? ` (${merchant})` : ''}` : `Content: ${payload.substring(0, 60)}`;

      if (score >= 45) {
        // Stage 2 Notification for Suspicious/High-risk
        const emoji = score >= 75 ? '🚨' : '⚠️';
        chrome.notifications.create(`qr-threat-${Date.now()}`, {
          type: 'basic',
          iconUrl: 'icons/icon128.png',
          title: `${emoji} SafePay: Threat Alert [${level}]`,
          message: `Suspicious QR payload detected (Risk: ${score}/100)!\n${details}`,
          priority: 2
        });
      } else {
        // Stage 2 Success Notification (Verified safe)
        chrome.notifications.create(`qr-safe-${Date.now()}`, {
          type: 'basic',
          iconUrl: 'icons/icon128.png',
          title: '🟢 SafePay: Verified Safe',
          message: `QR code verified safe (Risk: ${score}/100).\n${details}`,
          priority: 1
        });
      }

      // Also trigger a results broadcast to update feed/UI if open
      if (sender.tab?.id) {
        if (!tabThreatResults.has(sender.tab.id)) {
          tabThreatResults.set(sender.tab.id, { upiScans: [], urlScans: [] });
        }
        const tabData = tabThreatResults.get(sender.tab.id);
        
        // Form a resource object matching dashboard structure
        if (upiId) {
          const upiRes = {
            upi_id: upiId,
            merchant_name: merchant,
            amount: data.qr_data?.amount || 0.0,
            risk_score: score,
            risk_level: level,
            status: analysis.status || 'SAFE',
            analysis: analysis
          };
          if (!tabData.upiScans.some(x => x.upi_id === upiId)) {
            tabData.upiScans.push(upiRes);
          }
        } else {
          const urlRes = {
            message: payload,
            risk_score: score,
            risk_level: level,
            status: analysis.status || 'SAFE',
            analysis: analysis
          };
          if (!tabData.urlScans.some(x => x.message === payload)) {
            tabData.urlScans.push(urlRes);
          }
        }
        
        // Update badge counting and send results
        updateBadgeForTab(sender.tab.id);
        broadcastTabResults(sender.tab.id);
      }
    }).catch(err => {
      chrome.notifications.clear(scanNotifId, () => {});
      chrome.notifications.create(`qr-error-${Date.now()}`, {
        type: 'basic',
        iconUrl: 'icons/icon128.png',
        title: '⚠️ SafePay: Scan Interrupted',
        message: `An error occurred during verification: ${err.message}`,
        priority: 1
      });
    });

    sendResponse({ received: true });
    return false;
  }
});

// ============================================================================
// HANDLE THREATS FROM CONTENT SCRIPT
// ============================================================================
function handlePageThreats(threats, tab) {
  if (!tab?.id) return;

  const upiCount        = threats.upiIds?.length || 0;
  const urlCount        = threats.suspiciousUrls?.length || 0;
  const hasInvestment   = !!threats.investmentScams;
  const count           = upiCount + urlCount + (hasInvestment ? 1 : 0);

  if (count === 0) return;

  // Choose badge color based on severity
  let color = BADGE_COLORS.warning;
  if (count >= 3 || hasInvestment) color = BADGE_COLORS.danger;
  if (hasInvestment && upiCount === 0 && urlCount === 0) color = BADGE_COLORS.investment;

  chrome.action.setBadgeBackgroundColor({ color, tabId: tab.id });
  chrome.action.setBadgeText({ text: String(count), tabId: tab.id });

  // Show notification for high-severity pages
  const notifThreshold = 2;
  if (count >= notifThreshold || hasInvestment) {
    const parts = [];
    if (upiCount)       parts.push(`${upiCount} UPI ID${upiCount > 1 ? 's' : ''}`);
    if (urlCount)       parts.push(`${urlCount} suspicious URL${urlCount > 1 ? 's' : ''}`);
    if (hasInvestment)  parts.push('investment scam language');

    chrome.notifications.create(`threat-${tab.id}-${Date.now()}`, {
      type:     'basic',
      iconUrl:  'icons/icon128.png',
      title:    '⚠️ SafePay Alert',
      message:  `Detected: ${parts.join(', ')}`,
      priority: count >= 3 ? 2 : 1
    });
  }
}

// ============================================================================
// SCAN TEXT / URL AND NOTIFY
// ============================================================================
async function scanAndNotify(type, content, tab) {
  try {
    const token = await getStoredToken();
    if (!token) {
      chrome.notifications.create({
        type: 'basic', iconUrl: 'icons/icon128.png',
        title: 'SafePay', message: 'Please log in to scan.', priority: 1
      });
      return null;
    }

    const upiDetected = /\b[a-zA-Z0-9._%+-]{2,}@[a-zA-Z]{2,}\b/.test(content);
    const urlDetected = /https?:\/\/|www\.|\.(in|com|net|org)\b/.test(content);

    let endpoint = '/sms/scan';
    let body = { message: content };

    if (type === 'url' || urlDetected) {
      body = { message: content };
    } else if (upiDetected && !urlDetected) {
      endpoint = '/fraud/scan-qr';
      body = { upi_id: content.trim(), amount: 0, merchant_name: null };
    }

    const response = await fetch(`${BACKEND_URL}${endpoint}`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
      body:    JSON.stringify(body)
    });

    const data     = await response.json();
    const analysis = data.analysis || data;
    const riskScore = analysis?.risk_score || 0;
    const riskLevel = analysis?.risk_level || analysis?.status || 'LOW';

    let details = content.length > 80 ? content.substring(0, 80) + '...' : content;
    if (endpoint === '/fraud/scan-qr' && data.data?.upi_id) {
      details = data.data.upi_id;
    }

    const emoji = riskScore >= 75 ? '🔴' : riskScore >= 45 ? '🟡' : '🟢';
    chrome.notifications.create(`scan-${Date.now()}`, {
      type:     'basic',
      iconUrl:  'icons/icon128.png',
      title:    `${emoji} SafePay: ${riskLevel}`,
      message:  `Risk: ${riskScore}/100 — ${details}`,
      priority: riskScore >= 75 ? 2 : 1
    });

    return data;
  } catch (err) {
    chrome.notifications.create({
      type: 'basic', iconUrl: 'icons/icon128.png',
      title: 'SafePay Error', message: 'Scan failed — backend may be offline.', priority: 1
    });
    return null;
  }
}

// ============================================================================
// SCAN QR PAYLOAD (fast endpoint — no image upload)
// ============================================================================
async function scanQRPayload(payload, tab) {
  try {
    const token = await getStoredToken();
    if (!token) return { success: false, error: 'Not authenticated' };

    const response = await fetch(`${BACKEND_URL}/qr/analyze-payload`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
      body:    JSON.stringify({ payload })
    });
    const data = await response.json();

    // Update badge if high risk
    const score = data?.analysis?.risk_score || 0;
    if (tab?.id && score > 0) {
      const color = score >= 75 ? BADGE_COLORS.danger : score >= 45 ? BADGE_COLORS.warning : BADGE_COLORS.safe;
      chrome.action.setBadgeBackgroundColor({ color, tabId: tab.id });
      chrome.action.setBadgeText({ text: String(Math.round(score)), tabId: tab.id });
    }
    return data;
  } catch (err) {
    return { success: false, error: err.message };
  }
}

// ============================================================================
// HELPERS
// ============================================================================
function getStoredToken() {
  return new Promise(resolve => {
    chrome.storage.local.get(['accessToken'], data => resolve(data.accessToken || null));
  });
}

async function checkBackendStatus() {
  try {
    const controller = new AbortController();
    const timeoutId  = setTimeout(() => controller.abort(), 5000);
    const resp = await fetch(`${BACKEND_URL}/ping`, { signal: controller.signal });
    clearTimeout(timeoutId);
    return { online: resp.ok };
  } catch {
    return { online: false };
  }
}

// ============================================================================
// BATCH SCAN QUEUE IMPLEMENTATION
// ============================================================================
function enqueueThreatScan(tabId, threats) {
  if (!tabId) return;

  if (!upiScanQueue.has(tabId)) {
    upiScanQueue.set(tabId, new Set());
  }
  if (!urlScanQueue.has(tabId)) {
    urlScanQueue.set(tabId, new Set());
  }

  (threats.upiIds || []).forEach(upi => {
    if (!processedThreatsCache.has(`upi:${upi}`)) {
      upiScanQueue.get(tabId).add(upi);
    }
  });

  (threats.suspiciousUrls || []).forEach(url => {
    if (!processedThreatsCache.has(`url:${url}`)) {
      urlScanQueue.get(tabId).add(url);
    }
  });

  if (queueTimers.has(tabId)) {
    clearTimeout(queueTimers.get(tabId));
  }

  // Sliding 2.5s window
  const timerId = setTimeout(() => {
    flushAndScan(tabId);
  }, 2500);
  queueTimers.set(tabId, timerId);
}

async function flushAndScan(tabId) {
  queueTimers.delete(tabId);

  const upis = Array.from(upiScanQueue.get(tabId) || []);
  const urls = Array.from(urlScanQueue.get(tabId) || []);

  upiScanQueue.set(tabId, new Set());
  urlScanQueue.set(tabId, new Set());

  if (upis.length === 0 && urls.length === 0) return;

  const token = await getStoredToken();
  if (!token) return;

  if (!tabThreatResults.has(tabId)) {
    tabThreatResults.set(tabId, { upiScans: [], urlScans: [] });
  }
  const tabData = tabThreatResults.get(tabId);

  // Scan UPIs in bulk
  if (upis.length > 0) {
    try {
      const upiPayload = upis.map(upi => ({
        upi_id: upi,
        amount: 0,
        merchant_name: null
      }));

      const response = await fetch(`${BACKEND_URL}/fraud/bulk-scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify(upiPayload)
      });
      const data = await response.json();
      if (data && data.success) {
        data.results.forEach(res => {
          processedThreatsCache.add(`upi:${res.upi_id}`);
          if (!tabData.upiScans.some(x => x.upi_id === res.upi_id)) {
            tabData.upiScans.push(res);
          }
        });
      }
    } catch (e) {
      console.error("UPI bulk scan failed", e);
    }
  }

  // Scan URLs in bulk
  if (urls.length > 0) {
    try {
      const response = await fetch(`${BACKEND_URL}/sms/bulk-scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ messages: urls })
      });
      const data = await response.json();
      if (data && data.success) {
        data.results.forEach(res => {
          processedThreatsCache.add(`url:${res.message}`);
          if (!tabData.urlScans.some(x => x.message === res.message)) {
            tabData.urlScans.push(res);
          }
        });
      }
    } catch (e) {
      console.error("URL bulk scan failed", e);
    }
  }

  updateBadgeForTab(tabId);
  broadcastTabResults(tabId);
}

function updateBadgeForTab(tabId) {
  const tabData = tabThreatResults.get(tabId);
  if (!tabData) return;

  const totalUPIThreats = tabData.upiScans.filter(res => (res.analysis?.risk_score || 0) >= 45).length;
  const totalURLThreats = tabData.urlScans.filter(res => (res.risk_score || 0) >= 45).length;
  const count = totalUPIThreats + totalURLThreats;

  if (count === 0) {
    chrome.action.setBadgeText({ text: '', tabId });
    return;
  }

  const highestRisk = Math.max(
    ...tabData.upiScans.map(res => res.analysis?.risk_score || 0),
    ...tabData.urlScans.map(res => res.risk_score || 0),
    0
  );

  let color = BADGE_COLORS.warning;
  if (highestRisk >= 75) color = BADGE_COLORS.danger;

  chrome.action.setBadgeBackgroundColor({ color, tabId });
  chrome.action.setBadgeText({ text: String(count), tabId });

  if (highestRisk >= 75) {
    chrome.notifications.create(`threat-${tabId}-${Date.now()}`, {
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title: '🚨 High-Risk Threat Detected!',
      message: `SafePay detected ${count} high-risk elements on this page.`,
      priority: 2
    });
  }
}

function broadcastTabResults(tabId) {
  const tabData = tabThreatResults.get(tabId);
  if (!tabData) return;

  try {
    chrome.runtime.sendMessage({
      type: 'TAB_SCANS_UPDATED',
      tabId,
      data: tabData
    }, () => {
      if (chrome.runtime.lastError) { /* silent ignore when panel is closed */ }
    });
  } catch (e) {}
}
