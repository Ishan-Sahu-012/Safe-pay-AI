// SafePay Content Script — Auto Page Scanner
(() => {
  // Don't run on extension pages or chrome:// URLs
  if (window.location.protocol === 'chrome-extension:' || window.location.protocol === 'chrome:') return;

  // Trusted domains — skip scanning to save CPU
  const TRUSTED_DOMAINS = new Set([
    'google.com', 'youtube.com', 'amazon.in', 'amazon.com', 'flipkart.com',
    'github.com', 'stackoverflow.com', 'wikipedia.org', 'microsoft.com',
    'apple.com', 'linkedin.com', 'twitter.com', 'facebook.com', 'instagram.com'
  ]);
  const hostname = window.location.hostname.replace(/^www\./, '');
  if (TRUSTED_DOMAINS.has(hostname)) return;

  const UPI_REGEX = /\b[a-zA-Z0-9._%+-]{2,}@[a-zA-Z]{2,}\b/g;
  const UPI_SCHEME_REGEX = /\bupi:\/\/pay\?[^\s]+/gi;
  const SUSPICIOUS_URL_PATTERNS = /(?:bit\.ly|tinyurl|goo\.gl|t\.co|is\.gd|buff\.ly|ow\.ly|clck\.ru|shorturl|rebrand\.ly|cutt\.ly|paytm\.me|rzp\.io|gpay\.app|pay\.tm|upi\.com)/gi;
  const GENERIC_SUSPICIOUS_URL = /\b(?:https?:\/\/|www\.)[\w\-]+(?:\.[a-z]{2,})+\/(?:verify|login|secure|bank|payment|offer|claim|reward|free|bonus)\b/gi;
  const INVESTMENT_SCAM_KEYWORDS = /\b(guaranteed returns|double your money|crypto investment|passive income|trading platform|forex signals|investment scheme)\b/gi;
  const PHONE_REGEX = /(?:\+91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}/g;

  let lastScanTime = 0;
  const SCAN_COOLDOWN = 5000;
  const MAX_SCAN_SCHEDULE_DELAY = 300;
  let hasScanned = false;
  let scheduledScan = false;
  let lastBodySnapshot = '';

  // WeakSet tracks DOM nodes already highlighted — prevents re-processing
  const scannedNodes = new WeakSet();

  // Fingerprint cache — avoids duplicate backend calls for the same threats (5 min TTL)
  const threatFingerprintCache = new Map(); // fingerprint → timestamp
  const FINGERPRINT_TTL = 5 * 60 * 1000;

  function makeThreatFingerprint(threats) {
    return (threats.upiIds || []).slice().sort().join(',') + '::' + (threats.suspiciousUrls || []).slice().sort().join(',');
  }

  function isAlreadyReported(threats) {
    const fp = makeThreatFingerprint(threats);
    const ts = threatFingerprintCache.get(fp);
    if (ts && Date.now() - ts < FINGERPRINT_TTL) return true;
    threatFingerprintCache.set(fp, Date.now());
    if (threatFingerprintCache.size > 100) {
      // Prune oldest entries
      const entries = [...threatFingerprintCache.entries()].sort((a, b) => a[1] - b[1]);
      entries.slice(0, 30).forEach(([k]) => threatFingerprintCache.delete(k));
    }
    return false;
  }

  function getIdleCallback(callback) {
    if ('requestIdleCallback' in window) {
      return requestIdleCallback(callback, { timeout: 1000 });
    }
    return setTimeout(callback, MAX_SCAN_SCHEDULE_DELAY);
  }

  function makeSnapshot(text) {
    return `${text.length}|${text.slice(0, 60)}|${text.slice(-60)}`;
  }

  function scheduleScan() {
    if (scheduledScan) return;
    scheduledScan = true;
    getIdleCallback(() => {
      scheduledScan = false;
      scanPage();
    });
  }

  function scanPage() {
    const now = Date.now();
    if (now - lastScanTime < SCAN_COOLDOWN) return;
    lastScanTime = now;

    let bodyText = document.body?.innerText || '';
    if (!bodyText || bodyText.length < 20) return;
    if (bodyText.length > 200000) bodyText = bodyText.slice(0, 200000);

    const snapshot = makeSnapshot(bodyText);
    if (snapshot === lastBodySnapshot) return;
    lastBodySnapshot = snapshot;

    const upiIds = [...new Set((bodyText.match(UPI_REGEX) || []))].slice(0, 10);
    const upiSchemes = [...new Set((bodyText.match(UPI_SCHEME_REGEX) || []))].slice(0, 10);
    const phoneNumbers = [...new Set((bodyText.match(PHONE_REGEX) || []))].slice(0, 10);
    const suspiciousUrls = new Set();

    document.querySelectorAll('a[href]').forEach(link => {
      const href = link.href || '';
      if (href.length > 500) return;
      if (SUSPICIOUS_URL_PATTERNS.test(href) || GENERIC_SUSPICIOUS_URL.test(href)) suspiciousUrls.add(href);
      SUSPICIOUS_URL_PATTERNS.lastIndex = 0;
      GENERIC_SUSPICIOUS_URL.lastIndex = 0;
    });

    const investmentScams = INVESTMENT_SCAM_KEYWORDS.test(bodyText);
    const uniqueUrls = Array.from(suspiciousUrls).slice(0, 10);
    const threats = {
      upiIds,
      upiSchemes,
      suspiciousUrls: uniqueUrls,
      phoneNumbers,
      investmentScams,
      pageText: bodyText.slice(0, 20000)
    };

    const totalThreats = upiIds.length + upiSchemes.length + uniqueUrls.length + (investmentScams ? 1 : 0);
    if (totalThreats === 0) return;

    // Skip if we already reported the same threat set recently
    if (isAlreadyReported(threats)) return;

    try {
      chrome.runtime.sendMessage({ type: 'PAGE_THREATS_FOUND', data: threats }, () => {});
    } catch (error) {}

    if (!hasScanned) {
      highlightUPIs(upiIds);
      hasScanned = true;
    }
  }

  function highlightUPIs(upiIds) {
    if (!upiIds.length) return;
    const style = document.createElement('style');
    style.textContent = `
      .safepay-highlight { background: linear-gradient(135deg, rgba(255, 106, 0, 0.15), rgba(213, 0, 0, 0.15)) !important; border: 1px solid rgba(255, 106, 0, 0.4) !important; border-radius: 3px !important; padding: 1px 4px !important; cursor: help !important; position: relative !important; }
      .safepay-highlight::after { content: '🛡️ SafePay: UPI Detected' !important; position: absolute !important; bottom: 100% !important; left: 50% !important; transform: translateX(-50%) !important; background: #1a1a2e !important; color: #FFD600 !important; padding: 4px 8px !important; border-radius: 4px !important; font-size: 11px !important; white-space: nowrap !important; opacity: 0 !important; pointer-events: none !important; transition: opacity 0.2s !important; z-index: 999999 !important; }
      .safepay-highlight:hover::after { opacity: 1 !important; }
    `;
    document.head.appendChild(style);

    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null);
    const textNodes = [];
    while (walker.nextNode()) textNodes.push(walker.currentNode);

    for (const node of textNodes) {
      if (scannedNodes.has(node)) continue; // already highlighted
      const text = node.textContent;
      let hasMatch = false;
      for (const upi of upiIds) { if (text.includes(upi)) { hasMatch = true; break; } }
      if (!hasMatch) continue;

      const parent = node.parentNode;
      if (!parent || parent.closest('.safepay-highlight')) continue;
      if (['SCRIPT', 'STYLE', 'TEXTAREA', 'INPUT', 'CODE', 'PRE'].includes(parent.tagName)) continue;

      let html = text;
      for (const upi of upiIds) {
        const escaped = upi.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        html = html.replace(new RegExp(escaped, 'g'), `<span class="safepay-highlight">${upi}</span>`);
      }

      if (html !== text) {
        const span = document.createElement('span');
        span.innerHTML = html;
        parent.replaceChild(span, node);
        scannedNodes.add(node); // mark processed
      }
    }
  }

  // IntersectionObserver for tracking visible images with suspected QR features
  const imageObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const img = entry.target;
        if (scannedNodes.has(img)) return; // already scanned
        
        const src = img.src || '';
        const alt = img.alt || '';
        
        // Suspected QR features: filename or alt tags containing qr, pay, upi
        const hasQRFeatures = /qr|pay|upi/i.test(src) || /qr|pay|upi/i.test(alt);
        if (hasQRFeatures) {
          scannedNodes.add(img); // mark as scanned/processed
          
          try {
            chrome.runtime.sendMessage({
              type: 'SUSPECTED_QR_FOUND',
              data: { src, alt, id: img.id || '' }
            });
          } catch (error) {}
        }
      }
    });
  }, { threshold: 0.1 });

  function initializeImageObserver() {
    document.querySelectorAll('img').forEach(img => {
      try {
        imageObserver.observe(img);
      } catch (e) {}
    });
  }

  function scanNewNodes(nodes) {
    const upiIds = new Set();
    const upiSchemes = new Set();
    const phoneNumbers = new Set();
    const suspiciousUrls = new Set();
    let investmentScams = false;

    nodes.forEach(node => {
      if (node.nodeType === Node.ELEMENT_NODE) {
        if (['SCRIPT', 'STYLE', 'TEXTAREA', 'INPUT', 'CODE', 'PRE'].includes(node.tagName)) return;

        const text = node.innerText || node.textContent || '';
        if (text) {
          const upis = text.match(UPI_REGEX);
          if (upis) upis.forEach(u => upiIds.add(u));

          const schemes = text.match(UPI_SCHEME_REGEX);
          if (schemes) schemes.forEach(s => upiSchemes.add(s));

          const phones = text.match(PHONE_REGEX);
          if (phones) phones.forEach(p => phoneNumbers.add(p));

          if (INVESTMENT_SCAM_KEYWORDS.test(text)) {
            investmentScams = true;
          }
          INVESTMENT_SCAM_KEYWORDS.lastIndex = 0;
        }

        const links = node.tagName === 'A' ? [node] : node.querySelectorAll('a[href]');
        links.forEach(link => {
          const href = link.href || '';
          if (href.length > 500) return;
          if (SUSPICIOUS_URL_PATTERNS.test(href) || GENERIC_SUSPICIOUS_URL.test(href)) {
            suspiciousUrls.add(href);
          }
          SUSPICIOUS_URL_PATTERNS.lastIndex = 0;
          GENERIC_SUSPICIOUS_URL.lastIndex = 0;
        });

        const images = node.tagName === 'IMG' ? [node] : node.querySelectorAll('img');
        images.forEach(img => {
          try {
            imageObserver.observe(img);
          } catch (e) {}
        });

      } else if (node.nodeType === Node.TEXT_NODE) {
        const text = node.textContent || '';
        if (text) {
          const upis = text.match(UPI_REGEX);
          if (upis) upis.forEach(u => upiIds.add(u));

          const schemes = text.match(UPI_SCHEME_REGEX);
          if (schemes) schemes.forEach(s => upiSchemes.add(s));

          const phones = text.match(PHONE_REGEX);
          if (phones) phones.forEach(p => phoneNumbers.add(p));

          if (INVESTMENT_SCAM_KEYWORDS.test(text)) {
            investmentScams = true;
          }
          INVESTMENT_SCAM_KEYWORDS.lastIndex = 0;
        }
      }
    });

    const upiList = Array.from(upiIds).slice(0, 10);
    const urlList = Array.from(suspiciousUrls).slice(0, 10);
    if (upiList.length > 0 || urlList.length > 0 || phoneNumbers.size > 0 || investmentScams) {
      const threats = {
        upiIds: upiList,
        upiSchemes: Array.from(upiSchemes).slice(0, 10),
        suspiciousUrls: urlList,
        phoneNumbers: Array.from(phoneNumbers).slice(0, 10),
        investmentScams,
        pageText: upiList.join(' ') + ' ' + urlList.join(' ')
      };

      if (!isAlreadyReported(threats)) {
        try {
          chrome.runtime.sendMessage({ type: 'PAGE_THREATS_FOUND', data: threats }, () => {});
        } catch (error) {}
      }

      highlightUPIs(upiList);
    }
  }

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'SCAN_PAGE_LINKS') {
      try {
        const threats = scanPageLinks();
        sendResponse({ success: true, threats });
      } catch (error) { sendResponse({ success: false, error: error.message }); }
      return true;
    }
    if (message.type === 'SCAN_NOW') {
      lastScanTime = 0;
      lastBodySnapshot = '';
      scheduleScan();
      initializeImageObserver();
      sendResponse({ success: true });
      return true;
    }
  });

  window.addEventListener('focus', () => {
    scanPage();
    initializeImageObserver();
  });

  if (document.readyState === 'complete') {
    setTimeout(() => {
      scanPage();
      initializeImageObserver();
    }, 1000);
  } else {
    window.addEventListener('load', () => {
      setTimeout(() => {
        scanPage();
        initializeImageObserver();
      }, 1000);
    });
  }

  const observer = new MutationObserver((mutations) => {
    const addedNodes = [];
    mutations.forEach(mutation => {
      mutation.addedNodes.forEach(node => {
        addedNodes.push(node);
      });
    });
    if (addedNodes.length > 0) {
      scanNewNodes(addedNodes);
    }
  });

  observer.observe(document.body || document.documentElement, {
    childList: true,
    subtree: true
  });

  function scanPageLinks() {
    const bodyText = document.body?.innerText || '';
    const upiIds = [...new Set((bodyText.match(UPI_REGEX) || []))].slice(0, 10);
    const upiSchemes = [...new Set((bodyText.match(UPI_SCHEME_REGEX) || []))].slice(0, 10);
    const investmentScams = INVESTMENT_SCAM_KEYWORDS.test(bodyText);
    const suspiciousUrls = new Set();
    document.querySelectorAll('a[href]').forEach(link => {
      const href = link.href || '';
      if (SUSPICIOUS_URL_PATTERNS.test(href) || GENERIC_SUSPICIOUS_URL.test(href)) { suspiciousUrls.add(href); }
      SUSPICIOUS_URL_PATTERNS.lastIndex = 0;
      GENERIC_SUSPICIOUS_URL.lastIndex = 0;
    });
    return {
      upiIds: upiIds,
      upiSchemes: upiSchemes,
      investmentScams: investmentScams,
      suspiciousUrls: Array.from(suspiciousUrls).slice(0, 10)
    };
  }

  // ============================================================================
  // REAL-TIME CONTINUOUS QR MONITORING SYSTEM
  // ============================================================================
  let continuousScanEnabled = true;
  let continuousScanInterval = 2000; // default 2s
  let continuousScanTimer = null;
  let isContinuousScanning = false;

  // Reusable Image and Canvas elements to optimize memory (prevent GC churn)
  const sharedCanvas = document.createElement('canvas');
  const sharedImage = new Image();
  
  // Duplicate filter cache
  const decodedQRCache = new Map(); // payload -> timestamp
  const QR_CACHE_TTL = 5 * 60 * 1000; // 5 minutes TTL

  function initContinuousQRScanner() {
    chrome.storage.local.get(['continuousScanEnabled', 'continuousScanInterval'], (items) => {
      continuousScanEnabled = items.continuousScanEnabled ?? true;
      continuousScanInterval = (items.continuousScanInterval ?? 2.0) * 1000;
      console.log(`🛡️ SafePay Continuous Scanner Init | Enabled: ${continuousScanEnabled} | Interval: ${continuousScanInterval}ms`);
      updateContinuousScanTimer();
    });

    chrome.storage.onChanged.addListener((changes, areaName) => {
      if (areaName === 'local') {
        let changed = false;
        if (changes.continuousScanEnabled !== undefined) {
          continuousScanEnabled = changes.continuousScanEnabled.newValue;
          changed = true;
        }
        if (changes.continuousScanInterval !== undefined) {
          continuousScanInterval = changes.continuousScanInterval.newValue * 1000;
          changed = true;
        }
        if (changed) {
          console.log(`🛡️ SafePay Continuous Scanner Config Updated | Enabled: ${continuousScanEnabled} | Interval: ${continuousScanInterval}ms`);
          updateContinuousScanTimer();
        }
      }
    });
  }

  function updateContinuousScanTimer() {
    if (continuousScanTimer) {
      clearInterval(continuousScanTimer);
      continuousScanTimer = null;
    }
    if (continuousScanEnabled) {
      continuousScanTimer = setInterval(performContinuousQRScan, continuousScanInterval);
    }
  }

  function performContinuousQRScan() {
    // 1. Visibility Check: Pause if tab is inactive or document is hidden
    if (document.hidden || document.visibilityState !== 'visible') {
      return;
    }

    // 2. Throttling/Concurrency lock: Skip if a previous scan is still processing
    if (isContinuousScanning) {
      return;
    }

    isContinuousScanning = true;

    // 3. Request screenshot from background service worker
    chrome.runtime.sendMessage({ type: 'CAPTURE_VISIBLE_TAB' }, (response) => {
      if (chrome.runtime.lastError) {
        // Handle runtime error (e.g. extension context invalidated or tab not captureable)
        isContinuousScanning = false;
        return;
      }

      if (!response || !response.success || !response.dataUrl) {
        // Capture failed (e.g. window is minimized)
        isContinuousScanning = false;
        return;
      }

      // 4. Decode the screenshot
      sharedImage.onload = () => {
        try {
          const width = sharedImage.width;
          const height = sharedImage.height;
          
          if (width === 0 || height === 0) {
            isContinuousScanning = false;
            return;
          }

          sharedCanvas.width = width;
          sharedCanvas.height = height;
          const ctx = sharedCanvas.getContext('2d', { willReadFrequently: true });
          ctx.drawImage(sharedImage, 0, 0, width, height);

          const imageData = ctx.getImageData(0, 0, width, height);
          
          let qrResult = null;
          if (typeof jsQR !== 'undefined') {
            qrResult = jsQR(imageData.data, imageData.width, imageData.height, { inversionAttempts: 'dontInvert' });
          }

          if (qrResult && qrResult.data) {
            handleDetectedQR(qrResult.data);
          }
        } catch (err) {
          console.error("🛡️ SafePay QR scan/decode error:", err);
        } finally {
          isContinuousScanning = false;
        }
      };

      sharedImage.onerror = () => {
        isContinuousScanning = false;
      };

      sharedImage.src = response.dataUrl;
    });
  }

  function handleDetectedQR(payload) {
    const trimmedPayload = payload.trim();
    if (!trimmedPayload) return;

    const now = Date.now();
    
    // Clean expired entries from cache occasionally
    if (decodedQRCache.size > 50) {
      for (const [key, timestamp] of decodedQRCache.entries()) {
        if (now - timestamp > QR_CACHE_TTL) {
          decodedQRCache.delete(key);
        }
      }
    }

    // 5. Duplicate Filter Check
    const lastScanTime = decodedQRCache.get(trimmedPayload);
    if (lastScanTime && (now - lastScanTime < QR_CACHE_TTL)) {
      // Duplicate, ignore it
      return;
    }

    // New QR code detected! Cache it and report
    decodedQRCache.set(trimmedPayload, now);
    console.log(`🛡️ SafePay Continuous Scanner | New QR detected: ${trimmedPayload.substring(0, 100)}`);
    
    try {
      chrome.runtime.sendMessage({
        type: 'CONTINUOUS_QR_DETECTED',
        payload: trimmedPayload
      });
    } catch (e) {
      console.error("🛡️ SafePay failed to send QR payload message to background worker:", e);
    }
  }

  // Initialize the scanner on load
  initContinuousQRScanner();
})();

