/**
 * ScopeLens Platform - Service Worker (Background Script)
 * Manages CDP debugger capture, DoH queries, tab lifecycle, side panel, and suspension rehydration.
 */

const captures = new Map();
const REDACTED = "[REDACTED]";

function safeUrl(raw) {
  try {
    const url = new URL(raw);
    for (const key of [...url.searchParams.keys()]) {
      if (/token|auth|key|secret|session|password|code|signature|jwt/i.test(key)) {
        url.searchParams.set(key, REDACTED);
      }
    }
    url.username = "";
    url.password = "";
    return url.toString();
  } catch {
    return "[invalid URL]";
  }
}

function sameOrigin(rawUrl, origin) {
  try { return new URL(rawUrl).origin === origin; }
  catch { return false; }
}

function broadcast(tabId, state) {
  chrome.runtime.sendMessage({ type: "CAPTURE_UPDATE", tabId, state }).catch(() => {});
}

// Rehydrate memory map on service worker wake-up
async function rehydrateCaptures() {
  try {
    if (chrome.storage?.session) {
      const all = await chrome.storage.session.get(null);
      for (const [key, val] of Object.entries(all)) {
        if (key.startsWith("capture_") && val?.origin) {
          const tabId = Number(key.replace("capture_", ""));
          if (Number.isInteger(tabId)) {
            captures.set(tabId, val);
          }
        }
      }
    }
  } catch {}
}

chrome.runtime.onStartup.addListener(() => {
  rehydrateCaptures();
});

chrome.runtime.onInstalled.addListener(() => {
  rehydrateCaptures();
  // Enable side panel open behavior if available
  if (chrome.sidePanel?.setPanelBehavior) {
    chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: false }).catch(() => {});
  }
});

// Clean up captured resources when a tab is closed
chrome.tabs.onRemoved.addListener(async tabId => {
  if (captures.has(tabId)) {
    try {
      await chrome.debugger.detach({ tabId });
    } catch {}
    captures.delete(tabId);
    if (chrome.storage?.session) {
      await chrome.storage.session.remove(`capture_${tabId}`).catch(() => {});
    }
  }
});

// Chrome Debugger Protocol event listener
chrome.debugger.onEvent.addListener(async (source, method, params) => {
  if (method !== "Network.responseReceived") return;
  const tabId = source.tabId;
  let state = captures.get(tabId);
  if (!state && chrome.storage?.session) {
    const stored = await chrome.storage.session.get(`capture_${tabId}`);
    state = stored[`capture_${tabId}`];
    if (state) captures.set(tabId, state);
  }
  if (!state || !params?.response) return;

  const response = params.response;
  if (!sameOrigin(response.url, state.origin)) return;

  const remoteIp = response.remoteIPAddress || "Not exposed by browser";
  const remotePort = Number.isInteger(response.remotePort) ? response.remotePort : null;
  
  // Format security details if provided
  let security = null;
  if (response.securityDetails) {
    const sd = response.securityDetails;
    security = {
      protocol: sd.protocol || "",
      keyExchange: sd.keyExchange || "",
      cipher: sd.cipher || "",
      issuer: sd.issuer || "",
      subjectName: sd.subjectName || "",
      sanList: sd.sanList || [],
      validFrom: sd.validFrom ? sd.validFrom * 1000 : null,
      validTo: sd.validTo ? sd.validTo * 1000 : null
    };
    if (!state.securityDetails) {
      state.securityDetails = security;
    }
  }

  // Keep track of document-level response headers for security header analysis
  if (!state.documentHeaders && (params.type === "Document" || response.url === state.origin || response.url === state.origin + "/")) {
    state.documentHeaders = response.headers || {};
  }

  const record = {
    url: safeUrl(response.url),
    status: response.status,
    statusText: response.statusText || "",
    mimeType: response.mimeType || "",
    remoteIp,
    remotePort,
    protocol: response.protocol || "",
    fromDiskCache: Boolean(response.fromDiskCache),
    fromServiceWorker: Boolean(response.fromServiceWorker),
    security,
    headers: response.headers ? Object.entries(response.headers).slice(0, 40) : [],
    seenAt: new Date().toISOString()
  };

  const key = `${record.url}|${record.status}|${record.remoteIp}|${record.remotePort || ""}`;
  if (!state.items.some(item => item.key === key)) {
    state.items.unshift({ ...record, key });
    if (state.items.length > 300) state.items.length = 300;
    if (chrome.storage?.session) {
      chrome.storage.session.set({ [`capture_${tabId}`]: state }).catch(() => {});
    }
    broadcast(tabId, state);
  }
});

chrome.debugger.onDetach.addListener(source => {
  const state = captures.get(source.tabId);
  if (state) {
    state.running = false;
    captures.set(source.tabId, state);
    if (chrome.storage?.session) {
      chrome.storage.session.set({ [`capture_${source.tabId}`]: state }).catch(() => {});
    }
    broadcast(source.tabId, state);
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // DNS-over-HTTPS resolution via Cloudflare DoH (explicit and isolated)
  if (message?.type === "DNS_LOOKUP") {
    (async () => {
      const hostname = String(message.hostname || "").trim().replace(/\.$/, "");
      if (!hostname || hostname.length > 253 || /[^a-zA-Z0-9.-]/.test(hostname)) {
        throw new Error("Invalid hostname");
      }
      const types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA", "SOA"];
      let dnssecValidated = false;

      const results = await Promise.all(types.map(async type => {
        try {
          const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=${type}`;
          const response = await fetch(url, { headers: { accept: "application/dns-json" }, cache: "no-store" });
          if (!response.ok) return { type, status: response.status, answers: [], error: `HTTP ${response.status}` };
          const data = await response.json();
          if (data.AD) dnssecValidated = true;
          return {
            type,
            status: data.Status,
            answers: (data.Answer || []).map(answer => ({
              name: answer.name,
              type: answer.type,
              ttl: answer.TTL,
              data: answer.data
            }))
          };
        } catch (err) {
          return { type, status: -1, answers: [], error: err.message };
        }
      }));

      sendResponse({ ok: true, hostname, dnssec: dnssecValidated, results });
    })().catch(error => sendResponse({ ok: false, error: error.message }));
    return true;
  }

  // Side Panel API trigger
  if (message?.type === "OPEN_SIDEPANEL") {
    (async () => {
      if (chrome.sidePanel?.open) {
        let tabId = Number(message.tabId);
        if (!Number.isInteger(tabId) || tabId <= 0) {
          const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
          tabId = activeTab?.id;
        }
        if (tabId) {
          await chrome.sidePanel.open({ tabId });
          sendResponse({ ok: true });
        } else {
          throw new Error("No active tab to open side panel for.");
        }
      } else {
        throw new Error("Side Panel API is not supported in this Chromium version.");
      }
    })().catch(error => sendResponse({ ok: false, error: error.message }));
    return true;
  }

  // Start deep connection capture (CDP debugger)
  if (message?.type === "START_CAPTURE") {
    (async () => {
      const tabId = Number(message.tabId);
      const origin = String(message.origin || "");
      if (!Number.isInteger(tabId) || !/^https?:\/\//.test(origin)) throw new Error("A normal website tab is required.");
      const state = { origin, running: true, items: [], securityDetails: null, documentHeaders: null, startedAt: new Date().toISOString() };
      
      await chrome.debugger.attach({ tabId }, "1.3");
      try {
        await chrome.debugger.sendCommand({ tabId }, "Network.enable", {
          maxTotalBufferSize: 0,
          maxResourceBufferSize: 0
        });
      } catch (error) {
        await chrome.debugger.detach({ tabId }).catch(() => {});
        throw error;
      }
      captures.set(tabId, state);
      if (chrome.storage?.session) {
        await chrome.storage.session.set({ [`capture_${tabId}`]: state });
      }
      sendResponse({ ok: true, state });
    })().catch(error => sendResponse({ ok: false, error: error.message }));
    return true;
  }

  // Stop deep connection capture
  if (message?.type === "STOP_CAPTURE") {
    (async () => {
      const tabId = Number(message.tabId);
      try { await chrome.debugger.detach({ tabId }); } catch {}
      let state = captures.get(tabId);
      if (!state && chrome.storage?.session) {
        const stored = await chrome.storage.session.get(`capture_${tabId}`);
        state = stored[`capture_${tabId}`];
      }
      if (!state) state = { origin: "", items: [] };
      state.running = false;
      captures.set(tabId, state);
      if (chrome.storage?.session) {
        await chrome.storage.session.set({ [`capture_${tabId}`]: state });
      }
      sendResponse({ ok: true, state });
    })().catch(error => sendResponse({ ok: false, error: error.message }));
    return true;
  }

  // Retrieve active capture state
  if (message?.type === "GET_CAPTURE") {
    (async () => {
      const tabId = Number(message.tabId);
      let state = captures.get(tabId);
      if (!state && chrome.storage?.session) {
        const stored = await chrome.storage.session.get(`capture_${tabId}`);
        state = stored[`capture_${tabId}`] || null;
        if (state) captures.set(tabId, state);
      }
      sendResponse({ ok: true, state: state || null });
    })().catch(error => sendResponse({ ok: false, error: error.message }));
    return true;
  }
});
