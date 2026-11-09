/**
 * ScopeLens Platform - Side Panel Controller
 * Persistent real-time inspection, security auditing, and target telemetry.
 */

import { auditSecurityHeaders, auditDomSecurity } from './src/modules/security/security-auditor.js';
import { fingerprintTech } from './src/modules/tech/tech-fingerprint.js';
import { detectTokens } from './src/modules/tokens/token-detector.js';
import { sanitizeUrl } from './src/core/redactor.js';
import { FindingsEngine } from './src/modules/findings/findings-engine.js';
import { TlsAuditor } from './src/modules/security/tls-auditor.js';

let activeTab = null;
let activeOrigin = null;
let activeScan = null;
let captureState = null;

const $ = id => document.getElementById(id);

function setElementText(id, text) {
  const el = $(id);
  if (el) el.textContent = text;
}

// Injected collector script running inside the target tab's context
function collectTabSnapshot() {
  const origin = location.origin;
  const REDACTED = "[REDACTED]";

  function cleanUrl(raw) {
    try {
      const u = new URL(raw);
      for (const k of [...u.searchParams.keys()]) {
        if (/token|auth|key|secret|password|session|code|jwt/i.test(k)) {
          u.searchParams.set(k, REDACTED);
        }
      }
      u.username = "";
      u.password = "";
      return u.toString();
    } catch {
      return String(raw);
    }
  }

  function readStorage(storage) {
    const list = [];
    if (!storage) return list;
    try {
      for (let i = 0; i < storage.length; i++) {
        const key = storage.key(i);
        if (!key) continue;
        const val = storage.getItem(key) || "";
        list.push({
          key,
          length: val.length,
          preview: val.length > 80 ? val.substring(0, 80) + "..." : val,
          isJwt: /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(val.trim())
        });
      }
    } catch {}
    return list;
  }

  const cookieParts = document.cookie
    ? document.cookie.split(";").map(c => c.trim().split("=")[0]).filter(Boolean)
    : [];

  const headers = {};
  try {
    const xhr = new XMLHttpRequest();
    xhr.open("HEAD", location.href, false);
    xhr.send();
    xhr.getAllResponseHeaders().split("\r\n").forEach(line => {
      const parts = line.split(":");
      if (parts.length > 1) {
        headers[parts[0].trim().toLowerCase()] = parts.slice(1).join(":").trim();
      }
    });
  } catch {}

  const isHttps = location.protocol === "https:";
  const reverseTabnabbingLinks = [];
  document.querySelectorAll('a[target="_blank"]').forEach(a => {
    const rel = (a.getAttribute("rel") || "").toLowerCase();
    const href = a.getAttribute("href") || "";
    if (!rel.includes("noopener") && !rel.includes("noreferrer") && /^https?:\/\//i.test(href)) {
      reverseTabnabbingLinks.push(href);
    }
  });

  const externalScriptsWithoutSri = [];
  const mixedContentResources = [];
  document.querySelectorAll("script[src]").forEach(s => {
    const src = s.getAttribute("src") || "";
    try {
      const u = new URL(src, location.href);
      if (u.origin !== origin && !s.hasAttribute("integrity")) {
        externalScriptsWithoutSri.push(u.href);
      }
      if (isHttps && u.protocol === "http:") {
        mixedContentResources.push(u.href);
      }
    } catch {}
  });

  const insecureForms = [];
  const formsMissingCsrf = [];
  const sensitiveHiddenInputs = [];
  const csrfRegex = /csrf|xsrf|_token|authenticity_token|RequestVerificationToken/i;
  const secretRegex = /token|auth|key|secret|password|credential|private|signature/i;

  document.querySelectorAll("form").forEach(f => {
    const action = f.getAttribute("action") || "";
    const method = (f.getAttribute("method") || "GET").toUpperCase();
    try {
      const u = new URL(action, location.href);
      if (isHttps && u.protocol === "http:") insecureForms.push(u.href);
    } catch {}

    if (method === "POST") {
      const inputs = Array.from(f.querySelectorAll("input"));
      const hasCsrf = inputs.some(i => csrfRegex.test(i.name) || csrfRegex.test(i.id));
      if (!hasCsrf) formsMissingCsrf.push(action || location.pathname);
    }

    f.querySelectorAll('input[type="hidden"]').forEach(h => {
      const name = h.name || h.id || "";
      if (secretRegex.test(name) && !csrfRegex.test(name)) {
        sensitiveHiddenInputs.push(name);
      }
    });
  });

  const javascriptPseudoLinks = [];
  document.querySelectorAll('a[href^="javascript:"]').forEach(a => {
    javascriptPseudoLinks.push(a.getAttribute("href") || "");
  });

  let inlineEventHandlersCount = 0;
  ["onclick", "onload", "onerror", "onmouseover", "onchange", "onsubmit"].forEach(evt => {
    inlineEventHandlersCount += document.querySelectorAll(`[${evt}]`).length;
  });

  const domSignals = {
    forms: Array.from(document.forms).map(f => ({
      action: cleanUrl(f.action),
      method: (f.method || "GET").toUpperCase(),
      hasPassword: Boolean(f.querySelector('input[type="password"]'))
    })),
    scripts: Array.from(document.scripts).map(s => ({
      src: cleanUrl(s.src),
      hasSri: Boolean(s.integrity)
    })),
    links: Array.from(document.querySelectorAll('a[target="_blank"]')).map(a => ({
      href: cleanUrl(a.href),
      rel: a.rel || ""
    })),
    metaTags: Array.from(document.querySelectorAll("meta")).map(m => ({
      name: m.getAttribute("name") || m.getAttribute("property") || "",
      content: m.getAttribute("content") || "",
      httpEquiv: m.getAttribute("http-equiv") || ""
    })),
    domSecurity: {
      reverseTabnabbingLinks,
      externalScriptsWithoutSri,
      mixedContentResources,
      insecureForms,
      javascriptPseudoLinks,
      inlineEventHandlersCount,
      formsMissingCsrf,
      sensitiveHiddenInputs
    }
  };

  return {
    origin,
    url: cleanUrl(location.href),
    title: document.title,
    protocol: location.protocol,
    hostname: location.hostname,
    secureContext: window.isSecureContext,
    headers,
    localStorage: readStorage(window.localStorage),
    sessionStorage: readStorage(window.sessionStorage),
    cookieNames: cookieParts,
    dom: domSignals,
    scannedAt: new Date().toISOString()
  };
}

// Fetch active tab
async function resolveActiveTab() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.id) {
      activeTab = tab;
      try {
        const u = new URL(tab.url);
        activeOrigin = u.origin;
        setElementText("sp-target-title", tab.title || "Untitled Tab");
        setElementText("sp-target-url", u.origin);

        const isHttps = u.protocol === "https:";
        const pill = $("sp-protocol-pill");
        if (pill) {
          pill.textContent = isHttps ? "HTTPS" : u.protocol.toUpperCase().replace(":", "");
          pill.className = `sp-pill ${isHttps ? "sp-pill-secure" : "sp-pill-insecure"}`;
        }
      } catch {
        setElementText("sp-target-title", tab.title || "System Page");
        setElementText("sp-target-url", tab.url || "");
      }
    }
  } catch (err) {
    console.warn("Could not resolve active tab in side panel:", err);
  }
}

// Perform inspection
async function inspectPage() {
  if (!activeTab || !activeTab.id) {
    await resolveActiveTab();
  }
  if (!activeTab || !activeTab.id || !activeTab.url?.startsWith("http")) {
    alert("Please select a standard website tab first.");
    return;
  }

  setElementText("sp-inspect-btn", "⏳ Inspecting...");

  try {
    const [result] = await chrome.scripting.executeScript({
      target: { tabId: activeTab.id },
      func: collectTabSnapshot
    });

    const data = result?.result;
    if (!data) throw new Error("Could not collect page data.");

    activeScan = data;

    // 1. Audit Security
    const headerFindings = auditSecurityHeaders(data.headers || {}, data.url);
    const domFindings = auditDomSecurity(data.dom?.domSecurity || {}, data.url);

    // 2. Fingerprint Technologies
    const tech = fingerprintTech({
      url: data.url,
      headers: data.headers || {},
      meta: data.dom.metaTags,
      scripts: data.dom.scripts,
      storageKeys: [...data.localStorage.map(i => i.key), ...data.sessionStorage.map(i => i.key)]
    });

    // 3. Detect Tokens
    const storageItems = [...data.localStorage, ...data.sessionStorage];
    const detectedTokens = [];
    for (const item of storageItems) {
      if (item.preview) {
        const tokens = detectTokens(item.preview, item.key);
        if (tokens.length) detectedTokens.push(...tokens);
      }
    }

    // 4. Update Engine Findings
    const engine = new FindingsEngine();
    headerFindings.forEach(f => engine.addFinding(f));
    domFindings.forEach(f => engine.addFinding(f));

    // Update Metrics
    const allFindings = engine.getFindings();
    let grade = 'A';
    const hasCrit = allFindings.some(f => f.severity === 'CRITICAL');
    const highCount = allFindings.filter(f => f.severity === 'HIGH').length;
    const medCount = allFindings.filter(f => f.severity === 'MEDIUM').length;

    if (hasCrit) grade = 'F';
    else if (highCount > 1) grade = 'D';
    else if (highCount === 1 || medCount > 2) grade = 'C';
    else if (medCount > 0) grade = 'B';

    const gradeEl = $("sp-sec-grade");
    if (gradeEl) {
      gradeEl.textContent = grade;
      gradeEl.className = `sp-metric-val sp-grade-${grade.toLowerCase()}`;
    }

    setElementText("sp-findings-count", String(allFindings.length));
    setElementText("sp-tech-count", String(tech.length));
    setElementText("sp-storage-count", String(data.localStorage.length + data.sessionStorage.length));

    // Render findings
    renderFindings(allFindings);
    // Render security headers
    renderSecurity(headerFindings);
    // Render tech stack
    renderTech(tech);
    // Render tokens & storage
    renderStorage(data, detectedTokens);

    // Save scan to session storage
    await chrome.storage.session.set({
      [`scan_${activeTab.id}`]: {
        data,
        findings: allFindings,
        tech,
        detectedTokens
      }
    });

  } catch (err) {
    console.error("Inspection error:", err);
    alert(`Inspection failed: ${err.message}`);
  } finally {
    setElementText("sp-inspect-btn", "⚡ Inspect Page");
  }
}

function renderFindings(findings) {
  const container = $("sp-findings-container");
  if (!container) return;
  container.innerHTML = "";

  if (!findings || findings.length === 0) {
    container.innerHTML = `<div class="sp-placeholder">✓ No critical security misconfigurations observed.</div>`;
    return;
  }

  findings.forEach(f => {
    const card = document.createElement("div");
    card.className = `sp-item-card sp-sev-${(f.severity || "info").toLowerCase()}`;
    card.innerHTML = `
      <div class="sp-item-top">
        <strong class="sp-item-title">${escapeHtml(f.title || f.category)}</strong>
        <span class="sp-pill sp-pill-neutral">${(f.severity || "INFO").toUpperCase()}</span>
      </div>
      <div class="sp-item-desc">${escapeHtml(f.description || f.message || "")}</div>
    `;
    container.appendChild(card);
  });
}

function renderSecurity(headerFindings) {
  const container = $("sp-headers-list");
  if (!container) return;
  container.innerHTML = "";

  if (headerFindings && headerFindings.length > 0) {
    headerFindings.forEach(f => {
      const card = document.createElement("div");
      card.className = `sp-item-card sp-sev-${(f.severity || "medium").toLowerCase()}`;
      card.innerHTML = `
        <div class="sp-item-top">
          <strong class="sp-item-title">${escapeHtml(f.title || f.id)}</strong>
          <span class="sp-pill sp-pill-neutral">${(f.severity || "INFO").toUpperCase()}</span>
        </div>
        <div class="sp-item-desc">${escapeHtml(f.description || "")}</div>
      `;
      container.appendChild(card);
    });
  } else {
    container.innerHTML = `<div class="sp-placeholder">All recommended defensive security headers present.</div>`;
  }
}

function renderTech(techList) {
  const grid = $("sp-tech-grid");
  if (!grid) return;
  grid.innerHTML = "";

  if (!techList || techList.length === 0) {
    grid.innerHTML = `<div class="sp-placeholder">No known client technologies fingerprinted.</div>`;
    return;
  }

  techList.forEach(t => {
    const chip = document.createElement("div");
    chip.className = "sp-tech-chip";
    chip.innerHTML = `
      <span>${escapeHtml(t.name || t.technology)}</span>
      <span class="sp-tech-cat">${escapeHtml(t.category || "")}</span>
    `;
    grid.appendChild(chip);
  });
}

function renderStorage(data, tokens) {
  const tokenList = $("sp-tokens-list");
  if (tokenList) {
    tokenList.innerHTML = "";
    if (tokens && tokens.length > 0) {
      tokens.forEach(tok => {
        const card = document.createElement("div");
        card.className = "sp-item-card sp-sev-info";
        card.innerHTML = `
          <div class="sp-item-top">
            <strong class="sp-item-title">${escapeHtml(tok.format || "JWT")} (${tok.algorithm || "Signed"})</strong>
            <span class="sp-pill sp-pill-neutral">${tok.expiresIn ? "Exp: " + tok.expiresIn : "No Exp"}</span>
          </div>
          <div class="sp-item-desc" style="font-family: monospace; word-break: break-all;">
            Subject: ${escapeHtml(tok.claims?.sub || "N/A")} | Issuer: ${escapeHtml(tok.claims?.iss || "N/A")}
          </div>
        `;
        tokenList.appendChild(card);
      });
    } else {
      tokenList.innerHTML = `<div class="sp-placeholder">No JWTs or Bearer tokens detected in storage.</div>`;
    }
  }

  const storageList = $("sp-storage-list");
  if (storageList) {
    storageList.innerHTML = "";
    const all = [...data.localStorage, ...data.sessionStorage];
    if (all.length > 0) {
      all.slice(0, 30).forEach(item => {
        const card = document.createElement("div");
        card.className = "sp-item-card";
        card.innerHTML = `
          <div class="sp-item-top">
            <strong class="sp-item-title">${escapeHtml(item.key)}</strong>
            <span class="sp-pill sp-pill-neutral">${item.length} chars</span>
          </div>
        `;
        storageList.appendChild(card);
      });
    } else {
      storageList.innerHTML = `<div class="sp-placeholder">Storage is empty for this origin.</div>`;
    }
  }
}

function escapeHtml(text) {
  return String(text ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// Navigation Tabs
document.querySelectorAll(".sp-nav-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".sp-nav-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".sp-pane").forEach(p => p.classList.remove("active"));
    btn.classList.add("active");
    const pane = $(btn.getAttribute("data-pane"));
    if (pane) pane.classList.add("active");
  });
});

// Launch Dashboard handler
function openDashboard() {
  const targetId = activeTab?.id ? `?tabId=${activeTab.id}` : "";
  chrome.tabs.create({ url: chrome.runtime.getURL(`dashboard.html${targetId}`) });
}

// Wire up Buttons
$("sp-inspect-btn")?.addEventListener("click", inspectPage);
$("sp-refresh-btn")?.addEventListener("click", () => {
  resolveActiveTab().then(inspectPage);
});
$("sp-dashboard-btn")?.addEventListener("click", openDashboard);
$("sp-launch-dash-btn")?.addEventListener("click", openDashboard);

// DNS button
$("sp-dns-btn")?.addEventListener("click", async () => {
  if (!activeOrigin) return;
  try {
    const host = new URL(activeOrigin).hostname;
    setElementText("sp-dns-btn", "⏳ Querying...");
    const resp = await chrome.runtime.sendMessage({ type: "DNS_LOOKUP", hostname: host });
    if (resp?.ok) {
      alert(`DNS Lookup completed for ${host}.\nDNSSEC Validated: ${resp.dnssec ? "YES" : "NO"}\nTotal records found: ${resp.results?.reduce((acc, r) => acc + (r.answers?.length || 0), 0)}`);
    } else {
      alert(`DNS error: ${resp?.error || "Lookup failed"}`);
    }
  } catch (err) {
    alert(`DNS query failed: ${err.message}`);
  } finally {
    setElementText("sp-dns-btn", "🌐 DNS Lookup");
  }
});

// IP capture button
$("sp-capture-btn")?.addEventListener("click", async () => {
  if (!activeTab || !activeTab.id || !activeOrigin) return;
  try {
    if (!captureState?.running) {
      setElementText("sp-capture-btn", "⏳ Attaching...");
      const resp = await chrome.runtime.sendMessage({
        type: "START_CAPTURE",
        tabId: activeTab.id,
        origin: activeOrigin
      });
      if (resp?.ok) {
        captureState = resp.state;
        setElementText("sp-capture-btn", "⏹ Stop Capture");
      } else {
        alert(`Capture error: ${resp?.error || "Could not attach debugger"}`);
        setElementText("sp-capture-btn", "📡 IP Capture");
      }
    } else {
      const resp = await chrome.runtime.sendMessage({ type: "STOP_CAPTURE", tabId: activeTab.id });
      captureState = resp?.state || null;
      setElementText("sp-capture-btn", "📡 IP Capture");
    }
  } catch (err) {
    alert(`Capture failed: ${err.message}`);
    setElementText("sp-capture-btn", "📡 IP Capture");
  }
});

// React to tab switching in browser
chrome.tabs.onActivated?.addListener(async activeInfo => {
  if (activeInfo.tabId) {
    try {
      const tab = await chrome.tabs.get(activeInfo.tabId);
      if (tab?.url?.startsWith("http")) {
        activeTab = tab;
        await resolveActiveTab();
      }
    } catch {}
  }
});

chrome.tabs.onUpdated?.addListener((tabId, changeInfo, tab) => {
  if (activeTab && tabId === activeTab.id && changeInfo.status === "complete" && tab.url?.startsWith("http")) {
    activeTab = tab;
    resolveActiveTab();
  }
});

// Initialize on open
resolveActiveTab();
