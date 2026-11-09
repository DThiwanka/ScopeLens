let activeTab = null;
let activeOrigin = null;
let latestScan = null;
let captureState = null;
let latestDns = null;
let activeTabName = "tab-overview";

const $ = id => document.getElementById(id);
const show = el => el && el.classList.remove("hidden");
const hide = el => el && el.classList.add("hidden");

function setStatus(text) {
  const el = $("page-state");
  if (el) el.textContent = text;
}

function showToast(message) {
  const toast = $("toast");
  if (!toast) return;
  toast.textContent = message;
  toast.classList.remove("hidden");
  setTimeout(() => toast.classList.add("hidden"), 2000);
}

function escapeText(value) {
  return String(value ?? "");
}

function safeDisplayUrl(raw) {
  try {
    const url = new URL(raw);
    for (const key of [...url.searchParams.keys()]) {
      if (/token|auth|key|secret|session|password|code|signature|jwt/i.test(key)) {
        url.searchParams.set(key, "[REDACTED]");
      }
    }
    url.username = "";
    url.password = "";
    return url.toString();
  } catch {
    return raw;
  }
}

function addRow(parent, title, sub = "", extra = null) {
  const row = document.createElement("div");
  row.className = "data-row";
  const h = document.createElement("div");
  h.className = "row-title";
  h.textContent = title;
  row.append(h);
  if (sub) {
    const s = document.createElement("div");
    s.className = "row-sub";
    s.textContent = sub;
    row.append(s);
  }
  if (extra) row.append(extra);
  parent.append(row);
  return row;
}

function addCode(parent, value) {
  const pre = document.createElement("pre");
  pre.className = "token-box";
  pre.textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  parent.append(pre);
  return pre;
}

function addEmpty(parent, text) {
  const e = document.createElement("div");
  e.className = "empty";
  e.textContent = text;
  parent.append(e);
  return e;
}

function addTable(parent, headers, rows) {
  if (!rows || !rows.length) {
    addEmpty(parent, "No matching records found.");
    return;
  }
  const wrap = document.createElement("div");
  wrap.className = "table-wrap";
  const table = document.createElement("table");
  const thead = document.createElement("thead");
  const trh = document.createElement("tr");
  headers.forEach(h => {
    const th = document.createElement("th");
    th.textContent = h;
    trh.append(th);
  });
  thead.append(trh);
  table.append(thead);
  const tbody = document.createElement("tbody");
  rows.forEach(row => {
    const tr = document.createElement("tr");
    row.forEach(value => {
      const td = document.createElement("td");
      td.textContent = escapeText(value);
      tr.append(td);
    });
    tbody.append(tr);
  });
  table.append(tbody);
  wrap.append(table);
  parent.append(wrap);
}

function formatRelativeTime(secondsDiff) {
  const abs = Math.abs(secondsDiff);
  if (abs < 60) return `${Math.round(abs)}s`;
  if (abs < 3600) return `${Math.round(abs / 60)}m`;
  if (abs < 86400) return `${Math.round(abs / 3600)}h`;
  return `${Math.round(abs / 86400)}d`;
}

// ---------------- Page Data Collector (Injected into active tab) ----------------
function collectPageData() {
  const origin = location.origin;
  const secretKey = /token|auth|session|secret|password|credential|api.?key|jwt|access|refresh/i;
  const jwtPattern = /[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;

  const decodePart = part => {
    try {
      const b64 = part.replace(/-/g, "+").replace(/_/g, "/");
      const binary = atob(b64.padEnd(Math.ceil(b64.length / 4) * 4, "="));
      const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
      return JSON.parse(new TextDecoder().decode(bytes));
    } catch {
      return null;
    }
  };

  const parseJwt = token => {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const header = decodePart(parts[0]);
    const payload = decodePart(parts[1]);
    if (!header && !payload) return null;

    let expiryInfo = { status: "unknown", label: "No exp claim", expTimestamp: null };
    if (payload?.exp && typeof payload.exp === "number") {
      const nowSec = Math.floor(Date.now() / 1000);
      const diff = payload.exp - nowSec;
      expiryInfo.expTimestamp = payload.exp;
      if (diff <= 0) {
        expiryInfo = { status: "expired", label: `Expired ${Math.abs(Math.round(diff / 60))} mins ago`, expTimestamp: payload.exp };
      } else if (diff < 900) {
        expiryInfo = { status: "warning", label: `Expires soon in ${Math.round(diff / 60)} mins`, expTimestamp: payload.exp };
      } else {
        const days = Math.round(diff / 86400);
        const hours = Math.round(diff / 3600);
        expiryInfo = { status: "active", label: days > 0 ? `Active · Expires in ${days}d` : `Active · Expires in ${hours}h`, expTimestamp: payload.exp };
      }
    }

    const alg = header?.alg || "unknown";
    const isWeakAlg = alg.toLowerCase() === "none";

    return {
      header,
      payload,
      algorithm: alg,
      isWeakAlg,
      expiry: expiryInfo,
      rawSample: `${parts[0].slice(0, 8)}…[REDACTED]…${parts[2].slice(-6)}`
    };
  };

  const findJwts = value => {
    const matches = String(value || "").match(jwtPattern) || [];
    const results = [];
    for (const match of matches.slice(0, 5)) {
      const parsed = parseJwt(match);
      if (parsed) results.push(parsed);
    }
    return results;
  };

  const collectStorage = storage => {
    const items = [];
    try {
      for (let i = 0; i < storage.length && items.length < 300; i++) {
        const key = storage.key(i);
        const value = storage.getItem(key) || "";
        const jwts = findJwts(value);
        items.push({
          key,
          characters: value.length,
          kind: jwts.length ? "JWT-shaped value" : (secretKey.test(key) ? "Possible sensitive value (masked)" : "Standard entry"),
          jwts
        });
      }
    } catch (error) {
      return { items, error: error.message };
    }
    return { items, error: null };
  };

  const sanitizeUrl = raw => {
    try {
      const u = new URL(raw, location.href);
      for (const key of [...u.searchParams.keys()]) {
        if (secretKey.test(key)) u.searchParams.set(key, "[REDACTED]");
      }
      u.username = "";
      u.password = "";
      return u.toString();
    } catch {
      return String(raw);
    }
  };

  // --- Client-side Technology Detection ---
  const detectTechnologies = () => {
    const techs = [];
    const addTech = (name, category, version = null, confidence = "High") => {
      if (!techs.some(t => t.name === name)) {
        techs.push({ name, category, version, confidence });
      }
    };

    // Frameworks & Libraries
    if (window.React || document.querySelector("[data-reactroot], #react-root") || window.__REACT_DEVTOOLS_GLOBAL_HOOK__) {
      addTech("React", "Frontend Framework");
    }
    if (window.Vue || document.querySelector("[data-v-]") || window.__VUE__) {
      const version = window.Vue?.version || (window.__VUE__ ? "3.x" : null);
      addTech("Vue.js", "Frontend Framework", version);
    }
    if (window.angular || document.querySelector("[ng-version], [ng-app]")) {
      const el = document.querySelector("[ng-version]");
      const ver = el ? el.getAttribute("ng-version") : (window.angular?.version?.full || null);
      addTech("Angular", "Frontend Framework", ver);
    }
    if (window.__NEXT_DATA__ || document.getElementById("__next")) {
      addTech("Next.js", "Web Framework", window.__NEXT_DATA__?.buildId ? "build: " + window.__NEXT_DATA__.buildId.slice(0, 8) : null);
    }
    if (window.__NUXT__ || document.getElementById("__nuxt")) {
      addTech("Nuxt.js", "Web Framework");
    }
    if (window.__remixContext) {
      addTech("Remix", "Web Framework");
    }
    if (document.querySelector("astro-island")) {
      addTech("Astro", "Web Framework");
    }
    if (document.querySelector("[class*='svelte-']") || window.__svelte) {
      addTech("Svelte", "Frontend Framework");
    }
    if (window.jQuery || window.$?.fn?.jquery) {
      addTech("jQuery", "JavaScript Library", window.jQuery?.fn?.jquery || window.$?.fn?.jquery || null);
    }
    if (window.Alpine) {
      addTech("Alpine.js", "JavaScript Framework", window.Alpine?.version || null);
    }
    if (window.htmx) {
      addTech("htmx", "JavaScript Library", window.htmx?.version || null);
    }
    if (window._ && typeof window._.VERSION === "string") {
      addTech("Lodash", "JavaScript Library", window._.VERSION);
    }
    if (window.axios) {
      addTech("Axios", "HTTP Client");
    }

    // CSS Frameworks
    if (document.querySelector("link[href*='tailwind'], style[data-tailwind]") || [...document.querySelectorAll("*")].some(el => el.classList && [...el.classList].some(c => /^(flex|grid|p-\d|m-\d|text-(sm|md|lg|xl)|bg-|rounded-)/.test(c)))) {
      addTech("Tailwind CSS", "CSS Framework");
    }
    if (window.bootstrap || document.querySelector("link[href*='bootstrap'], [class*='navbar-expand']")) {
      addTech("Bootstrap", "CSS Framework");
    }

    // CMS & Platforms
    const metaGen = document.querySelector("meta[name='generator']")?.content || "";
    if (metaGen.includes("WordPress") || document.querySelector("link[href*='wp-content'], script[src*='wp-includes']")) {
      const match = metaGen.match(/WordPress\s*([\d.]+)/i);
      addTech("WordPress", "CMS", match ? match[1] : null);
    }
    if (window.Shopify || document.querySelector("link[href*='cdn.shopify.com']")) {
      addTech("Shopify", "E-commerce");
    }
    if (window.Webflow || metaGen.includes("Webflow")) {
      addTech("Webflow", "Website Builder");
    }
    if (metaGen.includes("Ghost")) {
      addTech("Ghost", "CMS");
    }
    if (window.Drupal || document.querySelector("script[src*='drupal']")) {
      addTech("Drupal", "CMS");
    }

    // Analytics, Monitoring & CDNs
    if (window.gtag || window.ga || window.GoogleAnalyticsObject) {
      addTech("Google Analytics", "Analytics");
    }
    if (window.google_tag_manager || window.dataLayer) {
      addTech("Google Tag Manager", "Tag Manager");
    }
    if (window.__SENTRY__ || window.Sentry) {
      addTech("Sentry", "Error Tracking");
    }
    if (window.analytics && typeof window.analytics.track === "function") {
      addTech("Segment", "Customer Data");
    }
    if (window.hj || window._hjSettings) {
      addTech("Hotjar", "User Feedback");
    }
    if (window.mixpanel) {
      addTech("Mixpanel", "Analytics");
    }
    if (document.querySelector("script[src*='challenges.cloudflare.com/turnstile']")) {
      addTech("Cloudflare Turnstile", "Security & Bot Protection");
    }

    // Browser APIs
    if (window.WebAssembly) addTech("WebAssembly", "Web API");
    if (window.WebGLRenderingContext) addTech("WebGL", "Graphics API");
    if (navigator.gpu) addTech("WebGPU", "Graphics API");

    return techs;
  };

  // --- Fetch Document Headers for live Security Header audit ---
  const fetchHeadersJob = (async () => {
    try {
      const resp = await fetch(location.href, { method: "HEAD", cache: "no-store" });
      const headers = {};
      resp.headers.forEach((value, key) => {
        headers[key.toLowerCase()] = value;
      });
      return { ok: true, headers, status: resp.status };
    } catch (err) {
      return { ok: false, error: err.message, headers: {} };
    }
  })();

  const resources = performance.getEntriesByType("resource")
    .filter(entry => {
      try { return new URL(entry.name).origin === origin; }
      catch { return false; }
    })
    .slice(-250)
    .map(entry => ({
      url: sanitizeUrl(entry.name),
      initiatorType: entry.initiatorType,
      durationMs: Math.round(entry.duration),
      transferSize: entry.transferSize || 0
    }));

  const cookieParts = document.cookie ? document.cookie.split(";").map(part => part.trim().split("=")[0]).filter(Boolean) : [];
  const sensitiveCookies = cookieParts.filter(name => secretKey.test(name));

  const cacheJobs = (async () => {
    const cachesFound = [];
    if (!("caches" in window)) return cachesFound;
    try {
      for (const cacheName of await caches.keys()) {
        const cache = await caches.open(cacheName);
        const requests = await cache.keys();
        const entries = [];
        for (const request of requests.slice(0, 100)) {
          if (new URL(request.url).origin !== origin) continue;
          const response = await cache.match(request);
          entries.push({
            url: sanitizeUrl(request.url),
            status: response?.status ?? null,
            contentType: response?.headers.get("content-type") || ""
          });
        }
        cachesFound.push({ name: cacheName, entries });
      }
    } catch (error) {
      cachesFound.push({ name: "CacheStorage error", error: error.message, entries: [] });
    }
    return cachesFound;
  })();

  const idbJob = (async () => {
    const dbs = [];
    if (!indexedDB.databases) return { supported: false, databases: dbs };
    try {
      const names = await indexedDB.databases();
      for (const info of names.slice(0, 50)) {
        if (!info.name) continue;
        const db = await new Promise(resolve => {
          const request = indexedDB.open(info.name);
          request.onsuccess = () => resolve(request.result);
          request.onerror = () => resolve(null);
          request.onblocked = () => resolve(null);
        });
        dbs.push({
          name: info.name,
          version: info.version || null,
          stores: db ? Array.from(db.objectStoreNames) : []
        });
        db?.close();
      }
    } catch (error) {
      return { supported: true, databases: dbs, error: error.message };
    }
    return { supported: true, databases: dbs };
  })();

  const swJob = (async () => {
    try {
      if (!navigator.serviceWorker) return [];
      const registrations = await navigator.serviceWorker.getRegistrations();
      return registrations.map(reg => ({
        scope: sanitizeUrl(reg.scope),
        active: Boolean(reg.active),
        waiting: Boolean(reg.waiting),
        installing: Boolean(reg.installing)
      }));
    } catch {
      return [];
    }
  })();

  return Promise.all([cacheJobs, idbJob, swJob, fetchHeadersJob]).then(([cacheStorage, indexedDb, serviceWorkers, liveHeaders]) => ({
    origin,
    title: document.title,
    protocol: location.protocol,
    hostname: location.hostname,
    secureContext: window.isSecureContext,
    technologies: detectTechnologies(),
    headers: liveHeaders.headers || {},
    localStorage: collectStorage(window.localStorage),
    sessionStorage: collectStorage(window.sessionStorage),
    cacheStorage,
    indexedDb,
    serviceWorkers,
    cookieNames: cookieParts,
    sensitiveCookies,
    resources
  }));
}

function scanReadableCacheBodies() {
  const origin = location.origin;
  const textTypes = /text\/|json|javascript|xml|svg/i;
  const redact = text => String(text)
    .replace(/(authorization|cookie|set-cookie|password|client_secret|access_token|refresh_token|api[_-]?key)(["'\s:=]+)([^"'\s,;&}]+)/gi, "$1$2[REDACTED]")
    .replace(/\bBearer\s+[A-Za-z0-9._~+/-]+=*/gi, "Bearer [REDACTED]")
    .replace(/[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, "[JWT REDACTED]");

  return (async () => {
    const output = [];
    if (!("caches" in window)) return output;
    for (const cacheName of await caches.keys()) {
      const cache = await caches.open(cacheName);
      for (const request of await cache.keys()) {
        if (new URL(request.url).origin !== origin) continue;
        const response = await cache.match(request);
        if (!response) continue;
        const type = response.headers.get("content-type") || "";
        const length = Number(response.headers.get("content-length") || 0);
        if (!textTypes.test(type) || (length && length > 256 * 1024)) continue;
        try {
          const text = await response.clone().text();
          if (text.length > 256 * 1024) continue;
          output.push({
            cache: cacheName,
            url: request.url,
            contentType: type,
            characters: text.length,
            preview: redact(text).slice(0, 600)
          });
        } catch {}
        if (output.length >= 30) return output;
      }
    }
    return output;
  })();
}

// ---------------- Security Posture Audit Engine ----------------
function evaluateSecurityPosture(data, networkHeaders = {}) {
  const headers = Object.assign({}, networkHeaders, data.headers || {});
  const checks = [];
  let score = 100;

  // 1. HTTPS / Secure Context
  const isHttps = data.protocol === "https:";
  checks.push({
    name: "HTTPS Protocol & Secure Context",
    passed: isHttps && data.secureContext,
    impact: "High",
    value: isHttps ? `${data.protocol} (Secure Context)` : "Insecure HTTP",
    recommendation: isHttps ? "TLS encryption active." : "Migrate all endpoints to HTTPS to protect confidentiality and integrity."
  });
  if (!isHttps) score -= 40;

  // 2. Strict-Transport-Security (HSTS)
  const hsts = headers["strict-transport-security"];
  if (hsts) {
    const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
    const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
    const hasSubDomains = /includeSubDomains/i.test(hsts);
    const hasPreload = /preload/i.test(hsts);
    const goodAge = maxAge >= 15552000; // >= 180 days

    checks.push({
      name: "Strict-Transport-Security (HSTS)",
      passed: goodAge,
      impact: "High",
      value: `max-age=${maxAge}s${hasSubDomains ? "; includeSubDomains" : ""}${hasPreload ? "; preload" : ""}`,
      recommendation: goodAge ? "HSTS enforces HTTPS and prevents SSL stripping." : "Increase max-age to at least 15552000 (180 days) and consider includeSubDomains."
    });
    if (!goodAge) score -= 10;
  } else {
    checks.push({
      name: "Strict-Transport-Security (HSTS)",
      passed: false,
      impact: "High",
      value: "Missing",
      recommendation: "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to prevent man-in-the-middle downgrades."
    });
    score -= 20;
  }

  // 3. Content-Security-Policy (CSP)
  const csp = headers["content-security-policy"];
  if (csp) {
    const hasUnsafeInline = /'unsafe-inline'/i.test(csp);
    const hasUnsafeEval = /'unsafe-eval'/i.test(csp);
    const hasFrameAncestors = /frame-ancestors/i.test(csp);
    const warnings = [];
    if (hasUnsafeInline) warnings.push("'unsafe-inline' detected");
    if (hasUnsafeEval) warnings.push("'unsafe-eval' detected");

    checks.push({
      name: "Content-Security-Policy (CSP)",
      passed: warnings.length === 0,
      impact: "Critical",
      value: warnings.length ? `Configured with warnings: ${warnings.join(", ")}` : "Configured and enforced",
      recommendation: warnings.length ? "Eliminate 'unsafe-inline' and 'unsafe-eval' by adopting nonce or hash-based CSP." : "Solid CSP protects against XSS and data injection."
    });
    if (warnings.length) score -= 10;
  } else {
    checks.push({
      name: "Content-Security-Policy (CSP)",
      passed: false,
      impact: "Critical",
      value: "Missing",
      recommendation: "Implement a Content Security Policy to mitigate Cross-Site Scripting (XSS) and content injection."
    });
    score -= 25;
  }

  // 4. X-Frame-Options (Clickjacking)
  const xfo = headers["x-frame-options"];
  const cspFrame = csp && /frame-ancestors/i.test(csp);
  const clickjackProtected = Boolean((xfo && /^(DENY|SAMEORIGIN)$/i.test(xfo.trim())) || cspFrame);
  checks.push({
    name: "Clickjacking Defense (X-Frame-Options / frame-ancestors)",
    passed: clickjackProtected,
    impact: "Medium",
    value: xfo || (cspFrame ? "Handled via CSP frame-ancestors" : "Missing"),
    recommendation: clickjackProtected ? "Protected against iframe clickjacking attacks." : "Set X-Frame-Options: SAMEORIGIN or CSP frame-ancestors to prevent clickjacking."
  });
  if (!clickjackProtected) score -= 15;

  // 5. X-Content-Type-Options (MIME-sniffing)
  const xcto = headers["x-content-type-options"];
  const hasNosniff = xcto && /nosniff/i.test(xcto);
  checks.push({
    name: "MIME Sniffing Protection (X-Content-Type-Options)",
    passed: Boolean(hasNosniff),
    impact: "Medium",
    value: xcto || "Missing",
    recommendation: hasNosniff ? "nosniff is properly enabled." : "Set 'X-Content-Type-Options: nosniff' to stop browsers from MIME-sniffing response types."
  });
  if (!hasNosniff) score -= 10;

  // 6. Referrer-Policy
  const refPol = headers["referrer-policy"];
  const safeRef = refPol && !/unsafe-url/i.test(refPol);
  checks.push({
    name: "Referrer-Policy",
    passed: Boolean(safeRef),
    impact: "Low",
    value: refPol || "Browser Default",
    recommendation: safeRef ? `Policy: ${refPol}` : "Set 'Referrer-Policy: strict-origin-when-cross-origin' to protect query parameter privacy."
  });
  if (refPol && /unsafe-url/i.test(refPol)) score -= 10;

  // 7. Information Leakage (Server / X-Powered-By)
  const server = headers["server"];
  const xPowered = headers["x-powered-by"];
  const disclosesTech = Boolean((xPowered && xPowered.length > 0) || (server && /[\d.]/.test(server)));
  checks.push({
    name: "Server Technology Disclosure",
    passed: !disclosesTech,
    impact: "Low",
    value: disclosesTech ? `Exposed: ${[server, xPowered].filter(Boolean).join(" · ")}` : "No granular server versions leaked",
    recommendation: disclosesTech ? "Remove or obfuscate Server and X-Powered-By headers to hinder automated reconnaissance." : "Headers do not leak server or framework versions."
  });
  if (disclosesTech) score -= 5;

  // 8. Sensitive Cookie Exposure in document.cookie
  const hasExposedSensitiveCookies = (data.sensitiveCookies || []).length > 0;
  if (hasExposedSensitiveCookies) {
    checks.push({
      name: "Cookie Hygiene (HttpOnly check)",
      passed: false,
      impact: "High",
      value: `Sensitive keys visible in document.cookie: ${data.sensitiveCookies.join(", ")}`,
      recommendation: "Ensure authentication and session cookies are marked 'HttpOnly' so they cannot be accessed by client JavaScript."
    });
    score -= 15;
  }

  score = Math.max(0, Math.min(100, score));
  let grade = "A+";
  if (score < 50) grade = "F";
  else if (score < 65) grade = "D";
  else if (score < 75) grade = "C";
  else if (score < 88) grade = "B";
  else if (score < 96) grade = "A";

  return { score, grade, checks, headers };
}

// ---------------- UI Rendering ----------------
async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id || !tab.url) throw new Error("Open a website tab first.");
  const url = new URL(tab.url);
  if (!/^https?:$/.test(url.protocol)) throw new Error("This page type cannot be inspected. Open an http or https website.");
  activeTab = tab;
  activeOrigin = url.origin;

  $("site-title").textContent = url.hostname;
  $("site-url").textContent = tab.url;

  const badge = $("site-security-badge");
  if (badge) {
    badge.textContent = url.protocol === "https:" ? "HTTPS" : "HTTP";
    badge.className = `badge-mini ${url.protocol === "https:" ? "badge-success" : "badge-danger"}`;
  }
  return tab;
}

function renderSnapshot(data) {
  latestScan = data;
  hide($("overview-empty"));
  show($("summary-panel"));
  show($("tech-stack-panel"));
  show($("security-score-card"));

  $("snapshot-origin").textContent = data.origin;
  $("snapshot-grid").replaceChildren();

  const stats = [
    [data.technologies.length, "tech detected"],
    [data.localStorage.items.length, "localStorage"],
    [data.sessionStorage.items.length, "sessionStorage"],
    [data.indexedDb.databases.length, "IndexedDBs"]
  ];
  stats.forEach(([num, label]) => {
    const el = document.createElement("div");
    el.className = "stat";
    const b = document.createElement("b");
    b.textContent = num;
    const s = document.createElement("span");
    s.textContent = label;
    el.append(b, s);
    $("snapshot-grid").append(el);
  });

  const details = $("snapshot-details");
  details.replaceChildren();
  addRow(details, data.title || "(untitled page)", `${data.protocol} · secure context: ${data.secureContext ? "yes" : "no"}`);
  addRow(details, `Visible cookie names: ${data.cookieNames.length}`, data.cookieNames.length ? data.cookieNames.join(", ") : "No document.cookie visible. HttpOnly cookies cannot be read here.");
  addRow(details, `Service workers: ${data.serviceWorkers.length}`, data.serviceWorkers.map(sw => sw.scope).join(" · ") || "None registered");
  addRow(details, `Performance resource entries: ${data.resources.length}`, "Same-origin resource timing entries observed.");

  // Render Tech Stack
  renderTechStack(data.technologies);

  // Render Security Posture
  const sec = evaluateSecurityPosture(data, captureState?.documentHeaders || {});
  renderSecurityAudit(sec, data);

  // Render Storage & JWTs
  renderStorageAndTokens(data);

  if (data.cacheStorage.some(cache => cache.entries.length)) {
    show($("cache-preview-btn"));
  } else {
    hide($("cache-preview-btn"));
  }
}

function renderTechStack(techs) {
  const grid = $("tech-stack-grid");
  grid.replaceChildren();
  $("tech-count").textContent = `${techs.length} detected`;

  if (!techs.length) {
    addEmpty(grid, "No common frameworks or technologies identified via client-side heuristics.");
    return;
  }

  techs.forEach(t => {
    const item = document.createElement("div");
    item.className = "tech-item";

    const name = document.createElement("div");
    name.className = "tech-name";
    name.textContent = t.name;

    const cat = document.createElement("div");
    cat.className = "tech-cat";
    cat.textContent = t.category + (t.version ? ` (${t.version})` : "");

    item.append(name, cat);
    grid.append(item);
  });
}

function renderSecurityAudit(sec, data) {
  // Update Grade badge
  const gradeBadge = $("security-grade-badge");
  gradeBadge.textContent = sec.grade;
  gradeBadge.className = `grade-badge grade-${sec.grade.toLowerCase().replace("+", "-plus")}`;

  $("security-score-sub").textContent = `Security score: ${sec.score}/100 · ${sec.checks.filter(c => c.passed).length}/${sec.checks.length} checks passed`;

  // Checklist in Security tab
  const list = $("security-checklist");
  list.replaceChildren();

  const failedCount = sec.checks.filter(c => !c.passed).length;
  const badge = $("sec-count-badge");
  if (failedCount > 0) {
    badge.textContent = failedCount;
    show(badge);
  } else {
    hide(badge);
  }

  sec.checks.forEach(check => {
    const card = document.createElement("div");
    card.className = `check-item ${check.passed ? "check-pass" : "check-fail"}`;

    const icon = document.createElement("span");
    icon.className = `check-icon ${check.passed ? "icon-pass" : "icon-fail"}`;
    icon.textContent = check.passed ? "✓" : "!";

    const body = document.createElement("div");
    body.className = "check-body";

    const titleRow = document.createElement("div");
    titleRow.className = "check-title-row";

    const title = document.createElement("span");
    title.className = "check-title";
    title.textContent = check.name;

    const statusPill = document.createElement("span");
    statusPill.className = `badge-mini ${check.passed ? "badge-success" : "badge-danger"}`;
    statusPill.textContent = check.passed ? "Passed" : "Action Needed";

    titleRow.append(title, statusPill);

    const val = document.createElement("div");
    val.className = "check-val";
    val.textContent = check.value;

    const rec = document.createElement("div");
    rec.className = "check-rec muted";
    rec.textContent = check.recommendation;

    body.append(titleRow, val, rec);
    card.append(icon, body);
    list.append(card);
  });

  // CSP Detail View
  const cspDetails = $("csp-details");
  cspDetails.replaceChildren();
  const rawCsp = sec.headers["content-security-policy"];
  if (rawCsp) {
    $("csp-status").textContent = "Enforced";
    addRow(cspDetails, "Directives breakdown", "Policies parsed from active response header:");
    addCode(cspDetails, rawCsp.split(";").map(p => p.trim()).filter(Boolean).join("\n"));
  } else {
    $("csp-status").textContent = "Missing";
    addEmpty(cspDetails, "No Content-Security-Policy header received for the inspected document.");
  }
}

function renderStorageAndTokens(data) {
  const target = $("storage-results");
  target.replaceChildren();

  // LocalStorage
  renderStorageGroup(target, "localStorage", data.localStorage);
  // SessionStorage
  renderStorageGroup(target, "sessionStorage", data.sessionStorage);

  // Cookie hygiene
  const cookieTitle = document.createElement("h3");
  cookieTitle.className = "row-title";
  cookieTitle.textContent = "Cookies (document.cookie)";
  target.append(cookieTitle);

  if (!data.cookieNames.length) {
    addEmpty(target, "No visible cookies on this origin. (HttpOnly cookies are protected from script access).");
  } else {
    addRow(target, `${data.cookieNames.length} readable cookie(s)`, data.cookieNames.join(", "));
    if (data.sensitiveCookies.length) {
      const warn = document.createElement("div");
      warn.className = "notice notice-warn";
      warn.textContent = `Warning: ${data.sensitiveCookies.length} potentially sensitive cookie(s) lack HttpOnly flag: ${data.sensitiveCookies.join(", ")}`;
      target.append(warn);
    }
  }

  // CacheStorage
  const cacheTitle = document.createElement("h3");
  cacheTitle.textContent = "CacheStorage";
  cacheTitle.className = "row-title";
  target.append(cacheTitle);

  if (!data.cacheStorage.length) addEmpty(target, "No CacheStorage buckets found.");
  data.cacheStorage.forEach(cache => {
    addRow(target, `Cache: ${cache.name}`, cache.error || `${cache.entries.length} same-origin entries`);
    if (cache.entries.length) {
      addTable(target, ["Cached URL", "Status", "Content Type"], cache.entries.map(e => [e.url, e.status, e.contentType]));
    }
  });

  // IndexedDB
  const idbTitle = document.createElement("h3");
  idbTitle.textContent = "IndexedDB Schema";
  idbTitle.className = "row-title";
  target.append(idbTitle);

  if (!data.indexedDb.databases.length) {
    addEmpty(target, data.indexedDb.supported ? "No databases found." : "IndexedDB enumeration unsupported in this context.");
  }
  data.indexedDb.databases.forEach(db => {
    addRow(target, db.name, `Version ${db.version ?? "?"} · stores: ${db.stores.join(", ") || "none visible"}`);
  });
}

function renderStorageGroup(parent, name, group) {
  const title = document.createElement("h3");
  title.textContent = `${name} (${group.items.length} keys)`;
  title.className = "row-title";
  parent.append(title);

  if (!group.items.length) {
    addEmpty(parent, "No keys found.");
    return;
  }

  group.items.forEach(item => {
    const badges = document.createElement("div");
    const badge = document.createElement("span");
    badge.className = "tag";
    badge.textContent = item.kind;
    badges.append(badge);

    const row = addRow(parent, item.key, `${item.characters} characters · actual value masked`, badges);

    // Render Deep JWT breakdown
    item.jwts.forEach((jwt, idx) => {
      const jwtBox = document.createElement("div");
      jwtBox.className = "jwt-card";

      const jwtTop = document.createElement("div");
      jwtTop.className = "jwt-header-row";

      const jwtLabel = document.createElement("span");
      jwtLabel.className = "jwt-title";
      jwtLabel.textContent = `Decoded JWT #${idx + 1} (${jwt.algorithm})`;

      const expPill = document.createElement("span");
      expPill.className = `badge-mini badge-${jwt.expiry.status === "active" ? "success" : (jwt.expiry.status === "warning" ? "warn" : "danger")}`;
      expPill.textContent = jwt.expiry.label;

      const copyBtn = document.createElement("button");
      copyBtn.className = "btn-xs";
      copyBtn.textContent = "Copy Payload";
      copyBtn.addEventListener("click", e => {
        e.stopPropagation();
        navigator.clipboard.writeText(JSON.stringify(jwt.payload, null, 2));
        showToast("JWT payload copied to clipboard!");
      });

      jwtTop.append(jwtLabel, expPill, copyBtn);
      jwtBox.append(jwtTop);

      if (jwt.isWeakAlg) {
        const warn = document.createElement("div");
        warn.className = "notice notice-danger";
        warn.textContent = "CRITICAL: JWT uses alg: 'none'. The token is unsigned and vulnerable to forgery!";
        jwtBox.append(warn);
      }

      addCode(jwtBox, {
        header: jwt.header,
        payload: jwt.payload,
        claims: {
          issuer: jwt.payload?.iss || "not set",
          subject: jwt.payload?.sub || "not set",
          audience: jwt.payload?.aud || "not set",
          expiration: jwt.payload?.exp ? new Date(jwt.payload.exp * 1000).toLocaleString() : "none"
        }
      });

      row.append(jwtBox);
    });
  });

  if (group.error) addEmpty(parent, `Storage access note: ${group.error}`);
}

function renderDns(result) {
  latestDns = result;
  $("dns-host").textContent = result.hostname;

  // Render DNSSEC badge
  const badgeContainer = $("dnssec-badge-container");
  badgeContainer.replaceChildren();
  const badge = document.createElement("div");
  badge.className = `dnssec-banner ${result.dnssec ? "dnssec-valid" : "dnssec-none"}`;
  badge.innerHTML = result.dnssec
    ? "<strong>DNSSEC Validated (AD Flag Set):</strong> Responses cryptographically authenticated by upstream resolver."
    : "<strong>DNSSEC:</strong> Authenticated Data (AD) flag not returned for this query.";
  badgeContainer.append(badge);

  const target = $("dns-results");
  target.replaceChildren();

  result.results.forEach(record => {
    const row = addRow(target, record.type, record.answers.length ? `${record.answers.length} answer(s)` : "No answer returned");
    if (record.answers.length) {
      addTable(target, ["Name", "TTL", "Data"], record.answers.map(a => [a.name, a.ttl, a.data]));
    }
  });
}

function renderCapture(state) {
  if (state) captureState = state;
  const active = Boolean(captureState?.running);
  $("capture-state").textContent = active ? "Capturing same-origin responses" : "Not capturing";
  $("capture-btn").innerHTML = active
    ? '<span class="btn-icon">⏹</span> Stop IP Capture'
    : '<span class="btn-icon">📡</span> Start IP Capture';

  // Render TLS summary if available
  const tlsCard = $("tls-card");
  if (captureState?.securityDetails) {
    show(tlsCard);
    tlsCard.replaceChildren();
    const sd = captureState.securityDetails;
    const daysLeft = sd.validTo ? Math.round((sd.validTo - Date.now()) / (1000 * 86400)) : null;

    const h = document.createElement("div");
    h.className = "tls-header";
    h.innerHTML = `<strong>TLS Security:</strong> ${sd.protocol} · ${sd.cipher || ""}`;

    const sub = document.createElement("div");
    sub.className = "tls-sub muted";
    sub.textContent = `Issuer: ${sd.issuer || "unknown"} · Subject: ${sd.subjectName || "unknown"}`;

    const pill = document.createElement("span");
    pill.className = `badge-mini ${daysLeft && daysLeft > 14 ? "badge-success" : "badge-danger"}`;
    pill.textContent = daysLeft !== null ? (daysLeft > 0 ? `Cert expires in ${daysLeft} days` : "Certificate expired!") : "TLS active";

    tlsCard.append(h, sub, pill);
  } else {
    hide(tlsCard);
  }

  const result = $("network-results");
  result.replaceChildren();
  const items = captureState?.items || [];
  if (!items.length) {
    addEmpty(result, "No captured responses yet. Click Start IP Capture, then reload or interact with the page.");
    return;
  }

  const unique = new Map();
  items.forEach(item => {
    const key = `${item.remoteIp}|${item.remotePort || ""}`;
    if (!unique.has(key)) unique.set(key, item);
  });

  addRow(result, `${unique.size} distinct remote endpoint(s)`, "Reported by Chrome DevTools Protocol for same-origin responses.");
  addTable(result, ["Remote IP", "Remote Port", "HTTP", "Protocol", "Resource"], items.slice(0, 60).map(item => [
    item.remoteIp,
    item.remotePort ?? "—",
    item.status,
    item.protocol || "—",
    item.url
  ]));

  const ports = [...new Set(items.map(item => item.remotePort).filter(Boolean))].sort((a, b) => a - b);
  addRow(result, `Observed remote ports: ${ports.join(", ") || "not exposed"}`, "Ports actually observed in connections, not a port scan.");
}

// ---------------- Actions ----------------
async function inspectPage() {
  try {
    setStatus("Inspecting…");
    const tab = await getActiveTab();
    const results = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: collectPageData
    });
    if (!results?.[0]?.result) {
      throw new Error("Page did not return inspection data. Try reloading it first.");
    }
    renderSnapshot(results[0].result);
    setStatus("Inspected");
    chrome.storage.session.set({
      [`scan_${tab.id}`]: results[0].result,
      lastTargetTab: { id: tab.id, url: tab.url, origin: activeOrigin, title: $("site-title").textContent }
    }).catch(() => {});

    const captured = await chrome.runtime.sendMessage({ type: "GET_CAPTURE", tabId: tab.id });
    if (captured?.state) renderCapture(captured.state);
    showToast("Page snapshot collected!");
  } catch (error) {
    setStatus("Error");
    alert(error.message);
  }
}

async function lookupDns() {
  try {
    const tab = await getActiveTab();
    const hostname = new URL(tab.url).hostname;
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname.includes(":")) {
      throw new Error("DNS record lookup requires a hostname, not an IP address.");
    }
    setStatus("Looking up DNS…");
    // Switch to DNS tab
    switchTab("tab-dns");

    const response = await chrome.runtime.sendMessage({ type: "DNS_LOOKUP", hostname });
    if (!response?.ok) throw new Error(response?.error || "DNS lookup failed.");
    renderDns(response);
    setStatus("DNS ready");
    showToast("DNS records retrieved!");
  } catch (error) {
    setStatus("Error");
    alert(error.message);
  }
}

async function toggleCapture() {
  try {
    const tab = await getActiveTab();
    if (captureState?.running) {
      const response = await chrome.runtime.sendMessage({ type: "STOP_CAPTURE", tabId: tab.id });
      if (!response?.ok) throw new Error(response?.error || "Could not stop capture.");
      renderCapture(response.state);
      setStatus("Capture stopped");
      showToast("IP capture stopped.");
    } else {
      setStatus("Attaching…");
      switchTab("tab-network");
      const response = await chrome.runtime.sendMessage({
        type: "START_CAPTURE",
        tabId: tab.id,
        origin: activeOrigin
      });
      if (!response?.ok) throw new Error(response?.error || "Could not start capture.");
      renderCapture(response.state);
      setStatus("Capturing");
      showToast("IP capture started! Reload the page to record endpoints.");
    }
  } catch (error) {
    setStatus("Capture error");
    alert(`${error.message}\n\nChrome may refuse attachment if another debugger is attached. Close other DevTools windows and retry.`);
  }
}

async function previewCacheBodies() {
  try {
    const tab = await getActiveTab();
    const response = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: scanReadableCacheBodies
    });
    const output = response?.[0]?.result || [];
    const target = $("cache-previews");
    target.replaceChildren();

    if (!output.length) {
      addEmpty(target, "No readable text cache bodies found. Encrypted or binary cache bodies are not decrypted.");
      return;
    }
    output.forEach(item => {
      const row = addRow(target, item.cache, `${safeDisplayUrl(item.url)} · ${item.contentType} · ${item.characters} chars`);
      addCode(row, item.preview);
    });
  } catch (error) {
    alert(`Cache preview failed: ${error.message}`);
  }
}

// ---------------- Export Report Feature ----------------
function exportAuditReport() {
  if (!latestScan && !latestDns && !captureState) {
    alert("Please click 'Inspect Site' or 'Lookup DNS' first to collect audit data before exporting.");
    return;
  }

  const hostname = activeTab ? new URL(activeTab.url).hostname : "site";
  const dateStr = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);

  // 1. Build structured JSON
  const auditReport = {
    generator: "ScopeLens Site Inspector",
    version: "1.2.0",
    hostname,
    url: activeTab?.url,
    inspectedAt: new Date().toISOString(),
    securityPosture: latestScan ? evaluateSecurityPosture(latestScan, captureState?.documentHeaders || {}) : null,
    detectedTechnologies: latestScan?.technologies || [],
    storageSummary: {
      localStorageKeys: latestScan?.localStorage?.items?.length || 0,
      sessionStorageKeys: latestScan?.sessionStorage?.items?.length || 0,
      cookieCount: latestScan?.cookieNames?.length || 0,
      cacheBuckets: latestScan?.cacheStorage?.length || 0,
      indexedDbDatabases: latestScan?.indexedDb?.databases?.length || 0
    },
    dns: latestDns || null,
    remoteEndpoints: captureState?.items?.slice(0, 100) || [],
    tlsSecurity: captureState?.securityDetails || null
  };

  // Trigger file download
  const blob = new Blob([JSON.stringify(auditReport, null, 2)], { type: "application/json" });
  const downloadUrl = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = downloadUrl;
  a.download = `scopelens-report-${hostname}-${dateStr}.json`;
  a.click();
  URL.revokeObjectURL(downloadUrl);

  // 2. Also copy executive Markdown summary to clipboard
  const sec = auditReport.securityPosture;
  const mdSummary = [
    `# ScopeLens Audit Report: ${hostname}`,
    `*Inspected: ${new Date().toLocaleString()}*`,
    "",
    `## Security Posture Grade: ${sec ? sec.grade : "N/A"} (${sec ? sec.score : 0}/100)`,
    sec ? sec.checks.map(c => `- [${c.passed ? "X" : " "}] **${c.name}**: ${c.value} *(${c.recommendation})*`).join("\n") : "Not evaluated",
    "",
    "## Detected Technologies",
    auditReport.detectedTechnologies.length ? auditReport.detectedTechnologies.map(t => `- **${t.name}** (${t.category}${t.version ? ` v${t.version}` : ""})`).join("\n") : "- None detected",
    "",
    "## Observed Endpoints & Ports",
    `- Total observed responses: ${auditReport.remoteEndpoints.length}`,
    `- Distinct endpoints: ${new Set(auditReport.remoteEndpoints.map(e => e.remoteIp)).size}`,
    `- Observed ports: ${[...new Set(auditReport.remoteEndpoints.map(e => e.remotePort).filter(Boolean))].join(", ") || "none"}`,
    "",
    "---",
    "*Generated by ScopeLens Site Inspector (local-only)*"
  ].join("\n");

  navigator.clipboard.writeText(mdSummary).then(() => {
    showToast("Audit JSON downloaded & Markdown copied to clipboard!");
  }).catch(() => {
    showToast("Audit JSON downloaded!");
  });
}

// ---------------- Tabs & Filtering ----------------
function switchTab(targetTabId) {
  activeTabName = targetTabId;
  document.querySelectorAll(".tab-btn").forEach(btn => {
    btn.classList.toggle("active", btn.dataset.tab === targetTabId);
  });
  document.querySelectorAll(".tab-pane").forEach(pane => {
    pane.classList.toggle("hidden", pane.id !== targetTabId);
    pane.classList.toggle("active", pane.id === targetTabId);
  });
  applyTabSearch();
}

function applyTabSearch() {
  const query = $("tab-search-input").value.trim().toLowerCase();
  const clearBtn = $("clear-search-btn");
  if (clearBtn) clearBtn.classList.toggle("hidden", query.length === 0);

  const activePane = $(activeTabName);
  if (!activePane) return;

  const rows = activePane.querySelectorAll(".data-row, .tech-item, .check-item, table tbody tr, .jwt-card");
  rows.forEach(row => {
    if (!query) {
      row.style.display = "";
      return;
    }
    const text = row.textContent.toLowerCase();
    row.style.display = text.includes(query) ? "" : "none";
  });
}

// ---------------- Event Listeners ----------------
document.querySelectorAll(".tab-btn").forEach(btn => {
  btn.addEventListener("click", () => switchTab(btn.dataset.tab));
});

$("inspect-btn").addEventListener("click", inspectPage);
$("dns-btn").addEventListener("click", lookupDns);
$("capture-btn").addEventListener("click", toggleCapture);
$("export-report-btn").addEventListener("click", exportAuditReport);
$("cache-preview-btn").addEventListener("click", previewCacheBodies);
$("open-dashboard-btn")?.addEventListener("click", async () => {
  try {
    const tab = activeTab || await getActiveTab();
    if (tab?.id) {
      await chrome.storage.session.set({
        lastTargetTab: { id: tab.id, url: tab.url, origin: activeOrigin, title: $("site-title").textContent },
        [`scan_${tab.id}`]: latestScan || null
      });
      chrome.tabs.create({ url: chrome.runtime.getURL(`dashboard.html?tabId=${tab.id}`) });
      return;
    }
  } catch (err) {}
  chrome.tabs.create({ url: chrome.runtime.getURL("dashboard.html") });
});

$("open-sidepanel-btn")?.addEventListener("click", async () => {
  try {
    const tab = activeTab || await getActiveTab();
    if (tab && tab.id) {
      if (chrome.sidePanel?.open) {
        await chrome.sidePanel.open({ tabId: tab.id });
        window.close();
        return;
      }
      await chrome.runtime.sendMessage({ type: "OPEN_SIDEPANEL", tabId: tab.id });
      window.close();
    }
  } catch (err) {
    alert("Side panel could not be opened: " + err.message);
  }
});

$("tab-search-input").addEventListener("input", applyTabSearch);
$("clear-search-btn").addEventListener("click", () => {
  $("tab-search-input").value = "";
  applyTabSearch();
});

chrome.runtime.onMessage.addListener(message => {
  if (message?.type === "CAPTURE_UPDATE" && activeTab && message.tabId === activeTab.id) {
    renderCapture(message.state);
  }
});

// Initialization
(async () => {
  try {
    const tab = await getActiveTab();
    const response = await chrome.runtime.sendMessage({ type: "GET_CAPTURE", tabId: tab.id });
    if (response?.state) renderCapture(response.state);
  } catch (error) {
    $("site-title").textContent = "No inspectable website";
    $("site-url").textContent = error.message;
    ["inspect-btn", "dns-btn", "capture-btn", "export-report-btn"].forEach(id => {
      const el = $(id);
      if (el) el.disabled = true;
    });
    setStatus("Unavailable");
  }
})();
