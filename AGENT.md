# ScopeLens — AI Agent & Developer Architecture Guide (AGENT.md)

> **Audience:** AI Coding Assistants, Autonomous Agents, Security Researchers, and Extension Developers.  
> **Status:** Authoritative Repository Documentation.

---

## 1. System Identity & Mission

**ScopeLens** is an advanced, production-grade Web Security, Network Intelligence, and Site Inspection Platform packaged as a native Chrome / Chromium Extension (Manifest V3, minimum Chrome 116).

### Core Philosophy
1. **100% Local-First & Zero Telemetry:** ScopeLens possesses **no remote backend, no user accounts, no telemetry, and no external AI dependencies**. All parsing, token decoding, vulnerability analysis, and reporting execute strictly within the user's browser sandbox.
2. **Passive Diagnostic Reconnaissance:** The tool discovers what the active target website naturally exposes. **Never implement intrusive exploitation, credential theft, denial-of-service, or arbitrary remote port scanning.**
3. **Mandatory Redaction Before Persistence:** High-entropy credentials, bearer tokens, passwords, private keys, and session cookies are scrubbed (`[REDACTED]`) before data enters local storage, UI displays, logs, or exported reports.
4. **Clean Manifest V3 Architecture:** Built with native ES2022 modules. No fragile external bundlers (Webpack, Vite) are required.

---

## 2. Repository Layout & Anatomy

```
scopelens-extension/
├── manifest.json              # Active MV3 extension manifest
├── background.js              # Background service worker (CDP, DoH, lifecycle)
├── dashboard.html / .js / .css# Master Operations Console (16+ views, SVG graph, Diff)
├── sidepanel.html / .js / .css# Persistent Chrome Side Panel (continuous companion inspection)
├── popup.html / .js / styles.css# Quick-look toolbar popup
├── devtools.html / .js        # DevTools extension entrypoint
├── panel.html / .js           # Dedicated DevTools Network Panel (HAR streams & bodies)
├── package.json               # Scripts, metadata, and dependencies
├── README.md                  # Public user documentation
├── AGENT.md                   # Authoritative AI Agent & Architecture specification
├── icons/                     # Generated extension icons (16, 32, 48, 128 px)
├── manifest/
│   ├── standard.json          # Standard permissions edition (no chrome.debugger)
│   └── deep-capture.json      # Deep capture edition (with chrome.debugger)
├── scripts/
│   ├── switch-manifest.js     # CLI switcher between standard and deep-capture
│   └── package-release.js     # Production release packager (.zip)
├── src/
│   ├── content/
│   │   └── content-script.js  # In-page passive collector (DOM, forms, tech globals)
│   ├── core/
│   │   ├── constants.js       # Severities, confidence ratings, secret regex patterns
│   │   ├── utils.js           # Safe parsing, Base64/UTF-8 decoding, formatting
│   │   ├── redactor.js        # Centralized credential & URL masking engine
│   │   ├── scope-policy.js    # Origin boundary enforcement & host permissions
│   │   ├── persistence.js     # Local-first IndexedDB engine (scopelens_db)
│   │   └── retention.js       # Quota manager (max 10 sessions) & 1-click purge
│   └── modules/
│       ├── ip-network/        # Module A: IP classification, subnet scopes, port tracking
│       ├── dns/               # Module B: DoH query runner, SPF/DMARC, Multi-Resolver, DKIM
│       ├── network/           # Module C & V: Waterfall & WebSocket/SSE streaming
│       ├── tokens/            # Module D: JWT/JWS/JWE decoder & live countdown timer
│       ├── storage/           # Module E: Local/Session storage, Cookie hygiene, CacheStorage
│       ├── tech/              # Module F: 50+ Framework & CMS fingerprinting
│       ├── security/          # Module G, R, S, U: OWASP, TLS, security.txt, Deep CORS
│       ├── api/               # Module H & T: API route abstraction & OpenAPI 3.0 draft generator
│       ├── third-party/       # Module I: Trackers, CDNs, and circular SVG dependency graph
│       ├── performance/       # Module J: Latency waterfall, slow requests, transfer size
│       ├── findings/          # Module K: Smart Findings Engine & deduplication
│       ├── reports/           # Module L: HTML, JSON, CSV, HAR, CycloneDX & SPDX SBOM
│       ├── snapshots/         # Module M: Point-in-time snapshots & differential delta comparison
│       ├── auth/              # Module O: OAuth 2.0 / OIDC flow tracing & PKCE validation
│       ├── dependencies/      # Module P: Source maps & npm package inventory
│       └── leakage/           # Module Q: Server stack traces, debug paths, internal IPs
└── tests/
    ├── runner.js              # Automated Node.js test runner (18 test suites)
    ├── test-utils.js          # Lightweight test assertion helpers
    └── *.test.js              # 18 dedicated unit & regression test suites
```

---

## 3. Manifest V3 & Runtime Constraints

### A. Dual Manifest Architecture
Chromium users have different risk appetites regarding permissions. ScopeLens provides two validated manifest editions:
- **Standard Edition (`manifest/standard.json`):** Requests `["activeTab", "tabs", "scripting", "storage", "sidePanel"]`. Perfect for standard web inspection without security warnings.
- **Deep Capture Edition (`manifest/deep-capture.json`):** Adds `"debugger"` permission to attach the Chrome DevTools Protocol (`Network.enable`) to observe connection-level remote IPs, ports, and TLS handshake details.
- **Switch Command:**
  ```bash
  npm run manifest:standard
  npm run manifest:deep
  ```

### B. Service Worker Suspension Resilience
MV3 background service workers terminate after ~30 seconds of inactivity. In-memory global maps (`const captures = new Map()`) are volatile.
- **Rule:** Never assume in-memory state persists across asynchronous callbacks.
- **Implementation:** Always sync state to `chrome.storage.session` and rehydrate state via `rehydrateCaptures()` on `chrome.runtime.onStartup` and `chrome.runtime.onInstalled`.

### C. DevTools vs. CDP Debugger Conflict
Chromium dictates that opening Chrome DevTools (`F12`) on a tab will automatically terminate an active `chrome.debugger` attachment on that tab.
- **DevTools Panel (`panel.js`):** Operates in **Standard Network Mode** using `chrome.devtools.network.onRequestFinished` (HAR-based).
- **Dashboard / Popup:** Can invoke **Deep Connection Mode** (`chrome.debugger`) when DevTools is closed.

### D. Side Panel Integration (`chrome.sidePanel`)
The Chrome Side Panel API (`chrome.sidePanel.open({ tabId })`) allows continuous companion inspection as users browse and click through pages without closing when focus shifts.

---

## 4. Security & Analysis Modules (Modules A through V)

| Code | Module | Responsibility | Key Classes / Functions |
| :--- | :--- | :--- | :--- |
| **A** | **IP & Network Intelligence** | IPv4/IPv6 classification, private RFC 1918, CGNAT, port tracking. | `analyzeIpIntelligence()`, `classifyIpScope()` |
| **B** | **DNS & Email Security** | DoH (A, AAAA, MX, NS, TXT, CAA, SOA), DNSSEC validation, SPF & DMARC parsers. | `queryDns()`, `MultiResolverService` |
| **C** | **Network Inspector** | DevTools HAR inspection, sanitized response body preview caching. | `panel.js`, `exportToHar()` |
| **D** | **Token & Auth Intel** | JWT header/claims parsing, JWE detection, live expiration countdown timer, `alg: none` warning. | `inventoryTokens()`, `detectTokens()` |
| **E** | **Browser Storage** | LocalStorage, SessionStorage, IndexedDB schema, cookie security flags (HttpOnly, Secure, SameSite). | `auditCookies()`, `analyzeStorageEntry()` |
| **F** | **Tech Fingerprinting** | Detection of 50+ frameworks, CMSs, CDNs, analytics with confidence ratings and evidence. | `fingerprintTechnologies()`, `fingerprintTech()` |
| **G** | **Security Auditor** | OWASP headers (HSTS, CSP, XFO, XCTO, Referrer, Permissions-Policy, COOP, COEP), DOM XSS sinks. | `auditSecurityHeaders()`, `auditDomSecurity()` |
| **H** | **API Discovery** | REST pattern clustering (`/users/{id}`), status distribution, auth header detection. | `analyzeApiTraffic()` |
| **I** | **Trackers & CDNs** | Third-party classification with circular SVG dependency graph. | `analyzeThirdPartyTrackers()`, `renderTrackerGraph()` |
| **J** | **Performance Intel** | Resource distribution, transfer sizes, slow request ranking. | `analyzePerformance()` |
| **K** | **Smart Findings Engine** | Unified vulnerability findings model, deduplication (FNV-1a), severity classification. | `FindingsEngine` |
| **L** | **Reporting & Exports** | Standalone HTML, structured JSON, CSV, HAR 1.2, CycloneDX v1.4 & SPDX 2.3 SBOM. | `buildJsonReport()`, `generateHtmlReport()` |
| **M** | **Snapshots & Diff** | Point-in-time snapshots and differential delta comparisons (A vs. B). | `SnapshotManager` |
| **O** | **Auth Flow Mapper** | OAuth 2.0 / OIDC redirect tracing, PKCE verification, CSRF `state` check, implicit grant check. | `AuthFlowMapper` |
| **P** | **Source Maps & SBOM** | Detection of source maps, extraction of npm dependencies from paths, CycloneDX / SPDX export. | `SourceMapAnalyzer` |
| **Q** | **Data Leakage & Heuristics**| Server stack traces (Node, Python, Java, PHP), internal system paths, private RFC 1918 IPs. | `LeakageAnalyzer` |
| **R** | **TLS & Cert Auditor** | Obsolete TLS (1.0/1.1), certificate validity countdown (<30d, <14d, expired), SAN validation. | `TlsAuditor` |
| **S** | **security.txt Auditor** | RFC 9116 vulnerability disclosure policy validation and expiration check. | `SecurityTxtAuditor` |
| **T** | **OpenAPI 3.0 Generator** | Automatic generation of OpenAPI 3.0.3 Swagger draft schemas from observed API traffic. | `OpenApiGenerator` |
| **U** | **Deep CORS Auditor** | Wildcard with credentials, missing `Vary: Origin` (cache poisoning), null origin, exposed headers. | `CorsAuditor` |
| **V** | **WebSocket & SSE Streams** | Detection of WebSocket upgrades, Server-Sent Events, unencrypted `ws://` on HTTPS origins. | `WebSocketInspector` |

---

## 5. Developer & Agent Workflow Commands

```bash
# 1. Run all 18 automated unit and integration test suites
npm test

# 2. Switch to Standard Manifest (without debugger permission)
npm run manifest:standard

# 3. Switch to Deep Capture Manifest (with debugger permission)
npm run manifest:deep

# 4. Bundle complete production archive (generates scopelens-platform-v2.0.0.zip)
npm run package
```

---

## 6. Rules for Future Code Changes

When maintaining or extending ScopeLens, adhere to these non-negotiable rules:

1. **Keep Tests Passing:** Every module must have a corresponding test file in `tests/*.test.js` registered in `tests/runner.js`. Never break existing tests.
2. **Preserve Privacy & Zero-Telemetry:** Do not add external API calls, analytics, telemetry, or remote logging. All DoH queries must use explicit, user-initiated paths (`https://cloudflare-dns.com/dns-query`).
3. **Always Redact Secrets:** If adding new collectors, views, or exports, pass all data through `src/core/redactor.js`.
4. **No Heavy Build Dependencies:** Do not introduce Webpack, Rollup, or Vite unless explicitly instructed. Keep code cleanly runnable natively in Chromium and Node.js with `"type": "module"`.
5. **Preserve Documentation Integrity:** Maintain existing comments, docstrings, and update `AGENT.md` whenever adding new modules.
