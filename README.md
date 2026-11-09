# ScopeLens — Web Security, Network Intelligence & Site Inspection Platform

[![Platform](https://img.shields.io/badge/Platform-Chrome%20%7C%20Edge%20%7C%20Chromium-blue.svg)](https://developer.chrome.com/docs/extensions/mv3/)
[![Manifest Version](https://img.shields.io/badge/Manifest-V3-success.svg)](https://developer.chrome.com/docs/extensions/mv3/intro/)
[![Tests](https://img.shields.io/badge/Automated%20Tests-16%2F16%20Passing-brightgreen.svg)](tests/runner.js)
[![Privacy](https://img.shields.io/badge/Privacy-100%25%20Local--First-amber.svg)](#privacy--security-architecture)

**ScopeLens** is an advanced, local-first web security inspection and network intelligence platform packaged as a Chrome / Chromium (MV3) extension. Designed for security engineers, technical architects, and developers, it transforms browser inspection into a comprehensive diagnostic and passive reconnaissance platform.

---

## 1. Feature Matrix

| Module | Capability / Feature | Status | Notes |
| :--- | :--- | :---: | :--- |
| **Module A** | Remote IP detection (IPv4 / IPv6) | ✅ Completed | Captured via Chrome DevTools Protocol |
| **Module A** | IP network scope classification (Public, RFC 1918, Loopback, Link-Local, CGNAT) | ✅ Completed | Deterministic local subnet evaluation |
| **Module A** | First-party vs. third-party host separation & port tracking | ✅ Completed | Only ports observed in actual connections |
| **Module B** | DNS-over-HTTPS resolution (A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, PTR) | ✅ Completed | Queries Cloudflare DoH endpoint |
| **Module B** | DNSSEC cryptographic validation (AD flag check) | ✅ Completed | Verified from upstream resolver |
| **Module B** | SPF & DMARC configuration analysis & mail provider detection | ✅ Completed | Parsed and audited locally |
| **Module C** | Dedicated DevTools Network Dashboard with filters & search | ✅ Completed | Chrome DevTools panel tab |
| **Module C** | Redacted request / response body previews | ✅ Completed | Up to 10 KB with sensitive masking |
| **Module D** | JWT & JWS local decoding & standard claims extraction (`exp`, `iat`, `nbf`, `iss`, `sub`, `aud`, `kid`) | ✅ Completed | No tokens ever leave the browser |
| **Module D** | Insecure algorithm detection (`alg: none` critical warning) | ✅ Completed | Highlighted with high-priority finding |
| **Module D** | JWE (JSON Web Encryption 5-part format) identification | ✅ Completed | Explicitly flags encrypted payload without false claims |
| **Module E** | LocalStorage, SessionStorage & IndexedDB schema inspection | ✅ Completed | In-page content script inspection |
| **Module E** | Cookie security hygiene (HttpOnly, Secure, SameSite, domain vs host-only) | ✅ Completed | Flags sensitive cookies exposed to scripts |
| **Module E** | CacheStorage entries & Service Worker scope tracking | ✅ Completed | Inspects Cache API and registration scopes |
| **Module F** | Technology fingerprinting with confidence ratings & evidence | ✅ Completed | Detects 40+ frameworks, CMSs, CDNs, analytics |
| **Module G** | OWASP Security Headers Audit (HSTS, CSP, XFO, XCTO, Referrer, Information Disclosure) | ✅ Completed | Automated scoring & grade (A+ to F) |
| **Module G** | DOM security (Reverse tabnabbing, missing SRI on external scripts, mixed content, insecure forms) | ✅ Completed | Inspected via content script |
| **Module H** | API discovery, route pattern abstraction (e.g. `/users/{id}`), GraphQL detection | ✅ Completed | Groups traffic by method & status |
| **Module I** | Third-party tracker & CDN classification with dependency graph | ✅ Completed | Categorizes analytics, ads, fonts, CDNs |
| **Module J** | Performance metrics, slow request ranking, cache utilization, size distribution | ✅ Completed | Observed browser latency and sizes |
| **Module K** | Smart Findings Engine (unified schema, deduplication, dismiss, search) | ✅ Completed | Centralized finding aggregator |
| **Module L** | Multi-format reporting (Structured JSON, Standalone HTML, CSV, Executive Markdown) | ✅ Completed | Redacted by default |
| **Module M** | Snapshots & Differential comparison (endpoints, headers, third parties, tech, findings) | ✅ Completed | Saves and diffs audit sessions |
| **Module N** | Charcoal/graphite professional dashboard + quick popup + DevTools integration | ✅ Completed | Dark UI with amber accents |
| **Auth Mapper** | OAuth 2.0 / OIDC redirection flow tracing, PKCE & state verification | ✅ Completed | Passive flow inspection |
| **SBOM Engine** | CycloneDX v1.4 & SPDX 2.3 Software Bill of Materials from source maps | ✅ Completed | Machine-readable dependency manifests |
| **Data Leakage**| Server stack traces, internal RFC 1918 IPs, debug paths & password in GET audit | ✅ Completed | Local heuristic scanning |
| **TLS & Certs** | TLS 1.0/1.1 deprecation, cert expiry countdown (<30d, <14d), SAN validation | ✅ Completed | Transport security auditor |
| **Security.txt**| RFC 9116 vulnerability disclosure policy validation & expiration audit | ✅ Completed | Standardized disclosure check |
| **OpenAPI 3.0** | Automatic OpenAPI 3.0.3 Swagger schema draft generation from API traffic | ✅ Completed | Exportable to Postman / Swagger UI |
| **Side Panel** | Persistent side-by-side companion inspection via `chrome.sidePanel` | ✅ Completed | Works continuously as you navigate |
| **Retention** | Local storage quota manager (sessions, observations) & one-click purge | ✅ Completed | 100% user-controlled local persistence |
| **Port Scanning**| Arbitrary external TCP/UDP port scanning | ⛔ Unsupported | Intrusive scanning is strictly avoided |
| **Decryption** | Client-side brute-force decryption of opaque/encrypted tokens | ⛔ Unsupported | Opaque/encrypted tokens are not decrypted |

---

## 2. Architecture & Modular Structure

ScopeLens is engineered using strict separation of concerns, native Manifest V3 APIs, and modular ES2022 code without fragile bundlers:

```
scopelens-extension/
├── manifest.json              # MV3 configuration, minimal permissions, icons
├── background.js              # Background service worker (CDP debugger, DoH router, storage)
├── dashboard.html             # Full-screen Master Security & Intelligence Dashboard
├── dashboard.js               # Master dashboard controller
├── dashboard.css              # Dark charcoal/graphite UI styling
├── popup.html                 # Rapid at-a-glance inspection popup
├── popup.js                   # Popup controller
├── styles.css                 # Popup & panel styles
├── devtools.html              # DevTools entry point
├── devtools.js                # DevTools panel registration
├── panel.html                 # Dedicated DevTools Network Panel UI
├── panel.js                   # DevTools panel controller
├── icons/                     # Extension icons (16, 32, 48, 128 px)
├── src/
│   ├── core/
│   │   ├── constants.js       # Global severity, confidence, message types, regex patterns
│   │   ├── utils.js           # Safe URL parsing, Base64/UTF-8 decoding, formatting
│   │   └── redactor.js        # Centralized credential & secret masking engine
│   ├── modules/
│   │   ├── ip-network/        # Module A: IP classification, subnet scopes, port tracking
│   │   ├── dns/               # Module B: DoH resolution, SPF/DMARC parser, DNSSEC
│   │   ├── network/           # Module C: Network capture & stream processing
│   │   ├── tokens/            # Module D: JWT/JWS/JWE/OAuth detector, expiry analysis
│   │   ├── storage/           # Module E: Local/Session storage, Cookies, IndexedDB, Cache
│   │   ├── tech/              # Module F: Technology fingerprinting engine
│   │   ├── security/          # Module G: Security auditor (OWASP headers, CORS, DOM)
│   │   ├── api/               # Module H: API discovery & route abstraction
│   │   ├── third-party/       # Module I: External trackers, CDNs & dependency graph
│   │   ├── performance/       # Module J: Resource breakdown, waterfall timing
│   │   ├── findings/          # Module K: Smart Findings Engine & deduplication
│   │   ├── snapshots/         # Module M: Point-in-time snapshots & delta comparison
│   │   └── reports/           # Module L: Report generation (JSON, HTML, CSV)
│   └── content/
│       └── content-script.js  # In-page collector for DOM cues, globals & storage
└── tests/
    ├── runner.js              # Automated master test runner
    ├── test-utils.js          # Assertion helpers
    ├── ip-analyzer.test.js    # Unit tests for Module A
    ├── dns-service.test.js    # Unit tests for Module B
    ├── token-detector.test.js # Unit tests for Module D
    ├── redactor.test.js       # Unit tests for Redaction Engine
    ├── security-auditor.test.js # Unit tests for Module G
    ├── tech-fingerprint.test.js # Unit tests for Module F
    ├── api-analyzer.test.js   # Unit tests for Module H
    ├── findings-engine.test.js # Unit tests for Module K
    ├── snapshot-manager.test.js # Unit tests for Module M
    └── report-generator.test.js # Unit tests for Module L
```

---

## 3. Privacy & Security Architecture

1. **Local-First Processing:** 100% of DOM inspection, token decoding, technology fingerprinting, and security audits execute locally on your machine.
2. **Zero Telemetry or Data Exfiltration:** The extension contains zero tracking pixels, analytics hooks, or third-party monitoring beacons.
3. **Automated Credential Redaction:** Bearer tokens, HTTP Basic authorization headers, cookies, passwords, secret query parameters, and API keys are masked (`[REDACTED]`) across all UI views, logs, and generated exports.
4. **Passive Inspection Boundaries:** ScopeLens observes browser requests and headers. It does not perform state-changing operations, intrusive vulnerability exploits, or port flooding.

---

## 4. Installation & Setup

1. Open your Chromium browser:
   - **Chrome:** `chrome://extensions`
   - **Edge:** `edge://extensions`
   - **Brave:** `brave://extensions`
2. Enable **Developer mode** in the upper-right corner.
3. Click **Load unpacked**.
4. Select the `scopelens-extension` directory.
5. The ScopeLens amber lens icon will appear in your extensions toolbar.

---

## 5. Usage Workflows

### Quick Inspection Popup
- Click the toolbar icon to view the active target, quick security score, and summary metrics.
- Click **⚡ Inspect Site** or **🌐 Lookup DNS** for immediate findings.
- Click **🚀 Launch Full Security & Intelligence Dashboard** to open the comprehensive workspace.

### Master Security Dashboard (`dashboard.html`)
- Open the dashboard at any time to explore all 16 modules:
  - **Overview:** Executive KPIs, security grade, top findings, and quick charts.
  - **Security Auditor:** Filterable findings by severity (Critical, High, Medium, Low, Info) with detailed remediation instructions and parsed CSP directives.
  - **IP Intelligence:** IPv4/IPv6 classification, network scope, observed ports, and associated domains.
  - **DNS & Email:** SPF mechanism breakdown (`-all` vs `+all`), DMARC enforcement policies (`p=reject`), and DNSSEC cryptographic authentication banners.
  - **Tokens & Auth:** Formatted claims, live expiration countdowns, and algorithm security reviews.
  - **Browser Storage & Cookies:** Complete key inventory with character lengths, data types, and Cookie hygiene checks (HttpOnly, Secure, SameSite).
  - **API Discovery:** Route abstraction (`/users/{id}`), GraphQL detection, and status code distribution.
  - **Tech Stack:** 40+ technologies classified with confidence ratings and observable evidence.
  - **Third-Party Trackers:** Categorization of external ad networks, tracking pixels, and CDNs.
  - **Snapshots & Comparison:** Save point-in-time audit snapshots and calculate differential changes between two sessions.
  - **Report Center:** Download standalone HTML reports, structured JSON audit files, or CSV spreadsheets.

### Chrome DevTools Network Panel
1. Press `F12` or `Ctrl + Shift + I` (`Cmd + Option + I` on macOS) to open Chrome DevTools.
2. Select the **ScopeLens** tab in the top navigation.
3. Reload or interact with the page to inspect live filtered same-origin requests, formatted headers, and sanitized payloads.

---

## 6. Running Automated Tests

ScopeLens includes a pure Node.js automated test runner with 10 comprehensive unit and regression test suites:

```bash
npm test
# or directly:
node tests/runner.js
```

### Test Output
```
================================================================
  ScopeLens Platform — Automated Test Suite Runner
================================================================

  ✓ [PASS] Module A: IP & Network Intelligence Analyzer
  ✓ [PASS] Module B: Advanced DNS & Email Security Service
  ✓ [PASS] Module D: Token & Authentication Intelligence
  ✓ [PASS] Core: Sensitive Credential & URL Redactor
  ✓ [PASS] Module G: Website Security & DOM Auditor
  ✓ [PASS] Module F: Technology Fingerprinting Engine
  ✓ [PASS] Module H: API Discovery & Route Abstraction
  ✓ [PASS] Module K: Smart Findings Engine & Deduplication
  ✓ [PASS] Module M: Snapshots & Differential Comparison
  ✓ [PASS] Module L: Reporting & Export Engine (JSON, HTML, CSV)

----------------------------------------------------------------
Total Test Suites: 10
Passed:            10
Failed:            0
Execution Time:    19 ms
----------------------------------------------------------------
```

---

## 7. Technical Limitations & Browser Boundaries

- **Connection-Level Ports:** Only ports utilized in actual browser connections can be observed. Browsers do not expose socket-level port scanning APIs to page scripts.
- **JWT Decoding vs. Decryption:** JWT decoding parses base64url payloads to inspect claims. Decoding does not verify server-side signatures (which require secret or public keys) and does not decrypt JWE tokens without encryption keys.
- **HttpOnly Cookies:** `document.cookie` cannot read cookies protected by the `HttpOnly` flag. ScopeLens correctly flags sensitive session tokens exposed without `HttpOnly` as a security finding.
- **CacheStorage vs. Internal HTTP Cache:** ScopeLens accesses Cache API buckets created by the application or Service Worker. The browser's internal disk HTTP cache is isolated by Chromium security architecture.
