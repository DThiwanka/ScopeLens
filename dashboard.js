/**
 * ScopeLens Platform - Master Dashboard Controller
 * Connects all 16 security, intelligence, and analysis modules into a unified operations center.
 */

import { analyzeIpIntelligence } from './src/modules/ip-network/ip-analyzer.js';
import { queryDns } from './src/modules/dns/dns-service.js';
import { inventoryTokens, parseToken } from './src/modules/tokens/token-detector.js';
import { auditCookies, analyzeStorageEntry, formatStorageQuota } from './src/modules/storage/storage-inspector.js';
import { fingerprintTechnologies } from './src/modules/tech/tech-fingerprint.js';
import { auditSecurityHeaders, auditDomSecurity } from './src/modules/security/security-auditor.js';
import { analyzeApiTraffic } from './src/modules/api/api-analyzer.js';
import { analyzeThirdPartyTrackers } from './src/modules/third-party/tracker-analyzer.js';
import { analyzePerformance } from './src/modules/performance/perf-analyzer.js';
import { FindingsEngine } from './src/modules/findings/findings-engine.js';
import { SnapshotManager } from './src/modules/snapshots/snapshot-manager.js';
import { buildJsonReport, generateHtmlReport, exportToCsv, exportToHar } from './src/modules/reports/report-generator.js';
import { sanitizeUrl, sanitizeHeaders, sanitizeString } from './src/core/redactor.js';
import { formatBytes } from './src/core/utils.js';
import { runInPageCollection } from './src/content/content-script.js';
import { AuthFlowMapper } from './src/modules/auth/auth-flow-mapper.js';
import { SourceMapAnalyzer } from './src/modules/dependencies/sourcemap-analyzer.js';
import { LeakageAnalyzer } from './src/modules/leakage/leakage-analyzer.js';
import { RetentionManager } from './src/core/retention.js';
import { localDb } from './src/core/persistence.js';
import { TlsAuditor } from './src/modules/security/tls-auditor.js';
import { SecurityTxtAuditor } from './src/modules/security/security-txt-auditor.js';
import { OpenApiGenerator } from './src/modules/api/openapi-generator.js';
import { CorsAuditor } from './src/modules/security/cors-auditor.js';
import { WebSocketInspector } from './src/modules/network/websocket-inspector.js';

// State Management
const state = {
  activeTab: null,
  activeOrigin: '',
  activeHostname: '',
  pageData: null,
  captureData: null,
  dnsData: null,
  findingsEngine: new FindingsEngine(),
  snapshotManager: new SnapshotManager(),
  authFlowMapper: new AuthFlowMapper(),
  sourceMapAnalyzer: new SourceMapAnalyzer(),
  leakageAnalyzer: new LeakageAnalyzer(),
  tlsAuditor: new TlsAuditor(),
  securityTxtAuditor: new SecurityTxtAuditor(),
  corsAuditor: new CorsAuditor(),
  webSocketInspector: new WebSocketInspector(),
  activeView: 'view-overview'
};

const retentionManager = new RetentionManager(localDb);

const $ = id => document.getElementById(id);

function showToast(message) {
  const toast = $('toast');
  if (!toast) return;
  toast.textContent = message;
  toast.classList.remove('hidden');
  setTimeout(() => toast.classList.add('hidden'), 2200);
}

// --- Target Discovery & Binding ---
function populateTargetDropdown(inspectableTabs, selectedId) {
  const select = $('target-tab-select');
  if (!select) return;

  select.replaceChildren();
  if (!inspectableTabs || !inspectableTabs.length) {
    select.classList.add('hidden');
    return;
  }

  inspectableTabs.forEach(t => {
    const opt = document.createElement('option');
    opt.value = String(t.id);
    let host = 'Target';
    try { host = new URL(t.url).hostname; } catch {}
    const pageTitle = t.title ? ` (${t.title.slice(0, 30)})` : '';
    opt.textContent = `${host}${pageTitle}`;
    if (String(t.id) === String(selectedId)) {
      opt.selected = true;
    }
    select.append(opt);
  });

  select.classList.remove('hidden');

  select.onchange = async () => {
    const chosenId = Number(select.value);
    const chosenTab = inspectableTabs.find(t => t.id === chosenId);
    if (chosenTab) {
      await bindTargetTab(chosenTab);
      executeFullAudit();
    }
  };
}

async function bindTargetTab(targetTab) {
  state.activeTab = targetTab;
  let url;
  try {
    url = new URL(targetTab.url);
  } catch {
    url = { origin: '', hostname: targetTab.url || 'unknown', protocol: 'https:' };
  }

  state.activeOrigin = url.origin;
  state.activeHostname = url.hostname;

  $('target-domain').textContent = url.hostname;
  $('target-url').textContent = targetTab.url;
  $('target-url').title = targetTab.url;

  const protoBadge = $('target-protocol-badge');
  protoBadge.textContent = url.protocol === 'https:' ? 'HTTPS' : 'HTTP';
  protoBadge.className = `badge-mini ${url.protocol === 'https:' ? 'badge-success' : 'badge-danger'}`;

  // Sync dropdown if available
  const select = $('target-tab-select');
  if (select && select.value !== String(targetTab.id)) {
    select.value = String(targetTab.id);
  }

  // Check for cached session scan
  try {
    const sess = await chrome.storage.session.get([`scan_${targetTab.id}`, `capture_${targetTab.id}`]);
    if (sess?.[`scan_${targetTab.id}`]) {
      state.pageData = sess[`scan_${targetTab.id}`];
    }
    if (sess?.[`capture_${targetTab.id}`]) {
      state.captureData = sess[`capture_${targetTab.id}`];
      $('capture-status-badge').textContent = state.captureData.running ? 'Capturing' : 'Passive';
    } else {
      const resp = await chrome.runtime.sendMessage({ type: 'GET_CAPTURE', tabId: targetTab.id });
      if (resp?.state) {
        state.captureData = resp.state;
        $('capture-status-badge').textContent = resp.state.running ? 'Capturing' : 'Passive';
      }
    }
  } catch {}
}

async function discoverTarget() {
  const params = new URLSearchParams(window.location.search);
  const paramTabId = params.get('tabId');

  // Query all tabs
  let inspectableTabs = [];
  try {
    const allTabs = await chrome.tabs.query({});
    inspectableTabs = allTabs.filter(t => t.url && /^https?:/.test(t.url) && !t.url.startsWith('chrome-extension://'));
  } catch {}

  let targetTab = null;

  // 1. Try URL query parameter tabId
  if (paramTabId) {
    targetTab = inspectableTabs.find(t => t.id === Number(paramTabId)) || null;
    if (!targetTab) {
      try {
        const tab = await chrome.tabs.get(Number(paramTabId));
        if (tab?.url && /^https?:/.test(tab.url)) {
          targetTab = tab;
          inspectableTabs.unshift(tab);
        }
      } catch {}
    }
  }

  // 2. Try chrome.storage.session lastTargetTab
  if (!targetTab) {
    try {
      const sess = await chrome.storage.session.get('lastTargetTab');
      if (sess?.lastTargetTab?.id) {
        targetTab = inspectableTabs.find(t => t.id === sess.lastTargetTab.id) || null;
      }
    } catch {}
  }

  // 3. Fallback to any active or first inspectable website tab
  if (!targetTab && inspectableTabs.length > 0) {
    targetTab = inspectableTabs[0];
  }

  // Populate dropdown
  populateTargetDropdown(inspectableTabs, targetTab ? targetTab.id : null);

  if (targetTab) {
    await bindTargetTab(targetTab);
    return true;
  }

  // If literally no website tabs are open
  $('target-domain').textContent = 'No website tabs open';
  $('target-url').textContent = 'Open any website (e.g. https://example.com) and reload or select it here.';
  $('target-protocol-badge').textContent = 'None';
  $('target-protocol-badge').className = 'badge-mini badge-neutral';
  return false;
}

// --- Full Audit Execution ---
async function executeFullAudit() {
  if (!state.activeTab?.id) {
    const found = await discoverTarget();
    if (!found) {
      alert('No inspectable website tab found. Please open any website (e.g. https://example.com) in your browser and click Run Full Audit.');
      return;
    }
  }

  $('btn-run-audit').innerHTML = '<span class="btn-icon">⏳</span> Auditing…';
  $('btn-run-audit').disabled = true;

  try {
    // 1. In-page DOM & storage collection
    let inPageData = null;
    try {
      const results = await chrome.scripting.executeScript({
        target: { tabId: state.activeTab.id },
        func: runInPageCollection
      });
      inPageData = results?.[0]?.result || null;
    } catch (err) {
      // In case executeScript fails (e.g. transient), check cached scan
      const sess = await chrome.storage.session.get(`scan_${state.activeTab.id}`);
      inPageData = sess?.[`scan_${state.activeTab.id}`] || null;
      if (!inPageData) {
        throw new Error(`Unable to inspect tab: ${err.message}. Ensure the target tab is not an internal browser page.`);
      }
    }

    state.pageData = inPageData;
    if (!state.pageData) throw new Error('Page inspection did not return data. Ensure tab is accessible.');

    // 2. Refresh background capture
    const captureResp = await chrome.runtime.sendMessage({ type: 'GET_CAPTURE', tabId: state.activeTab.id });
    if (captureResp?.state) state.captureData = captureResp.state;

    // 3. Clear and re-populate Findings Engine
    state.findingsEngine.clear();

    // Security Headers & DOM Audit
    const headerFindings = auditSecurityHeaders(state.pageData.headers, state.activeTab.url);
    const domFindings = auditDomSecurity(state.pageData.domSecurity, state.activeTab.url);
    state.findingsEngine.ingest(headerFindings, 'SecurityAuditor');
    state.findingsEngine.ingest(domFindings, 'DOMSecurity');

    // TLS Handshake Audit
    if (state.captureData?.securityDetails) {
      const tlsFindings = state.tlsAuditor.auditTls(state.captureData.securityDetails, state.activeHostname);
      state.findingsEngine.ingest(tlsFindings, 'TLSAuditor');
    }

    // RFC 9116 security.txt Vulnerability Disclosure Policy
    try {
      const secTxtResult = await state.securityTxtAuditor.probeSecurityTxt(state.activeOrigin);
      state.securityTxt = secTxtResult;
      if (secTxtResult.findings?.length) {
        state.findingsEngine.ingest(secTxtResult.findings, 'SecurityTxtAuditor');
      }
    } catch {}

    // Storage Tokens Inventory
    const storageEntries = [
      ...(state.pageData.storage?.localStorage?.items || []),
      ...(state.pageData.storage?.sessionStorage?.items || [])
    ];
    const tokens = inventoryTokens(storageEntries);
    state.tokens = tokens;

    tokens.forEach(tok => {
      if (tok.isWeakAlg) {
        state.findingsEngine.ingest({
          id: 'TOK-ALG-NONE',
          category: 'Authentication',
          title: 'Unsigned JWT Token (alg: none)',
          description: 'A JWT with alg: none was detected in browser storage. Token signatures are not verified.',
          severity: 'CRITICAL',
          confidence: 'CONFIRMED',
          evidence: `Source: ${tok.source}`,
          affectedResource: tok.source,
          remediation: 'Reject tokens with alg: none on server verification and use asymmetric signatures.'
        }, 'TokenDetector');
      }
      if (tok.timing?.expiry?.status === 'expired') {
        state.findingsEngine.ingest({
          id: 'TOK-EXPIRED',
          category: 'Authentication',
          title: 'Expired JWT Token Retained in Web Storage',
          description: `Token expired ${tok.timing.expiry.label}. Stale session credentials should be cleared.`,
          severity: 'LOW',
          confidence: 'CONFIRMED',
          evidence: `Source: ${tok.source}`,
          affectedResource: tok.source,
          remediation: 'Purge expired authentication tokens from localStorage upon expiration.'
        }, 'TokenDetector');
      }
    });

    // Tech Fingerprinting
    state.technologies = fingerprintTechnologies(state.pageData.techContext);

    // IP Intelligence & Trackers from captured traffic
    const networkItems = state.captureData?.items || [];
    state.ipSummary = analyzeIpIntelligence(networkItems, state.activeOrigin);
    state.apiSummary = analyzeApiTraffic(networkItems);
    state.thirdPartySummary = analyzeThirdPartyTrackers(networkItems, state.activeOrigin);
    state.perfSummary = analyzePerformance(networkItems, state.activeOrigin);

    // Cookies Audit
    state.cookiesSummary = auditCookies((state.pageData.storage?.cookieNames || []).map(name => ({ name })));

    // Sensitive Data Leakage & Form Auditing
    state.leakageAnalyzer = new LeakageAnalyzer();
    if (state.pageData?.dom?.forms) {
      const formFindings = state.leakageAnalyzer.auditForms(state.pageData.dom.forms, state.activeOrigin);
      formFindings.forEach(f => state.findingsEngine.ingest(f, 'LeakageAnalyzer'));
    }
    if (state.pageData?.headers) {
      const headerLeaks = state.leakageAnalyzer.auditHeaders(state.pageData.headers);
      headerLeaks.forEach(f => state.findingsEngine.ingest(f, 'LeakageAnalyzer'));
    }

    // Auth & OAuth Flow Mapper
    state.authFlowMapper = new AuthFlowMapper();
    networkItems.forEach(item => {
      state.authFlowMapper.inspectTransaction(item);
    });
    const authWarnings = state.authFlowMapper.getAllWarnings();
    authWarnings.forEach(w => state.findingsEngine.ingest(w, 'AuthFlowMapper'));

    // Source Map & Dependency Analyzer
    state.sourceMapAnalyzer = new SourceMapAnalyzer();
    const scripts = state.pageData?.dom?.scripts || [];
    scripts.forEach(s => {
      state.sourceMapAnalyzer.detectSourceMap({ url: s.src });
    });

    // Deep CORS & Cache Poisoning Audit
    if (state.pageData?.headers) {
      const corsFindings = state.corsAuditor.auditCors(state.pageData.headers, state.activeTab.url, state.activeOrigin);
      corsFindings.forEach(f => state.findingsEngine.ingest(f, 'CORSAuditor'));
    }

    // WebSocket & SSE Stream Inspection
    state.streamSummary = state.webSocketInspector.inspectStreams(networkItems, state.activeOrigin);
    state.streamSummary.findings.forEach(f => state.findingsEngine.ingest(f, 'WebSocketInspector'));

    // Update settings storage stats
    updateSettingsStorageStats();

    // Render All Views
    renderOverview();
    renderSecurityView();
    renderIpView();
    renderTokensView();
    renderStorageView();
    renderCookiesView();
    renderCacheView();
    renderApiView();
    renderTechView();
    renderTrackersView();
    renderPerformanceView();

    showToast('Full security & intelligence audit completed!');
  } catch (err) {
    alert(`Audit Error: ${err.message}`);
  } finally {
    $('btn-run-audit').innerHTML = '<span class="btn-icon">⚡</span> Run Full Audit';
    $('btn-run-audit').disabled = false;
  }
}

// --- Rendering Modules ---
function renderOverview() {
  const stats = state.findingsEngine.getStatistics();
  $('kpi-findings').textContent = stats.total;
  $('kpi-findings-sub').textContent = `${stats.critical} critical · ${stats.high} high · ${stats.medium} med`;

  // Grade calculation
  let grade = 'A+';
  if (stats.critical > 0) grade = 'F';
  else if (stats.high > 1) grade = 'D';
  else if (stats.high === 1 || stats.medium > 2) grade = 'C';
  else if (stats.medium > 0) grade = 'B';
  else if (stats.low > 2) grade = 'A';

  $('kpi-grade').textContent = grade;
  $('kpi-grade-sub').textContent = `${stats.total} total issue(s) identified`;

  $('kpi-endpoints').textContent = state.ipSummary?.distinctIps || 0;
  $('kpi-endpoints-sub').textContent = `${state.ipSummary?.ipv4Count || 0} IPv4 · ${state.ipSummary?.ipv6Count || 0} IPv6`;

  $('kpi-third-parties').textContent = state.thirdPartySummary?.distinctThirdPartyDomains || 0;
  $('kpi-third-parties-sub').textContent = `${state.thirdPartySummary?.totalThirdPartyRequests || 0} external requests`;

  // Top Findings Stack
  const topFindings = state.findingsEngine.query().slice(0, 5);
  const fContainer = $('overview-findings-list');
  fContainer.replaceChildren();

  if (!topFindings.length) {
    fContainer.innerHTML = '<div class="empty">No security findings recorded. Click Run Full Audit.</div>';
  } else {
    topFindings.forEach(f => {
      const card = document.createElement('div');
      card.className = `finding-card severity-${f.severity}`;
      card.innerHTML = `
        <div class="finding-body">
          <div class="finding-head">
            <span class="finding-title">${f.title}</span>
            <span class="badge-mini badge-${f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'danger' : (f.severity === 'MEDIUM' ? 'warn' : 'neutral')}">${f.severity}</span>
          </div>
          <div class="finding-desc">${f.description}</div>
          <div class="finding-rec">Remediation: ${f.remediation || 'Review configuration.'}</div>
        </div>
      `;
      fContainer.append(card);
    });
  }

  // Tech Badge Grid
  const techContainer = $('overview-tech-grid');
  techContainer.replaceChildren();
  if (!state.technologies?.length) {
    techContainer.innerHTML = '<div class="empty">No technologies fingerprinted.</div>';
  } else {
    state.technologies.slice(0, 12).forEach(t => {
      const el = document.createElement('div');
      el.className = 'tech-item';
      el.innerHTML = `<span class="tech-name">${t.name}</span> <span class="muted" style="font-size: 10px;">${t.version ? `(${t.version})` : ''} · ${t.category}</span>`;
      techContainer.append(el);
    });
  }

  // Observed Endpoints Table
  const endTable = $('overview-endpoints-table');
  endTable.replaceChildren();
  const endpoints = state.ipSummary?.endpoints || [];
  if (!endpoints.length) {
    endTable.innerHTML = '<div class="empty">No connections observed. Start CDP Capture or reload page.</div>';
  } else {
    const table = document.createElement('table');
    table.innerHTML = `
      <thead>
        <tr>
          <th>Remote IP</th>
          <th>Type / Scope</th>
          <th>Ports</th>
          <th>Requests</th>
        </tr>
      </thead>
      <tbody>
        ${endpoints.slice(0, 6).map(e => `
          <tr>
            <td><code>${e.ip}</code></td>
            <td>${e.type} (${e.scope})</td>
            <td>${e.ports.join(', ') || '—'}</td>
            <td>${e.requestCount}</td>
          </tr>
        `).join('')}
      </tbody>
    `;
    endTable.append(table);
  }

  // Trackers breakdown
  const trContainer = $('overview-trackers-chart');
  trContainer.replaceChildren();
  const categories = state.thirdPartySummary?.categoryCounts || {};
  if (!Object.keys(categories).length) {
    trContainer.innerHTML = '<div class="empty">No third-party domains observed.</div>';
  } else {
    const list = document.createElement('div');
    list.style.display = 'flex';
    list.style.flexDirection = 'column';
    list.style.gap = '6px';
    for (const [cat, count] of Object.entries(categories)) {
      const row = document.createElement('div');
      row.style.display = 'flex';
      row.style.justifyContent = 'space-between';
      row.style.fontSize = '11px';
      row.innerHTML = `<span>${cat}</span><span style="font-weight: 700; color: var(--amber);">${count} requests</span>`;
      list.append(row);
    }
    trContainer.append(list);
  }
}

function renderSecurityView(filter = 'all') {
  const container = $('security-findings-container');
  container.replaceChildren();

  const queryFilter = filter === 'all' ? {} : { severity: filter };
  const findings = state.findingsEngine.query(queryFilter);
  $('sec-findings-count').textContent = `${findings.length} finding(s)`;

  if (!findings.length) {
    container.innerHTML = '<div class="empty">No findings match this filter.</div>';
    return;
  }

  findings.forEach(f => {
    const card = document.createElement('div');
    card.className = `finding-card severity-${f.severity}`;
    card.innerHTML = `
      <div class="finding-body">
        <div class="finding-head">
          <span class="finding-title">${f.title}</span>
          <span class="badge-mini badge-${f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'danger' : (f.severity === 'MEDIUM' ? 'warn' : 'neutral')}">${f.severity}</span>
        </div>
        <div class="finding-desc">${f.description}</div>
        <div class="finding-meta">Resource: ${f.affectedResource || 'Origin'} | Category: ${f.category}</div>
        <div class="finding-meta" style="color: var(--muted);">Evidence: ${f.evidence || 'N/A'}</div>
        <div class="finding-rec">Remediation: ${f.remediation || 'Review configuration.'}</div>
      </div>
    `;
    container.append(card);
  });

  // CSP Details
  const cspBox = $('sec-csp-parsed');
  cspBox.replaceChildren();
  const rawCsp = state.pageData?.headers?.['content-security-policy'];
  if (rawCsp) {
    $('sec-csp-status').textContent = 'Configured';
    const pre = document.createElement('pre');
    pre.className = 'code-box';
    pre.textContent = rawCsp.split(';').map(p => p.trim()).filter(Boolean).join('\n');
    cspBox.append(pre);
  } else {
    $('sec-csp-status').textContent = 'Not configured';
    cspBox.innerHTML = '<div class="empty">No Content-Security-Policy header received for active document.</div>';
  }
}

function renderIpView() {
  const wrap = $('ip-endpoints-table-wrap');
  wrap.replaceChildren();
  const endpoints = state.ipSummary?.endpoints || [];
  $('ip-count-badge').textContent = `${endpoints.length} unique IP(s)`;

  if (!endpoints.length) {
    wrap.innerHTML = '<div class="empty">No remote IP endpoints observed yet. Click Start CDP Capture.</div>';
    return;
  }

  const table = document.createElement('table');
  table.innerHTML = `
    <thead>
      <tr>
        <th>Remote IP</th>
        <th>Type</th>
        <th>Network Classification</th>
        <th>Observed Ports</th>
        <th>Associated Hosts</th>
        <th>Requests</th>
      </tr>
    </thead>
    <tbody>
      ${endpoints.map(e => `
        <tr>
          <td><code>${e.ip}</code></td>
          <td>${e.type}</td>
          <td><span class="badge-mini ${e.isPublic ? 'badge-neutral' : 'badge-warn'}">${e.scope}</span></td>
          <td>${e.ports.join(', ') || '—'}</td>
          <td>${e.hosts.join(', ') || '—'}</td>
          <td>${e.requestCount}</td>
        </tr>
      `).join('')}
    </tbody>
  `;
  wrap.append(table);
}

function renderTokensView() {
  const container = $('tokens-list-container');
  container.replaceChildren();
  const tokens = state.tokens || [];
  $('tokens-count-badge').textContent = `${tokens.length} token(s)`;

  if (!tokens.length) {
    container.innerHTML = '<div class="empty">No tokens or credentials discovered in accessible storage or cookies.</div>';
    return;
  }

  tokens.forEach(tok => {
    const card = document.createElement('div');
    card.className = 'panel';
    card.style.marginBottom = '12px';

    const top = document.createElement('div');
    top.className = 'panel-header';
    top.innerHTML = `
      <div>
        <strong>${tok.type}</strong> · <span class="muted">${tok.source}</span>
      </div>
      <span class="badge-mini ${tok.isWeakAlg ? 'badge-danger' : (tok.timing?.expiry?.status === 'active' ? 'badge-success' : 'badge-warn')}">
        ${tok.timing?.expiry?.label || tok.algorithm || 'Secret'}
      </span>
    `;

    const code = document.createElement('pre');
    code.className = 'code-box';
    code.textContent = JSON.stringify({
      type: tok.type,
      algorithm: tok.algorithm,
      algorithmStatus: tok.algorithmMeta?.status || 'N/A',
      claims: tok.claims || {},
      payload: tok.payload || '[ENCRYPTED / MASKED]'
    }, null, 2);

    card.append(top, code);
    container.append(card);
  });
}

function renderStorageView() {
  const localTable = $('storage-local-table');
  const sessionTable = $('storage-session-table');
  const idbContainer = $('storage-idb-container');

  localTable.replaceChildren();
  sessionTable.replaceChildren();
  idbContainer.replaceChildren();

  const localItems = state.pageData?.storage?.localStorage?.items || [];
  const sessionItems = state.pageData?.storage?.sessionStorage?.items || [];
  const dbs = state.pageData?.storage?.indexedDb?.databases || [];

  $('storage-local-count').textContent = `${localItems.length} keys`;
  $('storage-session-count').textContent = `${sessionItems.length} keys`;
  $('storage-idb-count').textContent = `${dbs.length} DBs`;

  const makeTable = items => {
    if (!items.length) return '<div class="empty">No entries found.</div>';
    return `
      <table>
        <thead><tr><th>Key</th><th>Characters</th><th>Data Type</th></tr></thead>
        <tbody>
          ${items.map(i => {
            const ana = analyzeStorageEntry(i.key, i.value);
            return `<tr><td><code>${i.key}</code></td><td>${ana.charLength}</td><td>${ana.classification}</td></tr>`;
          }).join('')}
        </tbody>
      </table>
    `;
  };

  localTable.innerHTML = makeTable(localItems);
  sessionTable.innerHTML = makeTable(sessionItems);

  if (!dbs.length) {
    idbContainer.innerHTML = '<div class="empty">No IndexedDB databases found on this origin.</div>';
  } else {
    dbs.forEach(db => {
      const row = document.createElement('div');
      row.style.padding = '8px 0';
      row.style.borderBottom = '1px solid var(--border)';
      row.innerHTML = `<strong>${db.name}</strong> (Version: ${db.version ?? '?'}) · Stores: <code>${db.stores.join(', ') || 'none'}</code>`;
      idbContainer.append(row);
    });
  }
}

function renderCookiesView() {
  const wrap = $('cookies-table-wrap');
  wrap.replaceChildren();
  const cookies = state.cookiesSummary?.cookies || [];
  $('cookies-count-badge').textContent = `${cookies.length} cookie(s)`;

  if (!cookies.length) {
    wrap.innerHTML = '<div class="empty">No cookies visible in document.cookie (HttpOnly cookies protected from script access).</div>';
    return;
  }

  const table = document.createElement('table');
  table.innerHTML = `
    <thead><tr><th>Name</th><th>Domain / Scope</th><th>SameSite</th><th>Secure</th><th>HttpOnly</th><th>Security Note</th></tr></thead>
    <tbody>
      ${cookies.map(c => `
        <tr>
          <td><code>${c.name}</code></td>
          <td>${c.domain}</td>
          <td>${c.sameSite}</td>
          <td>${c.isSecure ? '✓' : '✗'}</td>
          <td>${c.isHttpOnly ? '✓' : '✗ (exposed)'}</td>
          <td style="color: var(--amber);">${c.issues.join(', ') || 'Clean'}</td>
        </tr>
      `).join('')}
    </tbody>
  `;
  wrap.append(table);
}

function renderCacheView() {
  const swContainer = $('cache-sw-container');
  const quotaContainer = $('cache-quota-container');
  const bucketsContainer = $('cache-buckets-container');

  swContainer.replaceChildren();
  quotaContainer.replaceChildren();
  bucketsContainer.replaceChildren();

  const sws = state.pageData?.storage?.serviceWorkers || [];
  const quota = state.pageData?.storage?.storageQuota;
  const buckets = state.pageData?.storage?.cacheStorage || [];

  $('cache-sw-count').textContent = `${sws.length} active`;
  $('cache-buckets-count').textContent = `${buckets.length} bucket(s)`;

  if (!sws.length) {
    swContainer.innerHTML = '<div class="empty">No Service Worker registrations detected.</div>';
  } else {
    sws.forEach(sw => {
      const el = document.createElement('div');
      el.style.padding = '6px 0';
      el.innerHTML = `Scope: <code>${sw.scope}</code> · Active: ${sw.active ? 'Yes' : 'No'}`;
      swContainer.append(el);
    });
  }

  if (quota) {
    const fQuota = formatStorageQuota(quota);
    quotaContainer.innerHTML = `
      <div style="font-size: 18px; font-weight: 700; color: var(--amber);">${formatBytes(fQuota.usageBytes)} used</div>
      <div class="muted">Quota: ${formatBytes(fQuota.quotaBytes)} (${fQuota.usagePercentage}% utilized) · Persisted: ${quota.persisted ? 'Yes' : 'No'}</div>
    `;
  } else {
    quotaContainer.innerHTML = '<div class="empty">Storage quota API not available.</div>';
  }

  if (!buckets.length) {
    bucketsContainer.innerHTML = '<div class="empty">No CacheStorage buckets registered.</div>';
  } else {
    buckets.forEach(b => {
      const el = document.createElement('div');
      el.style.padding = '8px 0';
      el.style.borderBottom = '1px solid var(--border)';
      el.innerHTML = `<strong>Cache: ${b.name}</strong> · ${b.entries?.length || 0} cached items`;
      bucketsContainer.append(el);
    });
  }
}

function renderApiView() {
  const wrap = $('api-inventory-table');
  wrap.replaceChildren();
  const endpoints = state.apiSummary?.endpoints || [];
  $('api-endpoints-count').textContent = `${endpoints.length} unique endpoint(s)`;

  if (!endpoints.length) {
    wrap.innerHTML = '<div class="empty">No API routes observed. Reload page while CDP Capture is running.</div>';
    return;
  }

  const table = document.createElement('table');
  table.innerHTML = `
    <thead><tr><th>Method</th><th>Abstracted Route Pattern</th><th>Type</th><th>Requests</th><th>Statuses</th><th>Auth Header</th></tr></thead>
    <tbody>
      ${endpoints.map(e => `
        <tr>
          <td><span class="badge-mini badge-neutral">${e.method}</span></td>
          <td><code>${e.pathnamePattern}</code></td>
          <td>${e.apiType}</td>
          <td>${e.requestCount}</td>
          <td>${e.statuses.join(', ')}</td>
          <td>${e.hasAuthHeader ? '✓ (Detected)' : '—'}</td>
        </tr>
      `).join('')}
    </tbody>
  `;
  wrap.append(table);
}

function renderTechView() {
  const wrap = $('tech-full-table');
  wrap.replaceChildren();
  const techs = state.technologies || [];
  $('tech-total-badge').textContent = `${techs.length} detected`;

  if (!techs.length) {
    wrap.innerHTML = '<div class="empty">No technologies fingerprinted.</div>';
    return;
  }

  const table = document.createElement('table');
  table.innerHTML = `
    <thead><tr><th>Technology</th><th>Category</th><th>Version</th><th>Confidence</th><th>Evidence & Source</th></tr></thead>
    <tbody>
      ${techs.map(t => `
        <tr>
          <td><strong>${t.name}</strong></td>
          <td>${t.category}</td>
          <td>${t.version || '—'}</td>
          <td><span class="badge-mini badge-${t.confidence === 'CONFIRMED' ? 'success' : 'neutral'}">${t.confidence}</span></td>
          <td>${t.evidence} <span class="muted">(${t.source})</span></td>
        </tr>
      `).join('')}
    </tbody>
  `;
  wrap.append(table);
}

function renderTrackerGraph(trackers, targetHost) {
  const svg = $('tracker-graph-svg');
  if (!svg) return;
  svg.innerHTML = '';

  const width = svg.clientWidth || 600;
  const height = svg.clientHeight || 260;
  const centerX = width / 2;
  const centerY = height / 2;

  if (!trackers || !trackers.length) {
    const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    text.setAttribute('x', centerX);
    text.setAttribute('y', centerY);
    text.setAttribute('text-anchor', 'middle');
    text.setAttribute('fill', '#64748b');
    text.setAttribute('font-size', '12');
    text.textContent = 'No external tracker connections observed';
    svg.appendChild(text);
    return;
  }

  // Draw central node
  const centerGroup = document.createElementNS('http://www.w3.org/2000/svg', 'g');
  const centerCircle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
  centerCircle.setAttribute('cx', centerX);
  centerCircle.setAttribute('cy', centerY);
  centerCircle.setAttribute('r', '22');
  centerCircle.setAttribute('fill', '#0891b2');
  centerCircle.setAttribute('stroke', '#06b6d4');
  centerCircle.setAttribute('stroke-width', '2');

  const centerText = document.createElementNS('http://www.w3.org/2000/svg', 'text');
  centerText.setAttribute('x', centerX);
  centerText.setAttribute('y', centerY + 4);
  centerText.setAttribute('text-anchor', 'middle');
  centerText.setAttribute('fill', '#ffffff');
  centerText.setAttribute('font-size', '10');
  centerText.setAttribute('font-weight', 'bold');
  centerText.textContent = (targetHost || 'Origin').slice(0, 10);

  centerGroup.appendChild(centerCircle);
  centerGroup.appendChild(centerText);

  // Categories colors
  const catColors = {
    'Advertising': '#ef4444',
    'Analytics': '#f97316',
    'CDN': '#10b981',
    'Hosting': '#3b82f6',
    'Social': '#8b5cf6',
    'Essential': '#06b6d4',
    'Other': '#64748b'
  };

  const visibleTrackers = trackers.slice(0, 12);
  const radius = Math.min(width, height) * 0.38;

  visibleTrackers.forEach((t, i) => {
    const angle = (i / visibleTrackers.length) * 2 * Math.PI - (Math.PI / 2);
    const nodeX = centerX + radius * Math.cos(angle);
    const nodeY = centerY + radius * Math.sin(angle);
    const color = catColors[t.category] || catColors['Other'];

    // Link line
    const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
    line.setAttribute('x1', centerX);
    line.setAttribute('y1', centerY);
    line.setAttribute('x2', nodeX);
    line.setAttribute('y2', nodeY);
    line.setAttribute('stroke', color);
    line.setAttribute('stroke-width', '1.5');
    line.setAttribute('stroke-opacity', '0.4');
    line.setAttribute('stroke-dasharray', '3,3');
    svg.appendChild(line);

    // Node group
    const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    g.style.cursor = 'pointer';

    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('cx', nodeX);
    circle.setAttribute('cy', nodeY);
    circle.setAttribute('r', '13');
    circle.setAttribute('fill', '#111827');
    circle.setAttribute('stroke', color);
    circle.setAttribute('stroke-width', '2');

    const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    label.setAttribute('x', nodeX);
    label.setAttribute('y', nodeY + (nodeY > centerY ? 22 : -16));
    label.setAttribute('text-anchor', 'middle');
    label.setAttribute('fill', '#94a3b8');
    label.setAttribute('font-size', '9');
    label.setAttribute('font-weight', '500');
    label.textContent = t.domain.length > 15 ? t.domain.slice(0, 14) + '…' : t.domain;

    const titleEl = document.createElementNS('http://www.w3.org/2000/svg', 'title');
    titleEl.textContent = `${t.domain}\nProvider: ${t.provider}\nCategory: ${t.category}\nRequests: ${t.requestCount}`;
    g.appendChild(titleEl);

    g.appendChild(circle);
    g.appendChild(label);
    svg.appendChild(g);
  });

  svg.appendChild(centerGroup);
}

function renderTrackersView() {
  const wrap = $('trackers-full-table');
  wrap.replaceChildren();
  const trackers = state.thirdPartySummary?.thirdPartyDomains || [];
  $('trackers-total-badge').textContent = `${trackers.length} external domain(s)`;

  renderTrackerGraph(trackers, state.activeHostname);

  if (!trackers.length) {
    wrap.innerHTML = '<div class="empty">No third-party trackers or CDNs detected.</div>';
    return;
  }

  const table = document.createElement('table');
  table.innerHTML = `
    <thead><tr><th>External Domain</th><th>Provider</th><th>Category</th><th>Requests</th><th>Data Types</th></tr></thead>
    <tbody>
      ${trackers.map(t => `
        <tr>
          <td><code>${t.domain}</code></td>
          <td>${t.provider}</td>
          <td><span class="badge-mini badge-warn">${t.category}</span></td>
          <td>${t.requestCount}</td>
          <td>${t.resources.join(', ') || '—'}</td>
        </tr>
      `).join('')}
    </tbody>
  `;
  wrap.append(table);
}

function renderPerformanceView() {
  const p = state.perfSummary;
  if (!p) return;
  $('perf-kpi-bytes').textContent = p.totalTransferFormatted;
  $('perf-kpi-cache').textContent = `${p.cacheUtilizationPercent}%`;
  $('perf-kpi-third-bytes').textContent = p.thirdPartyBytesFormatted;
  $('perf-kpi-failed').textContent = p.failedRequestsCount;

  const slowWrap = $('perf-slow-table');
  slowWrap.replaceChildren();
  if (!p.slowRequests.length) {
    slowWrap.innerHTML = '<div class="empty">No request timings captured yet.</div>';
    return;
  }

  const table = document.createElement('table');
  table.innerHTML = `
    <thead><tr><th>Resource URL</th><th>Duration</th><th>Resource Type</th><th>Status</th></tr></thead>
    <tbody>
      ${p.slowRequests.map(r => `
        <tr>
          <td><code>${sanitizeUrl(r.url)}</code></td>
          <td style="color: var(--amber); font-weight: 700;">${r.durationMs} ms</td>
          <td>${r.type}</td>
          <td>${r.status}</td>
        </tr>
      `).join('')}
    </tbody>
  `;
  slowWrap.append(table);
}

// --- DNS Query Execution ---
async function executeDnsQuery() {
  if (!state.activeHostname) {
    alert('No active target hostname discovered.');
    return;
  }

  $('btn-trigger-dns').textContent = 'Querying DoH…';
  $('btn-trigger-dns').disabled = true;

  try {
    const dnsResult = await queryDns(state.activeHostname);
    state.dnsData = dnsResult;

    // DNSSEC Banner
    const banner = $('dnssec-status-banner');
    banner.className = `action-bar-panel ${dnsResult.dnssecValidated ? 'badge-success' : 'badge-neutral'}`;
    banner.innerHTML = dnsResult.dnssecValidated
      ? '<strong>✓ DNSSEC Cryptographically Authenticated (AD flag set):</strong> Resolver verified digital signatures.'
      : '<strong>DNSSEC Unsigned / AD flag absent:</strong> Domain records do not present validated DNSSEC keys.';

    // SPF
    const spfPill = $('spf-policy-pill');
    const spfBox = $('spf-details-box');
    if (dnsResult.spfRecord) {
      spfPill.textContent = dnsResult.spfRecord.allPolicy;
      spfPill.className = `badge-mini ${dnsResult.spfRecord.isStrict ? 'badge-success' : 'badge-warn'}`;
      spfBox.textContent = JSON.stringify(dnsResult.spfRecord, null, 2);
    } else {
      spfPill.textContent = 'Missing';
      spfPill.className = 'badge-mini badge-danger';
      spfBox.textContent = 'No SPF (v=spf1) record discovered.';
    }

    // DMARC
    const dmarcPill = $('dmarc-policy-pill');
    const dmarcBox = $('dmarc-details-box');
    if (dnsResult.dmarcRecord) {
      dmarcPill.textContent = `p=${dnsResult.dmarcRecord.policy}`;
      dmarcPill.className = `badge-mini ${dnsResult.dmarcRecord.isEnforced ? 'badge-success' : 'badge-warn'}`;
      dmarcBox.textContent = JSON.stringify(dnsResult.dmarcRecord, null, 2);
    } else {
      dmarcPill.textContent = 'Missing';
      dmarcPill.className = 'badge-mini badge-danger';
      dmarcBox.textContent = 'No DMARC (v=DMARC1) record discovered at _dmarc host.';
    }

    // Records Table
    const recContainer = $('dns-records-container');
    recContainer.replaceChildren();
    const table = document.createElement('table');
    table.innerHTML = `
      <thead><tr><th>Type</th><th>Answers</th><th>Raw Records</th></tr></thead>
      <tbody>
        ${dnsResult.results.map(r => `
          <tr>
            <td><strong>${r.type}</strong></td>
            <td>${r.answers.length}</td>
            <td><code>${r.answers.map(a => a.data).join(' · ') || '—'}</code></td>
          </tr>
        `).join('')}
      </tbody>
    `;
    recContainer.append(table);
    $('dns-record-count').textContent = `${dnsResult.results.reduce((acc, r) => acc + r.answers.length, 0)} records`;

    showToast('DNS & Email security records resolved!');
  } catch (err) {
    alert(`DNS Query Error: ${err.message}`);
  } finally {
    $('btn-trigger-dns').textContent = 'Refresh DNS Lookup';
    $('btn-trigger-dns').disabled = false;
  }
}

// --- View Switching ---
function switchView(viewId) {
  state.activeView = viewId;
  document.querySelectorAll('.nav-item').forEach(b => b.classList.toggle('active', b.dataset.view === viewId));
  document.querySelectorAll('.view-pane').forEach(p => {
    p.classList.toggle('hidden', p.id !== viewId);
    p.classList.toggle('active', p.id === viewId);
  });

  const titles = {
    'view-overview': 'Overview Dashboard',
    'view-security': 'Security Auditor & Vulnerabilities',
    'view-ip': 'IP & Network Intelligence',
    'view-dns': 'DNS & Email Authentication',
    'view-network': 'Network Waterfall & CDP Streams',
    'view-tokens': 'Token & Authentication Intelligence',
    'view-storage': 'Browser Storage Inspector',
    'view-cookies': 'Cookie Security & Hygiene',
    'view-cache': 'Cache & Service Workers',
    'view-api': 'API Discovery & Routes',
    'view-tech': 'Technology Fingerprints',
    'view-trackers': 'Third-Party Tracking Infrastructure',
    'view-performance': 'Performance Metrics & Latency',
    'view-snapshots': 'Inspection Snapshots & Comparison',
    'view-reports': 'Report Generation & Data Exports',
    'view-settings': 'Scope & Extension Settings'
  };

  $('view-title').textContent = titles[viewId] || 'Dashboard';
}

// --- Exports & Downloads ---
function downloadFile(filename, content, type = 'text/plain') {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function handleExportJson() {
  const reportObj = buildJsonReport({
    origin: state.activeOrigin,
    hostname: state.activeHostname,
    securityGrade: $('kpi-grade').textContent,
    findings: state.findingsEngine.query(),
    severityCounts: state.findingsEngine.getStatistics(),
    technologies: state.technologies,
    ipSummary: state.ipSummary,
    dns: state.dnsData,
    storage: state.pageData?.storage,
    apis: state.apiSummary?.endpoints,
    thirdParties: state.thirdPartySummary?.thirdPartyDomains,
    performance: state.perfSummary
  });

  downloadFile(`scopelens-audit-${state.activeHostname || 'site'}-${Date.now()}.json`, JSON.stringify(reportObj, null, 2), 'application/json');
  showToast('JSON report downloaded!');
}

function handleExportHtml() {
  const htmlContent = generateHtmlReport({
    origin: state.activeOrigin,
    hostname: state.activeHostname,
    securityGrade: $('kpi-grade').textContent,
    findings: state.findingsEngine.query(),
    severityCounts: state.findingsEngine.getStatistics(),
    technologies: state.technologies
  });

  downloadFile(`scopelens-report-${state.activeHostname || 'site'}-${Date.now()}.html`, htmlContent, 'text/html');
  showToast('Standalone HTML report downloaded!');
}

function handleExportCsv() {
  const findings = state.findingsEngine.query();
  const csv = exportToCsv(findings, ['severity', 'title', 'category', 'affectedResource', 'remediation']);
  downloadFile(`scopelens-findings-${state.activeHostname || 'site'}-${Date.now()}.csv`, csv, 'text/csv');
  showToast('Findings CSV downloaded!');
}

// --- Snapshots ---
function handleCreateSnapshot() {
  const label = prompt('Enter a label for this snapshot:', `Snapshot ${new Date().toLocaleTimeString()}`);
  if (!label) return;

  const snap = state.snapshotManager.createSnapshot(label, {
    origin: state.activeOrigin,
    hostname: state.activeHostname,
    endpoints: state.ipSummary?.endpoints || [],
    headers: state.pageData?.headers || {},
    thirdPartyDomains: state.thirdPartySummary?.thirdPartyDomains || [],
    technologies: state.technologies || [],
    findings: state.findingsEngine.query()
  });

  renderSnapshotsList();
  showToast(`Snapshot "${snap.label}" created!`);
}

function renderSnapshotsList() {
  const list = $('snapshots-list');
  list.replaceChildren();
  const snaps = state.snapshotManager.listSnapshots();
  $('snapshots-count').textContent = `${snaps.length} saved`;

  if (!snaps.length) {
    list.innerHTML = '<div class="empty">No snapshots captured yet. Click "Capture New Snapshot".</div>';
    return;
  }

  snaps.forEach((s, idx) => {
    const el = document.createElement('div');
    el.style.padding = '8px 10px';
    el.style.borderBottom = '1px solid var(--border)';
    el.style.display = 'flex';
    el.style.alignItems = 'center';
    el.style.justifyContent = 'space-between';
    el.style.gap = '8px';

    const info = document.createElement('div');
    info.style.flex = '1';
    info.innerHTML = `<strong>${s.label}</strong> <span class="muted">(${new Date(s.createdAt).toLocaleTimeString()})</span><br><span class="muted" style="font-size: 11px;">${s.summary.totalFindings} findings · ${s.summary.totalEndpoints} endpoints</span>`;

    const controls = document.createElement('div');
    controls.style.display = 'flex';
    controls.style.gap = '8px';
    controls.style.alignItems = 'center';

    const labelA = document.createElement('label');
    labelA.style.fontSize = '11px';
    labelA.innerHTML = `<input type="radio" name="snap-base" value="${s.id}" ${idx === 1 || (snaps.length === 1 && idx === 0) ? 'checked' : ''}> Base`;

    const labelB = document.createElement('label');
    labelB.style.fontSize = '11px';
    labelB.innerHTML = `<input type="radio" name="snap-target" value="${s.id}" ${idx === 0 ? 'checked' : ''}> Target`;

    controls.append(labelA, labelB);
    el.append(info, controls);
    list.append(el);
  });
}

// --- Network Waterfall View ---
function renderNetworkView(filter = 'all') {
  const container = $('network-waterfall-container');
  if (!container) return;
  container.replaceChildren();

  const items = (state.captureData?.items || []).filter(item => {
    if (filter === 'all') return true;
    const mime = (item.mimeType || '').toLowerCase();
    const url = (item.url || '').toLowerCase();
    if (filter === 'fetch' && (mime.includes('json') || mime.includes('xml') || url.includes('/api/'))) return true;
    if (filter === 'script' && (mime.includes('javascript') || url.includes('.js'))) return true;
    if (filter === 'stylesheet' && (mime.includes('css') || url.includes('.css'))) return true;
    if (filter === 'document' && (mime.includes('html') || url.endsWith('/'))) return true;
    if (filter === 'image' && (mime.includes('image') || /\.(png|jpg|jpeg|gif|svg|webp|ico)/i.test(url))) return true;
    return false;
  });

  if (!items.length) {
    container.innerHTML = '<div class="empty">No network requests captured matching this filter. Click Start CDP Capture or reload page.</div>';
    return;
  }

  items.forEach(req => {
    const row = document.createElement('div');
    row.className = 'panel';
    row.style.marginBottom = '6px';
    row.style.padding = '8px 12px';
    row.style.cursor = 'pointer';

    const top = document.createElement('div');
    top.style.display = 'flex';
    top.style.alignItems = 'center';
    top.style.gap = '8px';

    const method = document.createElement('span');
    method.className = 'badge-mini badge-neutral';
    method.textContent = req.method || 'GET';

    const statusPill = document.createElement('span');
    statusPill.className = `status-pill ${req.status >= 400 ? 'status-4xx' : 'status-2xx'}`;
    statusPill.textContent = req.status || '—';

    const urlSpan = document.createElement('span');
    urlSpan.style.flex = '1';
    urlSpan.style.overflow = 'hidden';
    urlSpan.style.textOverflow = 'ellipsis';
    urlSpan.style.whiteSpace = 'nowrap';
    urlSpan.style.fontSize = '11px';
    urlSpan.textContent = sanitizeUrl(req.url);

    const meta = document.createElement('span');
    meta.className = 'muted';
    meta.style.fontSize = '10px';
    meta.textContent = `${req.remoteIp || '—'} · ${req.remotePort ? `:${req.remotePort}` : ''} · ${req.protocol || 'h2'}`;

    top.append(method, statusPill, urlSpan, meta);
    row.append(top);

    // Expandable details
    const details = document.createElement('div');
    details.className = 'hidden';
    details.style.marginTop = '8px';
    details.style.borderTop = '1px solid var(--border)';
    details.style.paddingTop = '8px';

    const code = document.createElement('pre');
    code.className = 'code-box';
    code.textContent = JSON.stringify({
      url: sanitizeUrl(req.url),
      status: req.status,
      remoteIp: req.remoteIp,
      remotePort: req.remotePort,
      protocol: req.protocol,
      headers: sanitizeHeaders(req.headers || [])
    }, null, 2);

    details.append(code);
    row.append(details);

    row.addEventListener('click', () => {
      details.classList.toggle('hidden');
    });

    container.append(row);
  });
}

// --- Toggle CDP Capture ---
async function toggleCdpCapture() {
  if (!state.activeTab?.id) {
    alert('Please select an active target tab first.');
    return;
  }

  const btn = $('btn-toggle-capture');
  const isRunning = Boolean(state.captureData?.running);

  try {
    if (isRunning) {
      btn.textContent = 'Stopping…';
      const resp = await chrome.runtime.sendMessage({ type: 'STOP_CAPTURE', tabId: state.activeTab.id });
      if (resp?.state) state.captureData = resp.state;
      btn.textContent = 'Start CDP Capture';
      $('capture-status-badge').textContent = 'Passive';
      showToast('CDP capture stopped.');
    } else {
      btn.textContent = 'Starting…';
      const resp = await chrome.runtime.sendMessage({
        type: 'START_CAPTURE',
        tabId: state.activeTab.id,
        origin: state.activeOrigin
      });
      if (resp?.state) state.captureData = resp.state;
      btn.textContent = 'Stop CDP Capture';
      $('capture-status-badge').textContent = 'Capturing';
      showToast('CDP capture started! Reload target page to record requests.');
    }
    renderNetworkView();
  } catch (err) {
    alert(`Capture Error: ${err.message}`);
    btn.textContent = isRunning ? 'Stop CDP Capture' : 'Start CDP Capture';
  }
}

// --- Compare Snapshots ---
function handleCompareSnapshots() {
  const baseEl = document.querySelector('input[name="snap-base"]:checked');
  const targetEl = document.querySelector('input[name="snap-target"]:checked');

  if (!baseEl || !targetEl) {
    alert('Please select both a Base and Target snapshot to compare.');
    return;
  }

  const baseId = baseEl.value;
  const targetId = targetEl.value;

  if (baseId === targetId) {
    alert('Please select two different snapshots to calculate differential comparison.');
    return;
  }

  const diff = state.snapshotManager.compareSnapshots(baseId, targetId);
  const out = $('snapshot-diff-output');
  if (!out) return;

  const d = diff.delta;
  const summaryText = [
    `=== ScopeLens Differential Audit Delta ===`,
    `Base Snapshot:   ${diff.baseSnapshot.label} (${new Date(diff.baseSnapshot.createdAt).toLocaleTimeString()})`,
    `Target Snapshot: ${diff.targetSnapshot.label} (${new Date(diff.targetSnapshot.createdAt).toLocaleTimeString()})`,
    ``,
    `[+] Newly Discovered Endpoints (${d.newEndpoints.length}):`,
    d.newEndpoints.length ? d.newEndpoints.map(e => `  + ${e}`).join('\n') : '  (None)',
    ``,
    `[-] Removed Endpoints (${d.removedEndpoints.length}):`,
    d.removedEndpoints.length ? d.removedEndpoints.map(e => `  - ${e}`).join('\n') : '  (None)',
    ``,
    `[+] Newly Introduced Third-Party Domains (${d.newThirdParties.length}):`,
    d.newThirdParties.length ? d.newThirdParties.map(t => `  + ${t}`).join('\n') : '  (None)',
    ``,
    `[~] Header Modifications (${d.headerChanges.length}):`,
    d.headerChanges.length ? d.headerChanges.map(h => `  ~ ${h.header}: "${h.before}" -> "${h.after}"`).join('\n') : '  (None)',
    ``,
    `[+] Newly Detected Technologies (${d.addedTechnologies.length}):`,
    d.addedTechnologies.length ? d.addedTechnologies.map(t => `  + ${t}`).join('\n') : '  (None)',
    ``,
    `Security Findings Delta:`,
    `  Newly Emerged Findings: ${d.newFindingsCount}`,
    `  Resolved Findings:       ${d.resolvedFindingsCount}`
  ].join('\n');

  out.textContent = summaryText;
  showToast('Differential snapshot comparison computed!');
}

function handleExportCycloneDx() {
  const cdx = state.sourceMapAnalyzer
    ? state.sourceMapAnalyzer.exportCycloneDxJson(state.activeOrigin)
    : new SourceMapAnalyzer().exportCycloneDxJson(state.activeOrigin);

  downloadFile(`scopelens-cyclonedx-sbom-${state.activeHostname || 'site'}-${Date.now()}.json`, JSON.stringify(cdx, null, 2), 'application/json');
  showToast('CycloneDX SBOM downloaded!');
}

function handleExportSpdx() {
  const spdx = state.sourceMapAnalyzer
    ? state.sourceMapAnalyzer.exportSpdxJson(state.activeOrigin)
    : new SourceMapAnalyzer().exportSpdxJson(state.activeOrigin);

  downloadFile(`scopelens-spdx-sbom-${state.activeHostname || 'site'}-${Date.now()}.json`, JSON.stringify(spdx, null, 2), 'application/json');
  showToast('SPDX 2.3 manifest downloaded!');
}

function handleExportOpenApi() {
  const generator = new OpenApiGenerator();
  const spec = generator.generateSpec({
    title: state.activeHostname || 'Target API',
    targetOrigin: state.activeOrigin || 'https://api.example.com',
    endpoints: state.apiSummary?.endpoints || [],
    sampleRequests: state.captureData?.items || []
  });

  downloadFile(`scopelens-openapi-spec-${state.activeHostname || 'api'}-${Date.now()}.json`, JSON.stringify(spec, null, 2), 'application/json');
  showToast('OpenAPI 3.0 draft specification downloaded!');
}

async function updateSettingsStorageStats() {
  try {
    const stats = await retentionManager.getStorageStats();
    if ($('quota-sessions-count')) $('quota-sessions-count').textContent = `${stats.sessions} / 10`;
    if ($('quota-obs-count')) $('quota-obs-count').textContent = `${stats.observations} / 5000`;
    if ($('quota-snapshots-count')) $('quota-snapshots-count').textContent = `${stats.snapshots} / 25`;
  } catch {}
}

async function handlePurgeAllStorage() {
  if (confirm('Are you sure you want to completely purge all locally stored ScopeLens data? This will clear sessions, snapshots, and observation history.')) {
    await retentionManager.purgeAllData();
    await updateSettingsStorageStats();
    state.snapshotManager = new SnapshotManager();
    renderSnapshotsList();
    showToast('All local ScopeLens data successfully purged!');
  }
}

function handleExportHar() {
  const requests = state.captureData?.items || [];
  if (!requests.length) {
    alert('No captured network requests to export into HAR format. Click Start CDP Capture first.');
    return;
  }
  const har = exportToHar(requests, state.activeOrigin);
  downloadFile(`scopelens-traffic-${state.activeHostname || 'capture'}-${Date.now()}.har`, har, 'application/json');
  showToast('HAR 1.2 archive downloaded!');
}

function handleCopyMarkdown() {
  const stats = state.findingsEngine.getStatistics();
  const findings = state.findingsEngine.query();
  const techs = state.technologies || [];

  const md = [
    `# ScopeLens Security & Intelligence Audit: ${state.activeHostname || 'Site'}`,
    `*Generated: ${new Date().toLocaleString()}*`,
    ``,
    `## Executive Summary`,
    `- Target Host: **${state.activeHostname}**`,
    `- Security Posture Grade: **${$('kpi-grade').textContent}**`,
    `- Total Identified Findings: **${stats.total}** (${stats.critical} Critical, ${stats.high} High, ${stats.medium} Medium)`,
    `- Technologies Fingerprinted: **${techs.length}**`,
    `- Observed Remote Endpoints: **${state.ipSummary?.distinctIps || 0}**`,
    ``,
    `## Top Security Findings`,
    findings.length ? findings.slice(0, 10).map(f => `- **[${f.severity}] ${f.title}**: ${f.description}\n  *Remediation: ${f.remediation}*`).join('\n') : `- No findings recorded.`,
    ``,
    `## Technology Stack`,
    techs.length ? techs.map(t => `- **${t.name}** (${t.category}${t.version ? ` v${t.version}` : ''}) — *${t.confidence}*`).join('\n') : `- None fingerprinted.`,
    ``,
    `---`,
    `*Generated locally by ScopeLens Web Security Platform*`
  ].join('\n');

  navigator.clipboard.writeText(md).then(() => {
    showToast('Executive Markdown copied to clipboard!');
  }).catch(() => {
    showToast('Notice: Unable to access clipboard.');
  });
}

// --- Wire Event Handlers ---
document.querySelectorAll('.nav-item').forEach(btn => {
  btn.addEventListener('click', () => {
    switchView(btn.dataset.view);
    if (btn.dataset.view === 'view-network') renderNetworkView();
  });
});

document.querySelectorAll('[data-switch-view]').forEach(btn => {
  btn.addEventListener('click', () => {
    switchView(btn.dataset.switchView);
    if (btn.dataset.switchView === 'view-network') renderNetworkView();
  });
});

$('btn-run-audit')?.addEventListener('click', executeFullAudit);
$('btn-trigger-dns')?.addEventListener('click', executeDnsQuery);
$('btn-export-quick')?.addEventListener('click', handleExportJson);
$('btn-export-json-full')?.addEventListener('click', handleExportJson);
$('btn-export-html')?.addEventListener('click', handleExportHtml);
$('btn-export-csv')?.addEventListener('click', handleExportCsv);
$('btn-export-har')?.addEventListener('click', handleExportHar);
$('btn-copy-markdown')?.addEventListener('click', handleCopyMarkdown);
$('btn-export-cyclonedx')?.addEventListener('click', handleExportCycloneDx);
$('btn-export-spdx')?.addEventListener('click', handleExportSpdx);
$('btn-export-openapi')?.addEventListener('click', handleExportOpenApi);
$('btn-purge-storage')?.addEventListener('click', handlePurgeAllStorage);
$('btn-create-snapshot')?.addEventListener('click', handleCreateSnapshot);
$('btn-run-compare')?.addEventListener('click', handleCompareSnapshots);
$('btn-toggle-capture')?.addEventListener('click', toggleCdpCapture);
$('btn-clear-network')?.addEventListener('click', () => {
  if (state.captureData) state.captureData.items = [];
  renderNetworkView();
  showToast('Network items cleared.');
});

document.querySelectorAll('[data-net-filter]').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('[data-net-filter]').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    renderNetworkView(btn.dataset.netFilter);
  });
});

document.querySelectorAll('[data-sec-filter]').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('[data-sec-filter]').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    renderSecurityView(btn.dataset.secFilter);
  });
});

// Real-time Global Search Filter
$('global-search')?.addEventListener('input', e => {
  const query = e.target.value.toLowerCase().trim();
  const currentView = $(state.activeView);
  if (!currentView) return;

  const rows = currentView.querySelectorAll('table tbody tr, .finding-card, .tech-item, .panel');
  rows.forEach(r => {
    if (!query) {
      r.style.display = '';
      return;
    }
    const txt = r.textContent.toLowerCase();
    r.style.display = txt.includes(query) ? '' : 'none';
  });
});

// Global Keyboard Shortcuts (Ctrl+K or Cmd+K to focus search, Esc to clear)
window.addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
    e.preventDefault();
    const search = $('global-search');
    if (search) {
      search.focus();
      search.select();
    }
  }
  if (e.key === 'Escape') {
    const search = $('global-search');
    if (search && document.activeElement === search) {
      search.value = '';
      search.dispatchEvent(new Event('input'));
      search.blur();
    }
  }
});

// Initialization
(async () => {
  await discoverTarget();
  if (state.activeTab) {
    executeFullAudit();
  }
})();
