/**
 * Module L - Reporting & Export Engine
 * Generates structured JSON, CSV, and standalone self-contained HTML audit reports.
 * Redacts sensitive credentials, tokens, and authorization parameters by default.
 */

import { sanitizeData, sanitizeUrl, sanitizeHeaders } from '../../core/redactor.js';

/**
 * Builds a standardized JSON audit report object.
 * @param {Object} auditData
 * @returns {Object}
 */
export function buildJsonReport(auditData = {}) {
  const sanitized = sanitizeData({
    reportMetadata: {
      generator: 'ScopeLens Web Security & Network Intelligence Platform',
      version: '2.0.0',
      generatedAt: new Date().toISOString(),
      scope: auditData.origin || 'Active Website',
      browser: typeof navigator !== 'undefined' ? navigator.userAgent : 'Chromium / V8'
    },
    executiveSummary: {
      targetHostname: auditData.hostname || '',
      securityGrade: auditData.securityGrade || 'N/A',
      totalFindings: auditData.findings?.length || 0,
      severityCounts: auditData.severityCounts || {},
      technologiesCount: auditData.technologies?.length || 0,
      distinctEndpointsCount: auditData.ipSummary?.distinctIps || 0,
      thirdPartyCount: auditData.thirdParties?.length || 0
    },
    findings: auditData.findings || [],
    technologies: auditData.technologies || [],
    ipIntelligence: auditData.ipSummary || {},
    dnsRecords: auditData.dns || {},
    storageSummary: auditData.storage || {},
    apiInventory: auditData.apis || [],
    thirdPartyServices: auditData.thirdParties || [],
    performanceMetrics: auditData.performance || {}
  });

  return sanitized;
}

/**
 * Converts a list of objects to CSV formatted text.
 * @param {Array<Object>} items
 * @param {Array<string>} [fields]
 * @returns {string}
 */
export function exportToCsv(items = [], fields = []) {
  if (!items || !items.length) return '';

  const columns = fields.length ? fields : Object.keys(items[0]);
  const headerLine = columns.map(c => `"${String(c).replace(/"/g, '""')}"`).join(',');

  const rows = items.map(item => {
    return columns.map(col => {
      const val = item[col];
      const str = val === null || val === undefined ? '' : (typeof val === 'object' ? JSON.stringify(val) : String(val));
      return `"${str.replace(/"/g, '""')}"`;
    }).join(',');
  });

  return [headerLine, ...rows].join('\r\n');
}

/**
 * Exports captured HTTP requests into standard HAR 1.2 format with sensitive credentials redacted.
 * @param {Array<Object>} requests
 * @param {string} [origin='']
 * @returns {string}
 */
export function exportToHar(requests = [], origin = '') {
  const entries = requests.map(r => {
    const rawUrl = r.url || r.request?.url || '';
    const method = r.method || r.request?.method || 'GET';
    const status = r.status || r.response?.status || 200;
    const statusText = r.statusText || r.response?.statusText || 'OK';
    const time = r.durationMs || r.time || 50;
    const mime = r.mimeType || r.response?.content?.mimeType || 'text/html';
    const size = r.size || r.transferSize || r.response?.bodySize || 0;

    return {
      startedDateTime: r.seenAt || new Date().toISOString(),
      time,
      request: {
        method,
        url: sanitizeUrl(rawUrl),
        httpVersion: r.protocol || 'HTTP/1.1',
        cookies: [],
        headers: sanitizeHeaders(r.headers || r.request?.headers || []),
        queryString: [],
        headersSize: -1,
        bodySize: -1
      },
      response: {
        status,
        statusText,
        httpVersion: r.protocol || 'HTTP/1.1',
        cookies: [],
        headers: sanitizeHeaders(r.headers || r.response?.headers || []),
        content: {
          size,
          mimeType: mime,
          text: r.preview || ''
        },
        redirectURL: '',
        headersSize: -1,
        bodySize: size
      },
      cache: {},
      timings: {
        send: 0,
        wait: Math.round(time * 0.7),
        receive: Math.round(time * 0.3)
      }
    };
  });

  return JSON.stringify({
    log: {
      version: '1.2',
      creator: { name: 'ScopeLens Web Security Platform', version: '2.0.0' },
      pages: [{
        startedDateTime: new Date().toISOString(),
        id: 'page_1',
        title: origin || 'ScopeLens Inspected Site',
        pageTimings: { onContentLoad: -1, onLoad: -1 }
      }],
      entries
    }
  }, null, 2);
}

/**
 * Generates a self-contained, standalone HTML report with embedded dark styles.
 * @param {Object} auditData
 * @returns {string}
 */
export function generateHtmlReport(auditData = {}) {
  const report = buildJsonReport(auditData);
  const m = report.reportMetadata;
  const s = report.executiveSummary;
  const findings = report.findings;
  const techs = report.technologies;

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>ScopeLens Security & Intelligence Audit: ${s.targetHostname || 'Report'}</title>
  <style>
    :root {
      --bg: #0b0e13;
      --card: #131923;
      --border: #222e3d;
      --text: #edf2f8;
      --muted: #8b9bb4;
      --amber: #f2b544;
      --green: #48bb78;
      --red: #f56565;
      --blue: #4299e1;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, sans-serif;
      font-size: 13px;
      line-height: 1.5;
      padding: 30px 40px;
    }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid var(--border);
      padding-bottom: 20px;
      margin-bottom: 25px;
    }
    .brand { font-size: 22px; font-weight: 800; color: var(--amber); }
    .badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
    }
    .badge-critical, .badge-high { background: rgba(245,101,101,0.2); color: var(--red); border: 1px solid var(--red); }
    .badge-medium { background: rgba(242,181,68,0.2); color: var(--amber); border: 1px solid var(--amber); }
    .badge-low, .badge-informational { background: rgba(66,153,225,0.2); color: var(--blue); border: 1px solid var(--blue); }
    .grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 25px; }
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 15px; }
    .card h3 { margin: 0 0 6px 0; font-size: 11px; color: var(--muted); text-transform: uppercase; }
    .card .val { font-size: 22px; font-weight: 700; color: var(--amber); }
    table { width: 100%; border-collapse: collapse; margin-top: 10px; }
    th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); }
    th { color: var(--muted); font-size: 11px; }
    .code-box {
      background: #06080b;
      border: 1px solid var(--border);
      padding: 8px;
      border-radius: 4px;
      font-family: monospace;
      font-size: 11px;
      white-space: pre-wrap;
      word-break: break-all;
    }
  </style>
</head>
<body>
  <div class="header">
    <div>
      <div class="brand">ScopeLens Platform</div>
      <div style="color: var(--muted); font-size: 12px; margin-top: 4px;">
        Automated Security Posture, Network Intelligence & Architecture Assessment
      </div>
    </div>
    <div style="text-align: right; color: var(--muted); font-size: 11px;">
      <div>Target: <strong>${s.targetHostname}</strong></div>
      <div>Generated: ${new Date(m.generatedAt).toLocaleString()}</div>
      <div>Scope: Local Inspection (${m.version})</div>
    </div>
  </div>

  <div class="grid">
    <div class="card">
      <h3>Security Posture</h3>
      <div class="val">${s.securityGrade}</div>
    </div>
    <div class="card">
      <h3>Identified Risks</h3>
      <div class="val">${s.totalFindings}</div>
    </div>
    <div class="card">
      <h3>Tech Stack Count</h3>
      <div class="val">${s.technologiesCount}</div>
    </div>
    <div class="card">
      <h3>Third-Party Hosts</h3>
      <div class="val">${s.thirdPartyCount}</div>
    </div>
  </div>

  <h2>Security Findings & Vulnerability Audit</h2>
  <table>
    <thead>
      <tr>
        <th>Severity</th>
        <th>Title</th>
        <th>Category</th>
        <th>Affected Resource</th>
        <th>Remediation</th>
      </tr>
    </thead>
    <tbody>
      ${findings.map(f => `
        <tr>
          <td><span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span></td>
          <td><strong>${f.title}</strong><br><span style="color: var(--muted); font-size: 11px;">${f.description}</span></td>
          <td>${f.category}</td>
          <td><code>${f.affectedResource || '—'}</code></td>
          <td>${f.remediation || '—'}</td>
        </tr>
      `).join('') || '<tr><td colspan="5" style="text-align: center; color: var(--muted);">No findings recorded.</td></tr>'}
    </tbody>
  </table>

  <h2 style="margin-top: 35px;">Detected Technology Stack</h2>
  <table>
    <thead>
      <tr>
        <th>Technology</th>
        <th>Category</th>
        <th>Version</th>
        <th>Confidence</th>
        <th>Evidence</th>
      </tr>
    </thead>
    <tbody>
      ${techs.map(t => `
        <tr>
          <td><strong>${t.name}</strong></td>
          <td>${t.category}</td>
          <td>${t.version || '—'}</td>
          <td>${t.confidence}</td>
          <td>${t.evidence || '—'}</td>
        </tr>
      `).join('') || '<tr><td colspan="5" style="text-align: center; color: var(--muted);">No technologies fingerprinted.</td></tr>'}
    </tbody>
  </table>

  <footer style="margin-top: 50px; text-align: center; color: var(--muted); font-size: 10px; border-top: 1px solid var(--border); padding-top: 15px;">
    Generated locally by ScopeLens Chrome Extension. All sensitive authentication tokens, passwords, and authorization headers are redacted.
  </footer>
</body>
</html>`;
}
