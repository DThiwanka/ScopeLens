/**
 * ScopeLens Platform - Sensitive Data Leakage & Privacy Analyzer
 * Detects server stack traces, debug file paths, internal IP addresses,
 * unencrypted/GET form actions for passwords, and framework version leakage.
 */

import { SECRET_PATTERNS } from '../../core/constants.js';

export class LeakageAnalyzer {
  constructor() {
    this.findings = [];
  }

  /**
   * Scans text content (DOM HTML, response bodies, script sources) for leakage signals.
   * @param {Object} target
   * @param {string} target.content
   * @param {string} target.url
   * @param {string} [target.type='text']
   * @returns {Array<Object>} Discovered leakage findings
   */
  scanContent(target) {
    if (!target || !target.content || typeof target.content !== 'string') {
      return [];
    }

    const content = target.content;
    const url = target.url || 'unknown';
    const localFindings = [];

    // 1. Stack Traces (Node, Python, Java, .NET, PHP)
    const stackTracePatterns = [
      { regex: /at\s+[\w$.]+\s+\([^)]+:\d+:\d+\)/i, env: 'Node.js / V8' },
      { regex: /Traceback \(most recent call last\):/i, env: 'Python' },
      { regex: /(java\.\w+\.\w+Exception|Exception in thread "[\w-]+")/i, env: 'Java' },
      { regex: /System\.[\w.]*Exception:\s+[^\n]+/i, env: '.NET' },
      { regex: /Fatal error:[\s\S]{0,100}in\s+[\w/\\.-]+\.php\s+on\s+line\s+\d+/i, env: 'PHP' }
    ];

    for (const pat of stackTracePatterns) {
      if (pat.regex.test(content)) {
        localFindings.push({
          id: 'LEAKAGE_STACK_TRACE',
          title: `Server Stack Trace Exposed (${pat.env})`,
          severity: 'HIGH',
          category: 'information_disclosure',
          description: `Discovered unhandled error or server stack trace leaking internal file paths and runtime details.`,
          evidence: { url, environment: pat.env }
        });
        break;
      }
    }

    // 2. Local/Internal System File Paths
    const pathPatterns = [
      { regex: /(?:[a-zA-Z]:\\(?:Users|inetpub|xampp|Windows|Program Files)\\[\w\s.-]+)/i, os: 'Windows' },
      { regex: /(?:\/(?:home|Users|var\/www|opt\/app)\/[\w.-]+)/i, os: 'Unix/macOS' }
    ];

    for (const pat of pathPatterns) {
      const match = content.match(pat.regex);
      if (match) {
        localFindings.push({
          id: 'LEAKAGE_INTERNAL_PATH',
          title: `Internal System Path Exposed (${pat.os})`,
          severity: 'MEDIUM',
          category: 'information_disclosure',
          description: `Found internal system directory path '${match[0]}' exposed in client-accessible content.`,
          evidence: { match: match[0], url }
        });
        break;
      }
    }

    // 3. Private RFC 1918 IP addresses in client comments / code
    const internalIpPattern = /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g;
    const ipMatches = content.match(internalIpPattern);
    if (ipMatches && ipMatches.length > 0) {
      const uniqueIps = Array.from(new Set(ipMatches)).slice(0, 5);
      localFindings.push({
        id: 'LEAKAGE_INTERNAL_IP',
        title: 'Internal RFC 1918 IP Address Leakage',
        severity: 'LOW',
        category: 'information_disclosure',
        description: `Discovered private intranet IP address(es) [${uniqueIps.join(', ')}] in client assets.`,
        evidence: { ips: uniqueIps, url }
      });
    }

    // 4. Exposed Secrets (AWS, Slack, GitHub, Stripe, Private Keys)
    for (const [keyName, pattern] of Object.entries(SECRET_PATTERNS)) {
      if (pattern.test(content)) {
        localFindings.push({
          id: `LEAKAGE_HARDCODED_${keyName}`,
          title: `Exposed Hardcoded Credential: ${keyName}`,
          severity: 'CRITICAL',
          category: 'secret_leakage',
          description: `Detected high-entropy pattern matching a production secret or API key (${keyName}).`,
          evidence: { secretType: keyName, url }
        });
      }
    }

    this.findings.push(...localFindings);
    return localFindings;
  }

  /**
   * Evaluates forms for dangerous cleartext submission or password transmission via GET.
   * @param {Array<Object>} forms
   * @param {string} pageUrl
   * @returns {Array<Object>}
   */
  auditForms(forms = [], pageUrl = '') {
    const findings = [];
    const isPageHttps = pageUrl.startsWith('https://');

    for (const form of forms) {
      const action = (form.action || '').trim();
      const method = (form.method || 'GET').toUpperCase();
      const hasPassword = Boolean(form.hasPassword);

      // Password in GET form
      if (hasPassword && method === 'GET') {
        findings.push({
          id: 'FORM_PASSWORD_IN_GET',
          title: 'Password Field Submitted via HTTP GET',
          severity: 'HIGH',
          category: 'credential_security',
          description: 'A form containing a password field submits via GET method. Password will be stored in cleartext in server logs, proxy caches, and browser history.',
          evidence: { action, method }
        });
      }

      // Mixed form submission: HTTPS page -> HTTP action
      if (isPageHttps && action.startsWith('http://') && !action.includes('localhost') && !action.includes('127.0.0.1')) {
        findings.push({
          id: 'FORM_MIXED_SUBMISSION',
          title: 'Insecure Mixed Form Submission',
          severity: 'HIGH',
          category: 'transport_security',
          description: `HTTPS page submits sensitive form data to unencrypted HTTP endpoint (${action}).`,
          evidence: { action, pageUrl }
        });
      }
    }

    this.findings.push(...findings);
    return findings;
  }

  /**
   * Evaluates HTTP response headers for server technology and version leakage.
   * @param {Object} headers
   * @returns {Array<Object>}
   */
  auditHeaders(headers = {}) {
    const findings = [];
    const leakHeaders = [
      { name: 'server', label: 'Web Server' },
      { name: 'x-powered-by', label: 'Backend Runtime' },
      { name: 'x-aspnet-version', label: 'ASP.NET Version' },
      { name: 'x-aspnetmvc-version', label: 'ASP.NET MVC Version' }
    ];

    // Normalize header keys to lowercase
    const normalized = {};
    for (const [k, v] of Object.entries(headers)) {
      if (k && v) normalized[k.toLowerCase()] = String(v);
    }

    for (const h of leakHeaders) {
      const val = normalized[h.name];
      if (val && /\d/.test(val)) { // Checks if version numbers are present
        findings.push({
          id: `HEADER_VERSION_LEAK_${h.name.toUpperCase().replace(/-/g, '_')}`,
          title: `Exact Version Disclosed in ${h.name} Header`,
          severity: 'LOW',
          category: 'information_disclosure',
          description: `Header '${h.name}: ${val}' reveals exact server software version to potential attackers.`,
          evidence: { header: h.name, value: val }
        });
      }
    }

    this.findings.push(...findings);
    return findings;
  }

  getFindings() {
    return [...this.findings];
  }
}
