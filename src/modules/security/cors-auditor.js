/**
 * ScopeLens Platform - Deep CORS & Preflight Cache Security Auditor
 * Inspects Cross-Origin Resource Sharing configurations, credentials handling,
 * cache poisoning vectors via missing Vary: Origin, and exposed headers.
 */

import { SEVERITY, CONFIDENCE } from '../../core/constants.js';

export class CorsAuditor {
  /**
   * Evaluates HTTP response headers for CORS misconfigurations and cache poisoning risks.
   * @param {Object} headers
   * @param {string} requestUrl
   * @param {string} [requestOrigin='']
   * @returns {Array<Object>} Discovered CORS findings
   */
  auditCors(headers = {}, requestUrl = '', requestOrigin = '') {
    const findings = [];
    const norm = {};
    for (const [k, v] of Object.entries(headers)) {
      if (k && v) norm[k.toLowerCase()] = String(v).trim();
    }

    const acao = norm['access-control-allow-origin'];
    const acac = norm['access-control-allow-credentials'];
    const acam = norm['access-control-allow-methods'];
    const acae = norm['access-control-expose-headers'];
    const acma = norm['access-control-max-age'];
    const vary = norm['vary'] || '';

    if (!acao) return findings;

    // 1. Wildcard origin with credentials allowed
    if (acao === '*' && acac === 'true') {
      findings.push({
        id: 'SEC-CORS-WILDCARD-CREDENTIALS',
        category: 'CORS Configuration',
        title: 'Dangerous CORS: Wildcard Origin Allowed with Credentials',
        description: 'Access-Control-Allow-Origin is set to \'*\' while Access-Control-Allow-Credentials is \'true\'.',
        severity: SEVERITY.HIGH,
        confidence: CONFIDENCE.CONFIRMED,
        evidence: `ACAO: *, ACAC: ${acac}`,
        affectedResource: requestUrl,
        explanation: 'While modern browsers reject this specific header combination, this configuration signals severe server-side access control flaws.',
        remediation: 'Do not use wildcard origins for authenticated APIs.'
      });
    }

    // 2. Origin Reflection without Vary: Origin (CORS Cache Poisoning)
    const isReflectedOrigin = acao !== '*' && acao !== 'null' && (!requestOrigin || acao.includes(requestOrigin) || acao.startsWith('http'));
    const hasVaryOrigin = /origin/i.test(vary);

    if (isReflectedOrigin && !hasVaryOrigin) {
      findings.push({
        id: 'SEC-CORS-CACHE-POISONING-RISK',
        category: 'CORS Configuration',
        title: 'CORS Cache Poisoning Risk: Missing Vary: Origin Header',
        description: `The server reflects an origin in Access-Control-Allow-Origin (${acao}) but omits "Vary: Origin" in response headers.`,
        severity: SEVERITY.MEDIUM,
        confidence: CONFIDENCE.CONFIRMED,
        evidence: `ACAO: ${acao}, Vary: ${vary || '(absent)'}`,
        affectedResource: requestUrl,
        explanation: 'Shared intermediate web caches or CDNs may cache the response for one origin and serve it to subsequent clients from other origins, bypassing CORS or causing denials of service.',
        remediation: 'Add: Vary: Origin to all responses containing dynamic Access-Control-Allow-Origin headers.'
      });
    }

    // 3. Null Origin Allowed
    if (acao === 'null') {
      findings.push({
        id: 'SEC-CORS-NULL-ORIGIN',
        category: 'CORS Configuration',
        title: 'Insecure CORS: "null" Origin Whitelisted',
        description: 'Access-Control-Allow-Origin is configured to allow the "null" origin.',
        severity: SEVERITY.HIGH,
        confidence: CONFIDENCE.CONFIRMED,
        evidence: 'Access-Control-Allow-Origin: null',
        affectedResource: requestUrl,
        explanation: 'Sandboxed iframes, local file URLs, and data: URIs produce a "null" origin. Whitelisting "null" allows hostile sites to embed an iframe and read authenticated cross-origin data.',
        remediation: 'Never whitelist the "null" origin; specify trusted, explicit origins.'
      });
    }

    // 4. Overly Permissive Preflight Cache (Access-Control-Max-Age)
    if (acma) {
      const maxAgeSec = parseInt(acma, 10);
      if (!isNaN(maxAgeSec) && maxAgeSec > 86400) { // > 24 hours
        findings.push({
          id: 'SEC-CORS-LONG-MAX-AGE',
          category: 'CORS Configuration',
          title: 'Excessive Preflight Cache Duration (Access-Control-Max-Age)',
          description: `Access-Control-Max-Age is set to ${maxAgeSec} seconds (> 24 hours).`,
          severity: SEVERITY.INFORMATIONAL,
          confidence: CONFIDENCE.CONFIRMED,
          evidence: `Access-Control-Max-Age: ${acma}`,
          affectedResource: requestUrl,
          explanation: 'Browsers cap preflight caching (Chrome caps at 2 hours / 7200s, Firefox at 24 hours / 86400s). Excessively high values are ignored or indicate stale security policy.',
          remediation: 'Set Access-Control-Max-Age between 600 and 7200 seconds.'
        });
      }
    }

    // 5. Sensitive Headers Exposed via Access-Control-Expose-Headers
    if (acae) {
      const exposed = acae.toLowerCase();
      if (/authorization|set-cookie|cookie|x-api-key/i.test(exposed)) {
        findings.push({
          id: 'SEC-CORS-SENSITIVE-EXPOSE-HEADERS',
          category: 'CORS Configuration',
          title: 'Sensitive Headers Exposed via Access-Control-Expose-Headers',
          description: `Access-Control-Expose-Headers exposes sensitive credentials: ${acae}`,
          severity: SEVERITY.HIGH,
          confidence: CONFIDENCE.CONFIRMED,
          evidence: `Access-Control-Expose-Headers: ${acae}`,
          affectedResource: requestUrl,
          explanation: 'Exposing authentication or cookie headers allows client scripts on external origins to read session credentials.',
          remediation: 'Do not expose authorization, cookie, or API key headers to cross-origin callers.'
        });
      }
    }

    return findings;
  }
}
