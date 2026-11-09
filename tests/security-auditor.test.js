/**
 * Tests for Module G: Website Security Auditor
 */

import { assertEqual, assertTrue, assertFalse } from './test-utils.js';
import { auditSecurityHeaders, auditDomSecurity } from '../src/modules/security/security-auditor.js';
import { SEVERITY } from '../src/core/constants.js';

export function runSecurityAuditorTests() {
  // 1. Insecure / Missing Headers Audit
  const emptyHeaders = {};
  const findings = auditSecurityHeaders(emptyHeaders, 'https://example.com');
  assertTrue(findings.some(f => f.id === 'SEC-HSTS-MISSING'), 'Flags missing HSTS');
  assertTrue(findings.some(f => f.id === 'SEC-CSP-MISSING'), 'Flags missing CSP');
  assertTrue(findings.some(f => f.id === 'SEC-CLICKJACKING-DEFENSE-MISSING'), 'Flags missing clickjacking defense');
  assertTrue(findings.some(f => f.id === 'SEC-MIME-SNIFFING-RISK'), 'Flags missing X-Content-Type-Options');
  assertTrue(findings.some(f => f.id === 'SEC-PERMISSIONS-POLICY-MISSING'), 'Flags missing Permissions-Policy');
  assertTrue(findings.some(f => f.id === 'SEC-COOP-MISSING'), 'Flags missing COOP');
  assertTrue(findings.some(f => f.id === 'SEC-COEP-MISSING'), 'Flags missing COEP');

  // 2. CSP Weakness Audit
  const weakCspHeaders = {
    'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval';",
    'strict-transport-security': 'max-age=31536000; includeSubDomains',
    'x-frame-options': 'DENY',
    'x-content-type-options': 'nosniff'
  };
  const cspFindings = auditSecurityHeaders(weakCspHeaders, 'https://example.com');
  assertTrue(cspFindings.some(f => f.id === 'SEC-CSP-UNSAFE-INLINE'), 'Detects unsafe-inline');
  assertTrue(cspFindings.some(f => f.id === 'SEC-CSP-UNSAFE-EVAL'), 'Detects unsafe-eval');
  assertTrue(cspFindings.some(f => f.id === 'SEC-CSP-MISSING-BASE-URI'), 'Detects missing base-uri directive');
  assertFalse(cspFindings.some(f => f.id === 'SEC-HSTS-MISSING'), 'HSTS is properly recognized');

  // CSP Report-Only
  const reportOnlyHeaders = {
    'content-security-policy-report-only': "default-src 'self';"
  };
  const roFindings = auditSecurityHeaders(reportOnlyHeaders, 'https://example.com');
  assertTrue(roFindings.some(f => f.id === 'SEC-CSP-REPORT-ONLY'), 'Flags CSP in report-only mode');

  // 3. CORS Misconfiguration Audit
  const badCors = {
    'access-control-allow-origin': '*',
    'access-control-allow-credentials': 'true'
  };
  const corsFindings = auditSecurityHeaders(badCors, 'https://example.com');
  assertTrue(corsFindings.some(f => f.id === 'SEC-CORS-CRITICAL-MISCONFIG'), 'Flags ACAO * with ACAC true');

  // 4. DOM Security Audit
  const domData = {
    reverseTabnabbingLinks: ['https://external-target.com'],
    externalScriptsWithoutSri: ['https://cdn.example.com/lib.js'],
    mixedContentResources: ['http://example.com/insecure-image.png'],
    insecureForms: ['http://api.example.com/login'],
    javascriptPseudoLinks: ['javascript:void(0)'],
    inlineEventHandlersCount: 12,
    formsMissingCsrf: ['/transfer-funds'],
    sensitiveHiddenInputs: ['client_secret', 'apiKey'],
    insecureBaseTags: ['http://evil.com/']
  };
  const domFindings = auditDomSecurity(domData, 'https://example.com');
  assertTrue(domFindings.some(f => f.id === 'SEC-REVERSE-TABNABBING'), 'Detects reverse tabnabbing links');
  assertTrue(domFindings.some(f => f.id === 'SEC-SRI-MISSING'), 'Detects external scripts without SRI');
  assertTrue(domFindings.some(f => f.id === 'SEC-MIXED-CONTENT'), 'Detects mixed content on HTTPS');
  assertTrue(domFindings.some(f => f.id === 'SEC-INSECURE-FORM'), 'Detects forms submitting over HTTP');
  assertTrue(domFindings.some(f => f.id === 'SEC-DOM-JAVASCRIPT-URL'), 'Detects javascript: links');
  assertTrue(domFindings.some(f => f.id === 'SEC-DOM-INLINE-EVENT-HANDLERS'), 'Detects excessive inline event handlers');
  assertTrue(domFindings.some(f => f.id === 'SEC-FORM-MISSING-CSRF-TOKEN'), 'Detects POST forms missing CSRF tokens');
  assertTrue(domFindings.some(f => f.id === 'SEC-DOM-SENSITIVE-HIDDEN-INPUT'), 'Detects secrets in hidden inputs');
  assertTrue(domFindings.some(f => f.id === 'SEC-DOM-INSECURE-BASE-TAG'), 'Detects insecure base tag');
}
