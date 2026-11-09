/**
 * Module G - Website Security Auditor
 * Performs comprehensive passive security checks against HTTP response headers,
 * cookie attributes, mixed content, CORS policies, SRI, reverse tabnabbing, and TLS.
 */

import { SEVERITY, CONFIDENCE } from '../../core/constants.js';

/**
 * Normalizes header keys to lowercase.
 * @param {Record<string, string>|Array<{name: string, value: string}>} rawHeaders
 * @returns {Record<string, string>}
 */
function normalizeHeaders(rawHeaders) {
  const norm = {};
  if (!rawHeaders) return norm;
  if (Array.isArray(rawHeaders)) {
    rawHeaders.forEach(({ name, value }) => {
      norm[name.toLowerCase()] = String(value || '').trim();
    });
  } else if (typeof rawHeaders === 'object') {
    Object.entries(rawHeaders).forEach(([k, v]) => {
      norm[k.toLowerCase()] = String(v || '').trim();
    });
  }
  return norm;
}

/**
 * Audits HTTP response headers for defensive security configurations.
 * @param {Record<string, string>} headers
 * @param {string} targetUrl
 * @returns {Array<Object>}
 */
export function auditSecurityHeaders(headers, targetUrl = '') {
  const norm = normalizeHeaders(headers);
  const findings = [];

  const isHttps = targetUrl.startsWith('https://');

  // 1. Strict-Transport-Security (HSTS)
  if (isHttps) {
    const hsts = norm['strict-transport-security'];
    if (!hsts) {
      findings.push({
        id: 'SEC-HSTS-MISSING',
        category: 'HTTP Headers',
        title: 'Missing Strict-Transport-Security (HSTS) Header',
        description: 'The server does not enforce HTTPS connections via HSTS, leaving users vulnerable to SSL-stripping and man-in-the-middle attacks.',
        severity: SEVERITY.HIGH,
        confidence: CONFIDENCE.CONFIRMED,
        evidence: 'Strict-Transport-Security header is absent.',
        affectedResource: targetUrl,
        explanation: 'HSTS instructs compliant browsers to only communicate with the origin over HTTPS for a specified duration, preventing downgrade attacks.',
        remediation: 'Add the header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'
      });
    } else {
      const match = hsts.match(/max-age=(\d+)/i);
      const maxAge = match ? parseInt(match[1], 10) : 0;
      if (maxAge < 15552000) { // < 180 days
        findings.push({
          id: 'SEC-HSTS-SHORT-MAXAGE',
          category: 'HTTP Headers',
          title: 'HSTS Max-Age Duration is Short',
          description: `The HSTS max-age is set to ${maxAge} seconds (less than 180 days).`,
          severity: SEVERITY.LOW,
          confidence: CONFIDENCE.CONFIRMED,
          evidence: `Strict-Transport-Security: ${hsts}`,
          affectedResource: targetUrl,
          explanation: 'Industry standards require max-age to be at least 180 days (15552000s), ideally 1 year (31536000s).',
          remediation: 'Increase max-age to at least 31536000 seconds.'
        });
      }
    }
  }

  // 2. Content-Security-Policy (CSP)
  const csp = norm['content-security-policy'];
  const cspReportOnly = norm['content-security-policy-report-only'];

  if (!csp) {
    if (cspReportOnly) {
      findings.push({
        id: 'SEC-CSP-REPORT-ONLY',
        category: 'HTTP Headers',
        title: 'CSP is Configured in Report-Only Mode (Not Enforced)',
        description: 'The Content Security Policy is only running in Content-Security-Policy-Report-Only mode. Violations are logged, but malicious script execution and data exfiltration are NOT blocked by the browser.',
        severity: SEVERITY.MEDIUM,
        confidence: CONFIDENCE.CONFIRMED,
        evidence: 'Content-Security-Policy-Report-Only is present, but Content-Security-Policy is absent.',
        affectedResource: targetUrl,
        explanation: 'Report-Only mode is meant for testing and deployment validation; it does not protect active users against real XSS attacks.',
        remediation: 'Migrate validated policies to the enforcing Content-Security-Policy header.'
      });
    } else {
      findings.push({
        id: 'SEC-CSP-MISSING',
        category: 'HTTP Headers',
        title: 'Missing Content-Security-Policy (CSP)',
        description: 'The website has not defined a Content Security Policy header, providing no defense-in-depth against Cross-Site Scripting (XSS) and data injection.',
        severity: SEVERITY.HIGH,
        confidence: CONFIDENCE.CONFIRMED,
        evidence: 'Content-Security-Policy header is absent.',
        affectedResource: targetUrl,
        explanation: 'CSP is a fundamental layer that restricts where scripts, images, and other resources can be loaded from and executed.',
        remediation: 'Implement a restrictive CSP starting with: default-src \'self\'; object-src \'none\'; base-uri \'self\';'
      });
    }
  } else {
    const hasUnsafeInline = /'unsafe-inline'/i.test(csp);
    const hasUnsafeEval = /'unsafe-eval'/i.test(csp);
    const hasBaseUri = /base-uri/i.test(csp);
    const hasObjectSrc = /object-src/i.test(csp);
    const hasDefaultSrc = /default-src/i.test(csp);

    if (hasUnsafeInline) {
      findings.push({
        id: 'SEC-CSP-UNSAFE-INLINE',
        category: 'HTTP Headers',
        title: 'CSP Allows \'unsafe-inline\' Scripts',
        description: 'The Content Security Policy allows execution of inline scripts via \'unsafe-inline\', substantially reducing protection against XSS.',
        severity: SEVERITY.MEDIUM,
        confidence: CONFIDENCE.CONFIRMED,
        evidence: `Directives contain: 'unsafe-inline'`,
        affectedResource: targetUrl,
        explanation: 'Attackers who inject HTML tags can execute arbitrary inline scripts because \'unsafe-inline\' bypasses execution restrictions.',
        remediation: 'Replace \'unsafe-inline\' with cryptographic nonces (\'nonce-...\') or hashes (\'sha256-...\').'
      });
    }

    if (hasUnsafeEval) {
      findings.push({
        id: 'SEC-CSP-UNSAFE-EVAL',
        category: 'HTTP Headers',
        title: 'CSP Allows \'unsafe-eval\' Dynamic Execution',
        description: 'The Content Security Policy permits eval(), Function(), and dynamic string-to-code execution.',
        severity: SEVERITY.LOW,
        confidence: CONFIDENCE.CONFIRMED,
        evidence: `Directives contain: 'unsafe-eval'`,
        affectedResource: targetUrl,
        explanation: 'Dynamic string evaluation can turn user input into executable code if untrusted data reaches eval sinks.',
        remediation: 'Refactor code to avoid dynamic code generation and remove \'unsafe-eval\'.'
      });
    }

    if (!hasBaseUri) {
      findings.push({
        id: 'SEC-CSP-MISSING-BASE-URI',
        category: 'HTTP Headers',
        title: 'CSP Missing base-uri Directive (Base Tag Hijacking)',
        description: 'The Content Security Policy lacks a base-uri directive, allowing injected <base> tags to redirect relative script, image, and form URLs to an external server.',
        severity: SEVERITY.LOW,
        confidence: CONFIDENCE.CONFIRMED,
        evidence: 'base-uri directive is omitted in CSP.',
        affectedResource: targetUrl,
        explanation: 'Attackers who inject a <base href="https://attacker.com"> tag can hijack relative script loads without executing inline script.',
        remediation: 'Add: base-uri \'self\'; to your Content-Security-Policy.'
      });
    }

    if (!hasObjectSrc && !hasDefaultSrc) {
      findings.push({
        id: 'SEC-CSP-MISSING-OBJECT-SRC',
        category: 'HTTP Headers',
        title: 'CSP Missing object-src Directive',
        description: 'The Content Security Policy does not restrict plugin execution (<object>, <embed>, <applet>).',
        severity: SEVERITY.LOW,
        confidence: CONFIDENCE.CONFIRMED,
        evidence: 'object-src and default-src directives are both absent in CSP.',
        affectedResource: targetUrl,
        explanation: 'Disabling legacy plugins prevents malicious Flash or Java applet execution in supporting environments.',
        remediation: 'Add: object-src \'none\'; to your Content-Security-Policy.'
      });
    }
  }

  // 3. X-Frame-Options & frame-ancestors
  const xfo = norm['x-frame-options'];
  const hasFrameAncestors = csp && /frame-ancestors/i.test(csp);

  if (!xfo && !hasFrameAncestors) {
    findings.push({
      id: 'SEC-CLICKJACKING-DEFENSE-MISSING',
      category: 'HTTP Headers',
      title: 'Missing Clickjacking Defense (X-Frame-Options / frame-ancestors)',
      description: 'The page does not specify framing restrictions, allowing hostile third-party websites to embed it inside an invisible iframe for clickjacking.',
      severity: SEVERITY.MEDIUM,
      confidence: CONFIDENCE.CONFIRMED,
      evidence: 'Neither X-Frame-Options nor CSP frame-ancestors is present.',
      affectedResource: targetUrl,
      explanation: 'Clickjacking deceives users into clicking transparent buttons overlaid on legitimate pages.',
      remediation: 'Add: X-Frame-Options: SAMEORIGIN (or CSP: frame-ancestors \'self\').'
    });
  }

  // 4. X-Content-Type-Options
  const xcto = norm['x-content-type-options'];
  if (!xcto || !xcto.toLowerCase().includes('nosniff')) {
    findings.push({
      id: 'SEC-MIME-SNIFFING-RISK',
      category: 'HTTP Headers',
      title: 'Missing X-Content-Type-Options: nosniff',
      description: 'The browser is not instructed to enforce declared MIME types, leaving it vulnerable to MIME-type confusion attacks.',
      severity: SEVERITY.LOW,
      confidence: CONFIDENCE.CONFIRMED,
      evidence: `X-Content-Type-Options: ${xcto || 'absent'}`,
      affectedResource: targetUrl,
      explanation: 'MIME sniffing can cause browsers to execute malicious files disguised as benign images or text.',
      remediation: 'Add the header: X-Content-Type-Options: nosniff'
    });
  }

  // 5. Referrer-Policy
  const refPol = norm['referrer-policy'];
  if (!refPol || refPol.toLowerCase().includes('unsafe-url')) {
    findings.push({
      id: 'SEC-REFERRER-POLICY-WEAK',
      category: 'HTTP Headers',
      title: 'Weak or Missing Referrer-Policy',
      description: refPol ? 'Referrer-Policy is set to unsafe-url.' : 'No Referrer-Policy header is configured.',
      severity: SEVERITY.LOW,
      confidence: CONFIDENCE.CONFIRMED,
      evidence: `Referrer-Policy: ${refPol || 'absent'}`,
      affectedResource: targetUrl,
      explanation: 'Without a strict referrer policy, sensitive URL parameters (such as tokens or reset IDs) may leak to third-party domains.',
      remediation: 'Set: Referrer-Policy: strict-origin-when-cross-origin (or no-referrer).'
    });
  }

  // 6. Technology Information Disclosure
  const server = norm['server'];
  const xPoweredBy = norm['x-powered-by'];
  const disclosesVersions = Boolean((xPoweredBy && xPoweredBy.length > 0) || (server && /[\d.]/.test(server)));

  if (disclosesVersions) {
    findings.push({
      id: 'SEC-TECH-DISCLOSURE',
      category: 'Information Disclosure',
      title: 'Server Version Disclosure in Response Headers',
      description: 'The server discloses underlying software names and version numbers in response headers.',
      severity: SEVERITY.INFORMATIONAL,
      confidence: CONFIDENCE.CONFIRMED,
      evidence: `Headers: Server="${server || ''}", X-Powered-By="${xPoweredBy || ''}"`,
      affectedResource: targetUrl,
      explanation: 'Disclosing exact software versions assists attackers in finding matching CVE exploits.',
      remediation: 'Configure the web server to suppress the Server and X-Powered-By headers.'
    });
  }

  // 7. CORS Misconfiguration
  const acao = norm['access-control-allow-origin'];
  const acac = norm['access-control-allow-credentials'];

  if (acao === '*' && acac === 'true') {
    findings.push({
      id: 'SEC-CORS-CRITICAL-MISCONFIG',
      category: 'CORS Configuration',
      title: 'Dangerous CORS Misconfiguration: Wildcard with Credentials',
      description: 'Access-Control-Allow-Origin is set to \'*\' while Access-Control-Allow-Credentials is \'true\'.',
      severity: SEVERITY.HIGH,
      confidence: CONFIDENCE.CONFIRMED,
      evidence: `ACAO: *, ACAC: ${acac}`,
      affectedResource: targetUrl,
      explanation: 'While modern browsers block this combination, it indicates severe CORS configuration flaws and potential API exposure.',
      remediation: 'Do not allow wildcard origins when authentication credentials are used.'
    });
  } else if (acao === '*') {
    findings.push({
      id: 'SEC-CORS-WILDCARD',
      category: 'CORS Configuration',
      title: 'CORS Configured with Wildcard (*)',
      description: 'The resource allows cross-origin reading from any domain via Access-Control-Allow-Origin: *.',
      severity: SEVERITY.INFORMATIONAL,
      confidence: CONFIDENCE.CONFIRMED,
      evidence: `Access-Control-Allow-Origin: *`,
      affectedResource: targetUrl,
      explanation: 'If this resource contains sensitive user data, any website can access and read the contents via fetch.',
      remediation: 'Ensure only public, non-authenticated resources use wildcard CORS.'
    });
  }

  // 8. Permissions-Policy (formerly Feature-Policy)
  const permPol = norm['permissions-policy'] || norm['feature-policy'];
  if (!permPol) {
    findings.push({
      id: 'SEC-PERMISSIONS-POLICY-MISSING',
      category: 'HTTP Headers',
      title: 'Missing Permissions-Policy Header',
      description: 'The website has not configured a Permissions-Policy header to restrict powerful browser capabilities (camera, microphone, geolocation, payment, USB).',
      severity: SEVERITY.LOW,
      confidence: CONFIDENCE.CONFIRMED,
      evidence: 'Permissions-Policy header is absent.',
      affectedResource: targetUrl,
      explanation: 'Without Permissions-Policy, third-party iframes embedded on the page can request access to sensitive device APIs.',
      remediation: 'Define: Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()'
    });
  }

  // 9. Cross-Origin Isolation (COOP & COEP)
  const coop = norm['cross-origin-opener-policy'];
  const coep = norm['cross-origin-embedder-policy'];

  if (!coop) {
    findings.push({
      id: 'SEC-COOP-MISSING',
      category: 'Process Isolation',
      title: 'Missing Cross-Origin-Opener-Policy (COOP)',
      description: 'The document does not isolate its browsing context group via Cross-Origin-Opener-Policy.',
      severity: SEVERITY.INFORMATIONAL,
      confidence: CONFIDENCE.CONFIRMED,
      evidence: 'Cross-Origin-Opener-Policy header is absent.',
      affectedResource: targetUrl,
      explanation: 'COOP prevents malicious cross-origin pages from opening your site in a popup and retaining a window reference for XS-Leaks or timing attacks.',
      remediation: 'Add the header: Cross-Origin-Opener-Policy: same-origin'
    });
  }

  if (!coep) {
    findings.push({
      id: 'SEC-COEP-MISSING',
      category: 'Process Isolation',
      title: 'Missing Cross-Origin-Embedder-Policy (COEP)',
      description: 'The document does not prevent loading cross-origin resources that have not granted explicit permission.',
      severity: SEVERITY.INFORMATIONAL,
      confidence: CONFIDENCE.CONFIRMED,
      evidence: 'Cross-Origin-Embedder-Policy header is absent.',
      affectedResource: targetUrl,
      explanation: 'COEP protects against side-channel memory leakage attacks like Spectre and enables high-resolution timers and SharedArrayBuffer.',
      remediation: 'Add: Cross-Origin-Embedder-Policy: require-corp'
    });
  }

  // 10. Clear-Site-Data on logout / session termination
  if (/logout|signout|endsession|disconnect/i.test(targetUrl)) {
    const csd = norm['clear-site-data'];
    if (!csd) {
      findings.push({
        id: 'SEC-CLEAR-SITE-DATA-MISSING',
        category: 'Session Security',
        title: 'Missing Clear-Site-Data Header on Logout Endpoint',
        description: 'The signout/logout endpoint does not instruct the browser to purge local session artifacts using Clear-Site-Data.',
        severity: SEVERITY.LOW,
        confidence: CONFIDENCE.CONFIRMED,
        evidence: `Target URL: ${targetUrl}, Clear-Site-Data: absent`,
        affectedResource: targetUrl,
        explanation: 'Clear-Site-Data ensures that cached credentials, cookies, and localStorage tokens are wiped on shared or public computers upon signout.',
        remediation: 'Return the header: Clear-Site-Data: "cache", "cookies", "storage"'
      });
    }
  }

  return findings;
}

/**
 * Audits DOM-level vulnerabilities such as Reverse Tabnabbing, Mixed Content,
 * missing Subresource Integrity (SRI), and insecure form submissions.
 * @param {Object} domData
 * @param {string} targetUrl
 * @returns {Array<Object>}
 */
export function auditDomSecurity(domData = {}, targetUrl = '') {
  const findings = [];
  const isHttps = targetUrl.startsWith('https://');

  const {
    reverseTabnabbingLinks = [],
    externalScriptsWithoutSri = [],
    mixedContentResources = [],
    insecureForms = [],
    javascriptPseudoLinks = [],
    inlineEventHandlersCount = 0,
    formsMissingCsrf = [],
    sensitiveHiddenInputs = [],
    insecureBaseTags = []
  } = domData;

  // 1. Reverse Tabnabbing
  if (reverseTabnabbingLinks.length > 0) {
    findings.push({
      id: 'SEC-REVERSE-TABNABBING',
      category: 'DOM Security',
      title: 'Links with target="_blank" Missing rel="noopener"',
      description: `Detected ${reverseTabnabbingLinks.length} external link(s) opening in a new tab without rel="noopener" or rel="noreferrer".`,
      severity: SEVERITY.LOW,
      confidence: CONFIDENCE.CONFIRMED,
      evidence: `Links: ${reverseTabnabbingLinks.slice(0, 3).join(', ')}${reverseTabnabbingLinks.length > 3 ? '...' : ''}`,
      affectedResource: targetUrl,
      explanation: 'Without rel="noopener", the newly opened page gains a window.opener reference and can redirect the source tab to a phishing page.',
      remediation: 'Add rel="noopener noreferrer" to all anchor tags using target="_blank".'
    });
  }

  // 2. Subresource Integrity (SRI) on External Scripts
  if (externalScriptsWithoutSri.length > 0) {
    findings.push({
      id: 'SEC-SRI-MISSING',
      category: 'Supply Chain Security',
      title: 'External Third-Party Scripts Missing Subresource Integrity (SRI)',
      description: `${externalScriptsWithoutSri.length} third-party script(s) loaded from CDNs lack the cryptographic integrity attribute.`,
      severity: SEVERITY.LOW,
      confidence: CONFIDENCE.CONFIRMED,
      evidence: `Scripts: ${externalScriptsWithoutSri.slice(0, 3).join(', ')}${externalScriptsWithoutSri.length > 3 ? '...' : ''}`,
      affectedResource: targetUrl,
      explanation: 'If the external CDN is compromised or malicious code is pushed, the browser will execute the altered script without warning.',
      remediation: 'Add integrity="sha384-..." and crossorigin="anonymous" to all external script tags.'
    });
  }

  // 3. Mixed Content on HTTPS
  if (isHttps && mixedContentResources.length > 0) {
    findings.push({
      id: 'SEC-MIXED-CONTENT',
      category: 'Transport Security',
      title: 'Insecure Mixed Content Detected on HTTPS Origin',
      description: `The page references ${mixedContentResources.length} unencrypted (http://) subresource(s).`,
      severity: SEVERITY.MEDIUM,
      confidence: CONFIDENCE.CONFIRMED,
      evidence: `Insecure assets: ${mixedContentResources.slice(0, 3).join(', ')}${mixedContentResources.length > 3 ? '...' : ''}`,
      affectedResource: targetUrl,
      explanation: 'Mixed content degrades the TLS security guarantees and allows active or passive network eavesdropping on those assets.',
      remediation: 'Migrate all resource URLs (scripts, stylesheets, images) to https:// or use protocol-relative paths.'
    });
  }

  // 4. Insecure Form Submissions
  if (insecureForms.length > 0) {
    findings.push({
      id: 'SEC-INSECURE-FORM',
      category: 'DOM Security',
      title: 'Form Action Points to Insecure HTTP Endpoint',
      description: `Found ${insecureForms.length} HTML form(s) submitting data over unencrypted HTTP.`,
      severity: SEVERITY.HIGH,
      confidence: CONFIDENCE.CONFIRMED,
      evidence: `Form targets: ${insecureForms.slice(0, 2).join(', ')}`,
      affectedResource: targetUrl,
      explanation: 'Form submissions sent over HTTP transmit credentials and user input in cleartext across the network.',
      remediation: 'Ensure all form action attributes point to https:// endpoints.'
    });
  }

  // 5. javascript: Pseudo-Protocol Links
  if (javascriptPseudoLinks.length > 0) {
    findings.push({
      id: 'SEC-DOM-JAVASCRIPT-URL',
      category: 'DOM Security',
      title: 'Links Using Dangerous javascript: Pseudo-Protocol',
      description: `Discovered ${javascriptPseudoLinks.length} anchor tag(s) using "javascript:..." execution URLs.`,
      severity: SEVERITY.LOW,
      confidence: CONFIDENCE.CONFIRMED,
      evidence: `Sample links: ${javascriptPseudoLinks.slice(0, 3).join(', ')}`,
      affectedResource: targetUrl,
      explanation: 'Using javascript: URLs in href attributes bypasses script isolation, violates modern CSP, and provides a direct injection vector for DOM XSS.',
      remediation: 'Refactor inline javascript: links to use standard DOM event listeners.'
    });
  }

  // 6. Excessive Inline Event Handlers
  if (inlineEventHandlersCount > 5) {
    findings.push({
      id: 'SEC-DOM-INLINE-EVENT-HANDLERS',
      category: 'DOM Security',
      title: 'Extensive Use of Inline HTML Event Handlers',
      description: `Observed ${inlineEventHandlersCount} DOM elements with inline event attributes (onclick, onload, onerror, etc.).`,
      severity: SEVERITY.LOW,
      confidence: CONFIDENCE.CONFIRMED,
      evidence: `Total inline handlers count: ${inlineEventHandlersCount}`,
      affectedResource: targetUrl,
      explanation: 'Inline event handlers prevent enforcing a strict Content Security Policy without \'unsafe-inline\', weakening XSS defense-in-depth.',
      remediation: 'Attach event handlers via addEventListener() in external scripts.'
    });
  }

  // 7. POST Forms Missing Anti-CSRF Token
  if (formsMissingCsrf.length > 0) {
    findings.push({
      id: 'SEC-FORM-MISSING-CSRF-TOKEN',
      category: 'Session Security',
      title: 'State-Changing POST Form Missing Anti-CSRF Protection',
      description: `Found ${formsMissingCsrf.length} POST form(s) without an apparent anti-CSRF token input field.`,
      severity: SEVERITY.MEDIUM,
      confidence: CONFIDENCE.CONFIRMED,
      evidence: `Target forms: ${formsMissingCsrf.slice(0, 3).join(', ')}`,
      affectedResource: targetUrl,
      explanation: 'State-changing requests without unique, unpredictable tokens can be triggered cross-site by an attacker without user intent.',
      remediation: 'Include a cryptographic CSRF token in a hidden input field or validate modern SameSite cookie policies.'
    });
  }

  // 8. Sensitive Hidden Input Fields Exposed in Public DOM
  if (sensitiveHiddenInputs.length > 0) {
    findings.push({
      id: 'SEC-DOM-SENSITIVE-HIDDEN-INPUT',
      category: 'Information Disclosure',
      title: 'Sensitive Credential Exposed in Hidden Form Input',
      description: `Found ${sensitiveHiddenInputs.length} hidden input field(s) containing secret or credential keys in public DOM.`,
      severity: SEVERITY.HIGH,
      confidence: CONFIDENCE.CONFIRMED,
      evidence: `Input names: ${sensitiveHiddenInputs.slice(0, 3).join(', ')}`,
      affectedResource: targetUrl,
      explanation: 'Embedding client secrets, master API keys, or private tokens in hidden input fields exposes them to any page script or inspectable source.',
      remediation: 'Never embed static secrets in HTML markup; generate short-lived signed tokens on the backend.'
    });
  }

  // 9. Dangerous <base> Tag
  if (insecureBaseTags.length > 0) {
    findings.push({
      id: 'SEC-DOM-INSECURE-BASE-TAG',
      category: 'DOM Security',
      title: 'Insecure or External <base> Tag Specified',
      description: 'Document specifies a <base href="..."> pointing to an external domain or cleartext HTTP.',
      severity: SEVERITY.HIGH,
      confidence: CONFIDENCE.CONFIRMED,
      evidence: `Base targets: ${insecureBaseTags.join(', ')}`,
      affectedResource: targetUrl,
      explanation: 'An external base tag diverts all relative links, images, and script requests to the specified host.',
      remediation: 'Remove the base tag or restrict it to the current origin with CSP base-uri \'self\'.'
    });
  }

  return findings;
}
