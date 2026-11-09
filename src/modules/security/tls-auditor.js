/**
 * ScopeLens Platform - TLS Handshake & Certificate Security Auditor
 * Inspects connection protocols, cipher suites, certificate validity periods,
 * and Subject Alternative Names (SAN) captured via Chrome DevTools Protocol.
 */

import { SEVERITY, CONFIDENCE } from '../../core/constants.js';

export class TlsAuditor {
  /**
   * Evaluates security details observed in connection TLS handshakes.
   * @param {Object} securityDetails
   * @param {string} [targetHostname='']
   * @returns {Array<Object>} Discovered TLS findings
   */
  auditTls(securityDetails, targetHostname = '') {
    if (!securityDetails) return [];

    const findings = [];
    const proto = (securityDetails.protocol || '').toUpperCase();
    const now = Date.now();

    // 1. Deprecated / Insecure TLS Protocols
    if (/SSL|TLS\s*1\.0|TLS\s*1\.1/i.test(proto)) {
      findings.push({
        id: 'SEC-TLS-DEPRECATED-PROTOCOL',
        category: 'Transport Security',
        title: `Deprecated & Insecure TLS Protocol: ${securityDetails.protocol}`,
        description: `The remote server negotiated an obsolete protocol version (${securityDetails.protocol}). Deprecated by IETF (RFC 8996).`,
        severity: SEVERITY.CRITICAL,
        confidence: CONFIDENCE.CONFIRMED,
        evidence: `Protocol: ${securityDetails.protocol}, Cipher: ${securityDetails.cipher || 'unknown'}`,
        affectedResource: targetHostname || 'Target Host',
        explanation: 'TLS 1.0 and 1.1 have known cryptographic vulnerabilities (BEAST, POODLE, CRIME) and are disabled by modern browsers.',
        remediation: 'Upgrade web server configuration to support only TLS 1.2 and TLS 1.3.'
      });
    }

    // 2. Certificate Validity & Expiration Analysis
    if (securityDetails.validTo) {
      const validToMs = typeof securityDetails.validTo === 'number'
        ? (securityDetails.validTo > 1e11 ? securityDetails.validTo : securityDetails.validTo * 1000)
        : new Date(securityDetails.validTo).getTime();

      const msUntilExpiry = validToMs - now;
      const daysUntilExpiry = Math.floor(msUntilExpiry / (1000 * 60 * 60 * 24));

      if (msUntilExpiry <= 0) {
        findings.push({
          id: 'SEC-TLS-CERT-EXPIRED',
          category: 'Transport Security',
          title: 'SSL/TLS Certificate Has Expired',
          description: `The certificate presented by the server expired on ${new Date(validToMs).toUTCString()}.`,
          severity: SEVERITY.CRITICAL,
          confidence: CONFIDENCE.CONFIRMED,
          evidence: `Expired on: ${new Date(validToMs).toISOString()}`,
          affectedResource: targetHostname || 'Target Host',
          explanation: 'Expired certificates break cryptographic trust and prompt full-screen security warnings in browsers.',
          remediation: 'Renew and deploy a valid SSL/TLS certificate immediately.'
        });
      } else if (daysUntilExpiry <= 14) {
        findings.push({
          id: 'SEC-TLS-CERT-EXPIRING-URGENT',
          category: 'Transport Security',
          title: `SSL/TLS Certificate Expiring Soon (${daysUntilExpiry} days)`,
          description: `The SSL certificate expires in ${daysUntilExpiry} day(s) on ${new Date(validToMs).toLocaleDateString()}.`,
          severity: SEVERITY.HIGH,
          confidence: CONFIDENCE.CONFIRMED,
          evidence: `Expires in ${daysUntilExpiry} days`,
          affectedResource: targetHostname || 'Target Host',
          explanation: 'Certificates nearing expiration risk unexpected outages and service degradation.',
          remediation: 'Trigger automated certificate renewal via ACME / Let\'s Encrypt.'
        });
      } else if (daysUntilExpiry <= 30) {
        findings.push({
          id: 'SEC-TLS-CERT-EXPIRING-WARN',
          category: 'Transport Security',
          title: `SSL/TLS Certificate Approaching Renewal (${daysUntilExpiry} days)`,
          description: `The certificate is within the 30-day renewal window.`,
          severity: SEVERITY.LOW,
          confidence: CONFIDENCE.CONFIRMED,
          evidence: `Expires in ${daysUntilExpiry} days`,
          affectedResource: targetHostname || 'Target Host',
          explanation: 'Standard certificate lifecycle management recommends initiating renewal 30 days prior to expiry.',
          remediation: 'Verify renewal automation is active.'
        });
      }
    }

    // 3. Subject Alternative Name (SAN) Validation
    if (targetHostname && Array.isArray(securityDetails.sanList) && securityDetails.sanList.length > 0) {
      const cleanHost = targetHostname.toLowerCase();
      const matchesSan = securityDetails.sanList.some(san => {
        const s = san.toLowerCase();
        if (s === cleanHost) return true;
        if (s.startsWith('*.') && cleanHost.endsWith(s.slice(2))) return true;
        return false;
      });

      if (!matchesSan) {
        findings.push({
          id: 'SEC-TLS-SAN-MISMATCH',
          category: 'Transport Security',
          title: 'Target Hostname Missing from Certificate SAN List',
          description: `The hostname '${targetHostname}' does not match any entry in the certificate's Subject Alternative Names.`,
          severity: SEVERITY.HIGH,
          confidence: CONFIDENCE.CONFIRMED,
          evidence: `SAN list: ${securityDetails.sanList.slice(0, 5).join(', ')}`,
          affectedResource: targetHostname,
          explanation: 'Browsers require the visited hostname to appear explicitly in the certificate SAN extension.',
          remediation: 'Reissue the certificate to include the exact domain name or a matching wildcard.'
        });
      }
    }

    return findings;
  }
}
