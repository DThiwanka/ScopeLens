/**
 * ScopeLens Platform - RFC 9116 security.txt Vulnerability Disclosure Auditor
 * Probes and validates /.well-known/security.txt according to RFC 9116 standards.
 */

import { SEVERITY, CONFIDENCE } from '../../core/constants.js';

export class SecurityTxtAuditor {
  constructor(fetchFn = (typeof fetch !== 'undefined' ? fetch : null)) {
    this.fetchFn = fetchFn;
  }

  /**
   * Fetches and parses security.txt for a given origin.
   * @param {string} targetOrigin
   * @returns {Promise<Object>}
   */
  async probeSecurityTxt(targetOrigin) {
    if (!this.fetchFn || !targetOrigin) {
      return { present: false, findings: [] };
    }

    const cleanOrigin = targetOrigin.replace(/\/+$/, '');
    const candidateUrls = [
      `${cleanOrigin}/.well-known/security.txt`,
      `${cleanOrigin}/security.txt`
    ];

    let foundContent = null;
    let foundUrl = null;

    for (const url of candidateUrls) {
      try {
        const res = await this.fetchFn(url, { cache: 'no-store' });
        if (res.ok) {
          const text = await res.text();
          // Verify it looks like security.txt and not a 404 HTML fallback page
          if (text.includes('Contact:') && !text.includes('<!DOCTYPE html>')) {
            foundContent = text;
            foundUrl = url;
            break;
          }
        }
      } catch {}
    }

    return this.parseAndAudit(foundContent, foundUrl, cleanOrigin);
  }

  /**
   * Parses and validates raw security.txt text against RFC 9116 rules.
   * @param {string|null} content
   * @param {string|null} url
   * @param {string} origin
   * @returns {Object}
   */
  parseAndAudit(content, url, origin) {
    const findings = [];

    if (!content) {
      findings.push({
        id: 'SEC-SECURITY-TXT-MISSING',
        category: 'Vulnerability Disclosure',
        title: 'Missing security.txt (RFC 9116 Vulnerability Disclosure Policy)',
        description: 'The website does not provide a standard /.well-known/security.txt file for security researchers.',
        severity: SEVERITY.INFORMATIONAL,
        confidence: CONFIDENCE.CONFIRMED,
        evidence: 'Neither /.well-known/security.txt nor /security.txt returned a valid policy.',
        affectedResource: origin,
        explanation: 'RFC 9116 establishes a standardized machine- and human-readable format for reporting security vulnerabilities responsibly.',
        remediation: 'Create /.well-known/security.txt with at least Contact: and Expires: directives.'
      });

      return {
        present: false,
        fields: {},
        findings
      };
    }

    // Parse lines
    const lines = content.split('\n');
    const fields = {
      contact: [],
      expires: null,
      encryption: [],
      acknowledgments: [],
      preferredLanguages: [],
      canonical: [],
      policy: []
    };

    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (!line || line.startsWith('#')) continue;

      const idx = line.indexOf(':');
      if (idx === -1) continue;

      const key = line.slice(0, idx).trim().toLowerCase();
      const val = line.slice(idx + 1).trim();

      if (key === 'contact') fields.contact.push(val);
      else if (key === 'expires') fields.expires = val;
      else if (key === 'encryption') fields.encryption.push(val);
      else if (key === 'acknowledgments') fields.acknowledgments.push(val);
      else if (key === 'preferred-languages') fields.preferredLanguages.push(val);
      else if (key === 'canonical') fields.canonical.push(val);
      else if (key === 'policy') fields.policy.push(val);
    }

    // Validation 1: Required Contact field
    if (!fields.contact.length) {
      findings.push({
        id: 'SEC-SECURITY-TXT-NO-CONTACT',
        category: 'Vulnerability Disclosure',
        title: 'Invalid security.txt: Missing Required Contact Directive',
        description: 'RFC 9116 requires at least one Contact: directive specifying a valid mailto: or https:// URL.',
        severity: SEVERITY.LOW,
        confidence: CONFIDENCE.CONFIRMED,
        evidence: `URL: ${url}`,
        affectedResource: origin,
        explanation: 'Without a Contact directive, researchers cannot locate the security team.',
        remediation: 'Add: Contact: mailto:security@yourdomain.com'
      });
    }

    // Validation 2: Required Expires field
    if (!fields.expires) {
      findings.push({
        id: 'SEC-SECURITY-TXT-NO-EXPIRES',
        category: 'Vulnerability Disclosure',
        title: 'Invalid security.txt: Missing Required Expires Directive',
        description: 'RFC 9116 requires an Expires: directive indicating when the disclosure policy will be reviewed.',
        severity: SEVERITY.LOW,
        confidence: CONFIDENCE.CONFIRMED,
        evidence: `URL: ${url}`,
        affectedResource: origin,
        explanation: 'The Expires directive prevents stale contact information from persisting indefinitely.',
        remediation: 'Add: Expires: 2027-01-01T00:00:00.000Z'
      });
    } else {
      const expDate = new Date(fields.expires);
      if (isNaN(expDate.getTime())) {
        findings.push({
          id: 'SEC-SECURITY-TXT-INVALID-DATE',
          category: 'Vulnerability Disclosure',
          title: 'Invalid Date in security.txt Expires Field',
          description: `The date format in Expires: "${fields.expires}" does not adhere to RFC 3339 / ISO 8601.`,
          severity: SEVERITY.LOW,
          confidence: CONFIDENCE.CONFIRMED,
          evidence: `Expires: ${fields.expires}`,
          affectedResource: origin,
          explanation: 'Standard parsers require ISO 8601 UTC date formatting.',
          remediation: 'Format date as YYYY-MM-DDTHH:MM:SS.000Z'
        });
      } else if (expDate.getTime() < Date.now()) {
        findings.push({
          id: 'SEC-SECURITY-TXT-EXPIRED',
          category: 'Vulnerability Disclosure',
          title: 'Vulnerability Disclosure Policy (security.txt) Has Expired',
          description: `The policy expired on ${expDate.toUTCString()} and may contain obsolete contact details.`,
          severity: SEVERITY.LOW,
          confidence: CONFIDENCE.CONFIRMED,
          evidence: `Expired on: ${fields.expires}`,
          affectedResource: origin,
          explanation: 'RFC 9116 specifies that expired security.txt files must not be considered valid.',
          remediation: 'Review and update the Expires date to a future timestamp.'
        });
      }
    }

    return {
      present: true,
      url,
      fields,
      findings
    };
  }
}
