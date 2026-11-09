/**
 * Tests for TLS Security Auditor and RFC 9116 security.txt Auditor
 */

import { assertEqual, assertTrue } from './test-utils.js';
import { TlsAuditor } from '../src/modules/security/tls-auditor.js';
import { SecurityTxtAuditor } from '../src/modules/security/security-txt-auditor.js';

export async function runTlsSecurityTxtTests() {
  // 1. TLS Protocol Audit Tests
  const tlsAuditor = new TlsAuditor();

  // Deprecated TLS 1.0 test
  const deprecatedTls = tlsAuditor.auditTls({
    protocol: 'TLS 1.0',
    cipher: 'AES_128_CBC',
    validTo: Date.now() + 1000 * 60 * 60 * 24 * 90 // 90 days in future
  }, 'example.com');

  assertTrue(deprecatedTls.some(f => f.id === 'SEC-TLS-DEPRECATED-PROTOCOL'), 'Detects deprecated TLS 1.0');

  // Expired Certificate Test
  const expiredTls = tlsAuditor.auditTls({
    protocol: 'TLS 1.3',
    cipher: 'AES_256_GCM',
    validTo: Date.now() - 1000 * 60 * 60 * 24 // 1 day in past
  }, 'example.com');

  assertTrue(expiredTls.some(f => f.id === 'SEC-TLS-CERT-EXPIRED'), 'Detects expired SSL/TLS certificate');

  // Certificate Expiring in 7 days test
  const urgentTls = tlsAuditor.auditTls({
    protocol: 'TLS 1.3',
    cipher: 'AES_256_GCM',
    validTo: Date.now() + 1000 * 60 * 60 * 24 * 7 // 7 days in future
  }, 'example.com');

  assertTrue(urgentTls.some(f => f.id === 'SEC-TLS-CERT-EXPIRING-URGENT'), 'Detects certificate expiring in 7 days');

  // SAN Mismatch Test
  const sanMismatch = tlsAuditor.auditTls({
    protocol: 'TLS 1.3',
    cipher: 'AES_256_GCM',
    validTo: Date.now() + 1000 * 60 * 60 * 24 * 100,
    sanList: ['otherdomain.com', '*.otherdomain.com']
  }, 'targetsite.com');

  assertTrue(sanMismatch.some(f => f.id === 'SEC-TLS-SAN-MISMATCH'), 'Detects SAN mismatch with target hostname');

  // 2. RFC 9116 security.txt Auditor Tests
  const mockFetch = async (url) => {
    if (url.includes('missing')) {
      return { ok: false, status: 404 };
    }
    const sampleTxt = `
Contact: mailto:security@example.com
Contact: https://example.com/security
Expires: 2028-12-31T23:59:59.000Z
Encryption: https://example.com/pgp-key.txt
Acknowledgments: https://example.com/hall-of-fame
Preferred-Languages: en, es
Canonical: https://example.com/.well-known/security.txt
Policy: https://example.com/security-policy
`;
    return {
      ok: true,
      status: 200,
      text: async () => sampleTxt
    };
  };

  const secTxtAuditor = new SecurityTxtAuditor(mockFetch);

  // Probe valid security.txt
  const validResult = await secTxtAuditor.probeSecurityTxt('https://example.com');
  assertTrue(validResult.present, 'Identifies valid security.txt');
  assertEqual(validResult.fields.contact.length, 2, 'Extracts 2 contact directives');
  assertEqual(validResult.fields.expires, '2028-12-31T23:59:59.000Z', 'Extracts expires timestamp');
  assertEqual(validResult.findings.length, 0, 'No findings for valid RFC 9116 policy');

  // Probe missing security.txt
  const missingResult = await secTxtAuditor.probeSecurityTxt('https://missing.com');
  assertTrue(!missingResult.present, 'Correctly flags absent security.txt');
  assertTrue(missingResult.findings.some(f => f.id === 'SEC-SECURITY-TXT-MISSING'), 'Flags missing security.txt');

  // Test expired security.txt content parsing
  const expiredParsed = secTxtAuditor.parseAndAudit(`
Contact: mailto:security@example.com
Expires: 2020-01-01T00:00:00.000Z
`, 'https://example.com/.well-known/security.txt', 'https://example.com');
  assertTrue(expiredParsed.findings.some(f => f.id === 'SEC-SECURITY-TXT-EXPIRED'), 'Flags expired security.txt');
}
