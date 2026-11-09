/**
 * Tests for Module B: Advanced DNS Analysis Service
 */

import { assertEqual, assertTrue, assertFalse } from './test-utils.js';
import { parseSpfRecord, parseDmarcRecord, identifyMailProviders, identifyNameserverProviders } from '../src/modules/dns/dns-service.js';

export function runDnsServiceTests() {
  // SPF Parsing Tests
  const strictSpf = 'v=spf1 include:_spf.google.com ip4:192.0.2.1 -all';
  const parsedStrict = parseSpfRecord(strictSpf);
  assertTrue(parsedStrict !== null, 'Parses valid SPF');
  assertEqual(parsedStrict.version, 'v=spf1', 'Extracts version');
  assertTrue(parsedStrict.includes.includes('_spf.google.com'), 'Extracts include mechanism');
  assertTrue(parsedStrict.ip4.includes('192.0.2.1'), 'Extracts ip4 mechanism');
  assertTrue(parsedStrict.isStrict, 'Identifies -all as strict');

  const weakSpf = 'v=spf1 +all';
  const parsedWeak = parseSpfRecord(weakSpf);
  assertFalse(parsedWeak.isStrict, '+all is not strict');
  assertTrue(parsedWeak.warnings.length > 0, 'Flags +all warning');

  // DMARC Parsing Tests
  const dmarcReject = 'v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc@example.com';
  const parsedDmarc = parseDmarcRecord(dmarcReject);
  assertTrue(parsedDmarc !== null, 'Parses valid DMARC');
  assertEqual(parsedDmarc.policy, 'reject', 'Identifies p=reject');
  assertTrue(parsedDmarc.isEnforced, 'Policy is enforced');
  assertEqual(parsedDmarc.percentage, 100, 'pct is 100');
  assertEqual(parsedDmarc.rua, 'mailto:dmarc@example.com', 'Extracts rua');

  const dmarcNone = 'v=DMARC1; p=none;';
  const parsedNone = parseDmarcRecord(dmarcNone);
  assertFalse(parsedNone.isEnforced, 'p=none is monitoring only');
  assertTrue(parsedNone.warnings.length > 0, 'Generates warning for p=none and missing rua');

  // Mail & Nameserver Providers Identification
  const mailProviders = identifyMailProviders(['aspmx.l.google.com', 'alt1.aspmx.l.google.com']);
  assertTrue(mailProviders.includes('Google Workspace / Gmail'), 'Identifies Google Workspace');

  const nsProviders = identifyNameserverProviders(['ns1.cloudflare.com', 'ns2.cloudflare.com']);
  assertTrue(nsProviders.includes('Cloudflare'), 'Identifies Cloudflare nameservers');
}
