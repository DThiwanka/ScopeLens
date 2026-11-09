/**
 * Tests for Module A: IP & Network Intelligence Analyzer
 */

import { assertEqual, assertTrue } from './test-utils.js';
import { getIpType, classifyIpScope, analyzeIpIntelligence, IP_TYPES, IP_SCOPES } from '../src/modules/ip-network/ip-analyzer.js';

export function runIpAnalyzerTests() {
  // IP Type Tests
  assertEqual(getIpType('192.168.1.1'), IP_TYPES.IPV4, 'Detects IPv4');
  assertEqual(getIpType('8.8.8.8'), IP_TYPES.IPV4, 'Detects IPv4 public');
  assertEqual(getIpType('2606:4700:4700::1111'), IP_TYPES.IPV6, 'Detects IPv6');
  assertEqual(getIpType('::1'), IP_TYPES.IPV6, 'Detects IPv6 loopback');
  assertEqual(getIpType('invalid-ip'), IP_TYPES.UNKNOWN, 'Detects invalid IP');

  // Scope Classifications
  assertEqual(classifyIpScope('127.0.0.1'), IP_SCOPES.LOOPBACK, 'IPv4 127.0.0.1 is loopback');
  assertEqual(classifyIpScope('10.0.0.1'), IP_SCOPES.PRIVATE, 'IPv4 10.x is private RFC 1918');
  assertEqual(classifyIpScope('172.16.0.5'), IP_SCOPES.PRIVATE, 'IPv4 172.16.x is private RFC 1918');
  assertEqual(classifyIpScope('192.168.1.254'), IP_SCOPES.PRIVATE, 'IPv4 192.168.x is private RFC 1918');
  assertEqual(classifyIpScope('169.254.1.1'), IP_SCOPES.LINK_LOCAL, 'IPv4 169.254 is link-local');
  assertEqual(classifyIpScope('100.64.0.1'), IP_SCOPES.CARRIER_GRADE_NAT, 'IPv4 100.64 is CGNAT');
  assertEqual(classifyIpScope('1.1.1.1'), IP_SCOPES.PUBLIC, 'IPv4 1.1.1.1 is public');
  assertEqual(classifyIpScope('::1'), IP_SCOPES.LOOPBACK, 'IPv6 ::1 is loopback');

  // Traffic Analysis & Grouping
  const mockRecords = [
    { url: 'https://example.com/api', remoteIp: '93.184.216.34', remotePort: 443, status: 200, protocol: 'h2', seenAt: '2026-01-01T00:00:00Z' },
    { url: 'https://example.com/logo.png', remoteIp: '93.184.216.34', remotePort: 443, status: 200, protocol: 'h2', seenAt: '2026-01-01T00:00:01Z' },
    { url: 'https://cdn.example.com/bundle.js', remoteIp: '104.16.1.1', remotePort: 443, status: 200, protocol: 'h2', seenAt: '2026-01-01T00:00:02Z' },
    { url: 'https://analytics.thirdparty.com/collect', remoteIp: '142.250.190.46', remotePort: 443, status: 204, protocol: 'h2', seenAt: '2026-01-01T00:00:03Z' }
  ];

  const analysis = analyzeIpIntelligence(mockRecords, 'https://example.com');
  assertEqual(analysis.totalRecords, 4, 'Total records matches');
  assertEqual(analysis.distinctIps, 3, 'Distinct IP count matches');
  assertEqual(analysis.observedPorts.length, 1, 'Observed ports count');
  assertEqual(analysis.observedPorts[0], 443, 'Port 443 observed');
  assertTrue(analysis.firstPartyRequests >= 2, 'Counts first-party requests');
}
