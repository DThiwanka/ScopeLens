/**
 * Tests for Module L: Reporting & Export Engine
 */

import { assertEqual, assertTrue, assertFalse } from './test-utils.js';
import { buildJsonReport, exportToCsv, generateHtmlReport, exportToHar } from '../src/modules/reports/report-generator.js';
import { REDACTED_PLACEHOLDER } from '../src/core/redactor.js';

export function runReportGeneratorTests() {
  const mockAudit = {
    origin: 'https://example.com',
    hostname: 'example.com',
    securityGrade: 'B',
    findings: [
      { id: 'SEC-1', severity: 'HIGH', title: 'Missing HSTS', category: 'Headers', affectedResource: 'https://example.com?token=secret123', remediation: 'Add HSTS' }
    ],
    technologies: [
      { name: 'React', category: 'Frontend', version: '18.2.0', confidence: 'CONFIRMED', evidence: 'DOM' }
    ]
  };

  // 1. JSON Report & Redaction
  const jsonReport = buildJsonReport(mockAudit);
  assertEqual(jsonReport.executiveSummary.targetHostname, 'example.com', 'Sets target hostname');
  assertEqual(jsonReport.executiveSummary.securityGrade, 'B', 'Sets security grade');
  assertTrue(jsonReport.findings[0].affectedResource.includes(REDACTED_PLACEHOLDER), 'Sanitizes query parameters in findings');
  assertFalse(jsonReport.findings[0].affectedResource.includes('secret123'), 'Strips raw secret tokens from JSON report');

  // 2. CSV Export
  const csv = exportToCsv(mockAudit.findings, ['id', 'severity', 'title']);
  assertTrue(csv.startsWith('"id","severity","title"'), 'Generates valid CSV header');
  assertTrue(csv.includes('"SEC-1","HIGH","Missing HSTS"'), 'Formats row data properly');

  // 4. HAR 1.2 Export
  const mockRequests = [
    { url: 'https://example.com/api?token=secret123', method: 'GET', status: 200, mimeType: 'application/json', time: 75 }
  ];
  const har = exportToHar(mockRequests, 'https://example.com');
  assertTrue(har.includes('"version": "1.2"'), 'Produces valid HAR 1.2 format');
  assertTrue(har.includes('ScopeLens Web Security Platform'), 'Includes ScopeLens creator metadata');
  assertFalse(har.includes('secret123'), 'Redacts secret token in HAR request URL');
}
