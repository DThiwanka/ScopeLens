/**
 * ScopeLens Platform - Automated Master Test Runner
 * Runs all unit, integration, and security regression test suites in Node.js.
 */

import { runIpAnalyzerTests } from './ip-analyzer.test.js';
import { runDnsServiceTests } from './dns-service.test.js';
import { runTokenDetectorTests } from './token-detector.test.js';
import { runRedactorTests } from './redactor.test.js';
import { runSecurityAuditorTests } from './security-auditor.test.js';
import { runTechFingerprintTests } from './tech-fingerprint.test.js';
import { runApiAnalyzerTests } from './api-analyzer.test.js';
import { runFindingsEngineTests } from './findings-engine.test.js';
import { runSnapshotManagerTests } from './snapshot-manager.test.js';
import { runReportGeneratorTests } from './report-generator.test.js';
import { runCorePolicyRetentionTests } from './core-policy-retention.test.js';
import { runAuthFlowMapperTests } from './auth-flow-mapper.test.js';
import { runSourceMapAnalyzerTests } from './sourcemap-analyzer.test.js';
import { runLeakageAnalyzerTests } from './leakage-analyzer.test.js';
import { runTlsSecurityTxtTests } from './tls-security-txt.test.js';
import { runOpenApiGeneratorTests } from './openapi-generator.test.js';
import { runCorsAuditorTests } from './cors-auditor.test.js';
import { runWebSocketInspectorTests } from './websocket-inspector.test.js';

const suites = [
  { name: 'Core: Scope Policy, Storage & Retention Manager', fn: runCorePolicyRetentionTests },
  { name: 'Module A: IP & Network Intelligence Analyzer', fn: runIpAnalyzerTests },
  { name: 'Module B: Advanced DNS & Email Security Service', fn: runDnsServiceTests },
  { name: 'Module D: Token & Authentication Intelligence', fn: runTokenDetectorTests },
  { name: 'Core: Sensitive Credential & URL Redactor', fn: runRedactorTests },
  { name: 'Module G: Website Security & DOM Auditor', fn: runSecurityAuditorTests },
  { name: 'Module F: Technology Fingerprinting Engine', fn: runTechFingerprintTests },
  { name: 'Module H: API Discovery & Route Abstraction', fn: runApiAnalyzerTests },
  { name: 'Module K: Smart Findings Engine & Deduplication', fn: runFindingsEngineTests },
  { name: 'Module M: Snapshots & Differential Comparison', fn: runSnapshotManagerTests },
  { name: 'Module L: Reporting & Export Engine (JSON, HTML, CSV)', fn: runReportGeneratorTests },
  { name: 'Phase 4: Authentication & OAuth/OIDC Flow Mapper', fn: runAuthFlowMapperTests },
  { name: 'Phase 5: Source Map & Dependency Intelligence (SBOM)', fn: runSourceMapAnalyzerTests },
  { name: 'Phase 6: Sensitive Data Leakage & Privacy Analyzer', fn: runLeakageAnalyzerTests },
  { name: 'Security Checkup: TLS Handshake, Cert Expiry & RFC 9116 security.txt', fn: runTlsSecurityTxtTests },
  { name: 'Security & API: OpenAPI 3.0.3 Draft Specification Generator', fn: runOpenApiGeneratorTests },
  { name: 'Security Checkup: Deep CORS & Preflight Cache Auditor', fn: runCorsAuditorTests },
  { name: 'Network Inspector: WebSocket & Server-Sent Events (SSE) Streams', fn: runWebSocketInspectorTests }
];

console.log('================================================================');
console.log('  ScopeLens Platform — Automated Test Suite Runner');
console.log('================================================================\n');

async function runAll() {
  let passedCount = 0;
  let failedCount = 0;
  const startTime = Date.now();

  for (const suite of suites) {
    try {
      await suite.fn();
      console.log(`  ✓ [PASS] ${suite.name}`);
      passedCount++;
    } catch (err) {
      console.error(`  ✗ [FAIL] ${suite.name}`);
      console.error(`     Error: ${err.message}\n${err.stack}\n`);
      failedCount++;
    }
  }

  const duration = Date.now() - startTime;
  console.log('\n----------------------------------------------------------------');
  console.log(`Total Test Suites: ${suites.length}`);
  console.log(`Passed:            ${passedCount}`);
  console.log(`Failed:            ${failedCount}`);
  console.log(`Execution Time:    ${duration} ms`);
  console.log('----------------------------------------------------------------');

  if (failedCount > 0) {
    console.error('\nTests FAILED. Fix issues above.');
    process.exit(1);
  } else {
    console.log('\nAll tests PASSED successfully.');
    process.exit(0);
  }
}

runAll();
