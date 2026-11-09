/**
 * Tests for Module K: Smart Findings Engine
 */

import { assertEqual, assertTrue, assertFalse } from './test-utils.js';
import { FindingsEngine } from '../src/modules/findings/findings-engine.js';
import { SEVERITY } from '../src/core/constants.js';

export function runFindingsEngineTests() {
  const engine = new FindingsEngine();

  // Ingest Findings
  const finding1 = {
    id: 'SEC-001',
    category: 'HTTP Headers',
    title: 'Missing HSTS Header',
    severity: SEVERITY.HIGH,
    affectedResource: 'https://example.com'
  };

  const finding2 = {
    id: 'SEC-002',
    category: 'Authentication',
    title: 'Unsigned JWT Token',
    severity: SEVERITY.CRITICAL,
    affectedResource: 'localStorage:token'
  };

  engine.ingest([finding1, finding2], 'SecurityModule');

  // Verify Counts & Stats
  const stats = engine.getStatistics();
  assertEqual(stats.total, 2, 'Total findings is 2');
  assertEqual(stats.critical, 1, 'Critical count is 1');
  assertEqual(stats.high, 1, 'High count is 1');

  // Deduplication check
  engine.ingest(finding1, 'SecurityModule');
  const statsAfterDup = engine.getStatistics();
  assertEqual(statsAfterDup.total, 2, 'Does not duplicate identical finding');

  // Severity Filter Query
  const criticalOnly = engine.query({ severity: SEVERITY.CRITICAL });
  assertEqual(criticalOnly.length, 1, 'Returns only critical findings');
  assertEqual(criticalOnly[0].title, 'Unsigned JWT Token', 'Returns correct critical item');

  // Search Filter Query
  const searchResults = engine.query({ search: 'HSTS' });
  assertEqual(searchResults.length, 1, 'Finds item by keyword search');

  // Dismiss Functionality
  const sig = criticalOnly[0].signature;
  engine.dismiss(sig);
  const activeAfterDismiss = engine.query();
  assertEqual(activeAfterDismiss.length, 1, 'Dismissed finding excluded from active query');
  const withDismissed = engine.query({ includeDismissed: true });
  assertEqual(withDismissed.length, 2, 'Dismissed finding returned when explicitly requested');
}
