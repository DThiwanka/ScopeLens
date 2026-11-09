/**
 * Tests for Core Architecture: Scope Policy, Persistence & Retention
 */

import { assertEqual, assertTrue } from './test-utils.js';
import { ScopePolicy } from '../src/core/scope-policy.js';
import { ScopeLensStorage } from '../src/core/persistence.js';
import { RetentionManager } from '../src/core/retention.js';

export async function runCorePolicyRetentionTests() {
  // 1. ScopePolicy Tests
  const policy = new ScopePolicy('https://example.com', { allowSubdomains: true });

  assertTrue(policy.isFirstParty('https://example.com/api/test'), 'Same origin is first-party');
  assertTrue(policy.isFirstParty('https://sub.example.com/assets/app.js'), 'Subdomain is first-party with allowSubdomains=true');
  assertTrue(!policy.isFirstParty('https://evil-example.com/'), 'Attacker domain is not first-party');
  assertTrue(!policy.isFirstParty('https://another-domain.com/'), 'External domain is not first-party');

  // Forbidden schemes
  assertTrue(!policy.canObserveMetadata('chrome://settings'), 'Internal chrome:// is rejected');
  assertTrue(!policy.canObserveMetadata('chrome-extension://xyz/popup.html'), 'Internal chrome-extension:// is rejected');

  // Third party approval
  assertTrue(!policy.isApprovedThirdParty('https://api.stripe.com/v1/tokens'), 'Initially not approved');
  policy.approveOrigin('https://api.stripe.com');
  assertTrue(policy.isApprovedThirdParty('https://api.stripe.com/v1/charges'), 'Approved after whitelist');
  assertTrue(policy.canInspectBody('https://api.stripe.com/v1/charges'), 'Approved third-party body inspection allowed');
  policy.revokeOrigin('https://api.stripe.com');
  assertTrue(!policy.isApprovedThirdParty('https://api.stripe.com/v1/charges'), 'Revoked third party');

  // 2. ScopeLensStorage & Memory Fallback Tests
  const storage = new ScopeLensStorage();
  await storage.put('sessions', { id: 'sess_1', startedAt: '2026-01-01T00:00:00Z', topLevelOrigin: 'https://example.com' });
  await storage.put('sessions', { id: 'sess_2', startedAt: '2026-01-02T00:00:00Z', topLevelOrigin: 'https://test.org' });

  const retrieved = await storage.get('sessions', 'sess_1');
  assertEqual(retrieved.topLevelOrigin, 'https://example.com', 'Storage gets stored session');

  const allSessions = await storage.getAll('sessions');
  assertEqual(allSessions.length, 2, 'Storage retrieves all sessions');

  // 3. RetentionManager Tests
  // Populate with 12 sessions, limit maxSessions to 5
  const retention = new RetentionManager(storage, { maxSessions: 5, maxObservations: 10 });
  for (let i = 3; i <= 12; i++) {
    await storage.put('sessions', {
      id: `sess_${i}`,
      startedAt: `2026-01-0${i < 10 ? '0' + i : i}T00:00:00Z`,
      topLevelOrigin: 'https://site' + i + '.com'
    });
  }

  const beforeStats = await retention.getStorageStats();
  assertEqual(beforeStats.sessions, 12, '12 sessions populated');

  const pruneResult = await retention.enforceRetention();
  assertEqual(pruneResult.prunedSessions, 7, 'Pruned 7 excess sessions down to 5');

  const afterStats = await retention.getStorageStats();
  assertEqual(afterStats.sessions, 5, 'Now exactly 5 sessions remaining');

  // Purge all test
  const purgeSuccess = await retention.purgeAllData();
  assertTrue(purgeSuccess, 'Purge all data succeeded');
  const purgedStats = await retention.getStorageStats();
  assertEqual(purgedStats.sessions, 0, 'Sessions count 0 after purge');
}
