/**
 * Tests for Module M: Snapshots & Comparison Engine
 */

import { assertEqual, assertTrue } from './test-utils.js';
import { SnapshotManager } from '../src/modules/snapshots/snapshot-manager.js';

export function runSnapshotManagerTests() {
  const manager = new SnapshotManager();

  const state1 = {
    origin: 'https://example.com',
    hostname: 'example.com',
    endpoints: ['93.184.216.34'],
    headers: { 'server': 'nginx/1.18', 'x-frame-options': 'DENY' },
    thirdPartyDomains: ['google-analytics.com'],
    technologies: ['React', 'Nginx'],
    findings: [{ signature: 'find-1', title: 'Issue 1' }]
  };

  const snap1 = manager.createSnapshot('Baseline Inspection', state1);
  assertTrue(snap1.id.startsWith('SNAP-'), 'Generates valid snapshot ID');

  const state2 = {
    origin: 'https://example.com',
    hostname: 'example.com',
    endpoints: ['93.184.216.34', '104.16.1.1'], // Added endpoint
    headers: { 'server': 'nginx/1.20', 'x-frame-options': 'DENY' }, // Changed server header
    thirdPartyDomains: ['google-analytics.com', 'hotjar.com'], // Added tracker
    technologies: ['React', 'Nginx', 'Next.js'], // Added tech
    findings: [{ signature: 'find-1', title: 'Issue 1' }, { signature: 'find-2', title: 'Issue 2' }] // Added finding
  };

  const snap2 = manager.createSnapshot('Follow-up Inspection', state2);

  // Compare Snapshots
  const diff = manager.compareSnapshots(snap1.id, snap2.id);
  const delta = diff.delta;

  assertEqual(delta.newEndpoints.length, 1, 'Identifies 1 new endpoint');
  assertEqual(delta.newEndpoints[0], '104.16.1.1', 'Identifies correct new endpoint IP');

  assertEqual(delta.newThirdParties.length, 1, 'Identifies 1 new third-party host');
  assertEqual(delta.newThirdParties[0], 'hotjar.com', 'Identifies new tracker');

  assertEqual(delta.addedTechnologies.length, 1, 'Identifies 1 newly added tech');
  assertEqual(delta.addedTechnologies[0], 'Next.js', 'Identifies Next.js as added');

  assertEqual(delta.headerChanges.length, 1, 'Identifies 1 header change');
  assertEqual(delta.headerChanges[0].header, 'server', 'Identifies server header modified');
  assertEqual(delta.headerChanges[0].before, 'nginx/1.18', 'Before value matches');
  assertEqual(delta.headerChanges[0].after, 'nginx/1.20', 'After value matches');
}
