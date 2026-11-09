/**
 * Module M - Snapshots & Comparison Engine
 * Allows saving point-in-time site inspection snapshots and comparing
 * two snapshots to detect newly introduced endpoints, changed headers,
 * third-party additions, tech stack changes, and newly emerged security findings.
 */

import { deepClone } from '../../core/utils.js';

export class SnapshotManager {
  constructor() {
    this.snapshots = new Map();
  }

  /**
   * Creates a snapshot from current inspection state.
   * @param {string} label
   * @param {Object} state
   * @returns {Object}
   */
  createSnapshot(label, state) {
    const id = `SNAP-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
    const snapshot = {
      id,
      label: label || `Snapshot ${new Date().toLocaleTimeString()}`,
      createdAt: new Date().toISOString(),
      origin: state.origin || '',
      hostname: state.hostname || '',
      summary: {
        totalEndpoints: state.endpoints?.length || 0,
        totalThirdParties: state.thirdPartyDomains?.length || 0,
        totalTechnologies: state.technologies?.length || 0,
        totalFindings: state.findings?.length || 0
      },
      data: {
        endpoints: (state.endpoints || []).map(e => e.ip || e.url || e),
        headers: deepClone(state.headers || {}),
        thirdPartyDomains: (state.thirdPartyDomains || []).map(t => t.domain || t),
        technologies: (state.technologies || []).map(t => t.name || t),
        findingsSignatures: (state.findings || []).map(f => f.signature || f.id || f.title)
      }
    };

    this.snapshots.set(id, snapshot);
    return snapshot;
  }

  /**
   * Retrieves all stored snapshots.
   * @returns {Array<Object>}
   */
  listSnapshots() {
    return Array.from(this.snapshots.values()).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  }

  /**
   * Compares two snapshots and produces a structured delta.
   * @param {string} baseSnapshotId
   * @param {string} targetSnapshotId
   * @returns {Object}
   */
  compareSnapshots(baseSnapshotId, targetSnapshotId) {
    const base = this.snapshots.get(baseSnapshotId);
    const target = this.snapshots.get(targetSnapshotId);

    if (!base || !target) {
      throw new Error('Both base and target snapshots must exist for comparison.');
    }

    const baseData = base.data;
    const targetData = target.data;

    // Compare Endpoints
    const baseEndpoints = new Set(baseData.endpoints);
    const targetEndpoints = new Set(targetData.endpoints);
    const newEndpoints = [...targetEndpoints].filter(e => !baseEndpoints.has(e));
    const removedEndpoints = [...baseEndpoints].filter(e => !targetEndpoints.has(e));

    // Compare Third-party domains
    const baseTP = new Set(baseData.thirdPartyDomains);
    const targetTP = new Set(targetData.thirdPartyDomains);
    const newThirdParties = [...targetTP].filter(d => !baseTP.has(d));
    const removedThirdParties = [...baseTP].filter(d => !targetTP.has(d));

    // Compare Technologies
    const baseTech = new Set(baseData.technologies);
    const targetTech = new Set(targetData.technologies);
    const addedTechnologies = [...targetTech].filter(t => !baseTech.has(t));
    const removedTechnologies = [...baseTech].filter(t => !targetTech.has(t));

    // Compare Findings
    const baseFindings = new Set(baseData.findingsSignatures);
    const targetFindings = new Set(targetData.findingsSignatures);
    const newFindings = [...targetFindings].filter(f => !baseFindings.has(f));
    const resolvedFindings = [...baseFindings].filter(f => !targetFindings.has(f));

    // Compare Headers
    const headerChanges = [];
    const allHeaderKeys = new Set([...Object.keys(baseData.headers), ...Object.keys(targetData.headers)]);
    for (const key of allHeaderKeys) {
      const valBase = baseData.headers[key];
      const valTarget = targetData.headers[key];
      if (valBase !== valTarget) {
        headerChanges.push({
          header: key,
          before: valBase || '(absent)',
          after: valTarget || '(removed)'
        });
      }
    }

    return {
      baseSnapshot: { id: base.id, label: base.label, createdAt: base.createdAt },
      targetSnapshot: { id: target.id, label: target.label, createdAt: target.createdAt },
      delta: {
        newEndpoints,
        removedEndpoints,
        newThirdParties,
        removedThirdParties,
        addedTechnologies,
        removedTechnologies,
        newFindingsCount: newFindings.length,
        resolvedFindingsCount: resolvedFindings.length,
        headerChanges
      }
    };
  }
}
