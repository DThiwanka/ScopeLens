/**
 * ScopeLens Platform - Retention & Storage Policy Engine
 * Manages local storage quotas, automated aging out of historical sessions,
 * and one-click user data purge.
 */

export const DEFAULT_RETENTION_LIMITS = {
  maxSessions: 10,
  maxObservations: 5000,
  maxSnapshots: 25,
  maxReports: 20
};

export class RetentionManager {
  /**
   * @param {import('./persistence.js').ScopeLensStorage} storage
   * @param {typeof DEFAULT_RETENTION_LIMITS} [customLimits]
   */
  constructor(storage, customLimits = {}) {
    this.storage = storage;
    this.limits = { ...DEFAULT_RETENTION_LIMITS, ...customLimits };
  }

  /**
   * Enforces retention policy by removing old sessions and associated records.
   * @returns {Promise<{ prunedSessions: number, prunedObservations: number }>}
   */
  async enforceRetention() {
    if (!this.storage) return { prunedSessions: 0, prunedObservations: 0 };

    let prunedSessions = 0;
    let prunedObservations = 0;

    try {
      // 1. Check sessions
      const sessions = await this.storage.getAll('sessions');
      if (sessions.length > this.limits.maxSessions) {
        // Sort ascending by startedAt (oldest first)
        sessions.sort((a, b) => new Date(a.startedAt || 0) - new Date(b.startedAt || 0));
        const excessCount = sessions.length - this.limits.maxSessions;
        const sessionsToRemove = sessions.slice(0, excessCount);

        for (const session of sessionsToRemove) {
          if (session.id) {
            // Delete associated observations
            const obs = await this.storage.getByIndex('observations', 'sessionId', session.id);
            for (const o of obs) {
              if (o.id) {
                await this.storage.delete('observations', o.id);
                prunedObservations++;
              }
            }
            // Delete associated findings
            const findings = await this.storage.getByIndex('findings', 'sessionId', session.id);
            for (const f of findings) {
              if (f.signature) {
                await this.storage.delete('findings', f.signature);
              }
            }
            // Delete session
            await this.storage.delete('sessions', session.id);
            prunedSessions++;
          }
        }
      }

      // 2. Check total observations
      const allObs = await this.storage.getAll('observations');
      if (allObs.length > this.limits.maxObservations) {
        allObs.sort((a, b) => new Date(a.observedAt || 0) - new Date(b.observedAt || 0));
        const excess = allObs.length - this.limits.maxObservations;
        const toRemove = allObs.slice(0, excess);
        for (const o of toRemove) {
          if (o.id) {
            await this.storage.delete('observations', o.id);
            prunedObservations++;
          }
        }
      }

      // 3. Check snapshots
      const snapshots = await this.storage.getAll('snapshots');
      if (snapshots.length > this.limits.maxSnapshots) {
        snapshots.sort((a, b) => new Date(a.createdAt || 0) - new Date(b.createdAt || 0));
        const excess = snapshots.length - this.limits.maxSnapshots;
        for (const s of snapshots.slice(0, excess)) {
          if (s.id) await this.storage.delete('snapshots', s.id);
        }
      }

      // 4. Check reports
      const reports = await this.storage.getAll('reports');
      if (reports.length > this.limits.maxReports) {
        reports.sort((a, b) => new Date(a.generatedAt || 0) - new Date(b.generatedAt || 0));
        const excess = reports.length - this.limits.maxReports;
        for (const r of reports.slice(0, excess)) {
          if (r.id) await this.storage.delete('reports', r.id);
        }
      }
    } catch (err) {
      console.warn('Retention enforcement error:', err);
    }

    return { prunedSessions, prunedObservations };
  }

  /**
   * Returns storage statistics across all stores.
   * @returns {Promise<{ sessions: number, observations: number, findings: number, snapshots: number, reports: number }>}
   */
  async getStorageStats() {
    if (!this.storage) {
      return { sessions: 0, observations: 0, findings: 0, snapshots: 0, reports: 0 };
    }

    const [sessions, observations, findings, snapshots, reports] = await Promise.all([
      this.storage.getAll('sessions'),
      this.storage.getAll('observations'),
      this.storage.getAll('findings'),
      this.storage.getAll('snapshots'),
      this.storage.getAll('reports')
    ]);

    return {
      sessions: sessions.length,
      observations: observations.length,
      findings: findings.length,
      snapshots: snapshots.length,
      reports: reports.length
    };
  }

  /**
   * Completely purges all stored user data locally.
   * @returns {Promise<boolean>}
   */
  async purgeAllData() {
    if (!this.storage) return true;
    try {
      await Promise.all([
        this.storage.clear('sessions'),
        this.storage.clear('observations'),
        this.storage.clear('findings'),
        this.storage.clear('evidence'),
        this.storage.clear('snapshots'),
        this.storage.clear('reports')
      ]);
      return true;
    } catch (err) {
      console.error('Failed to purge ScopeLens data:', err);
      return false;
    }
  }
}
