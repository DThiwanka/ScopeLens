/**
 * Module K - Smart Findings Engine
 * Centralized aggregator for security and inspection findings across all modules.
 * Handles deduplication, severity ranking, search, dismissal, and false-positive marking.
 */

import { SEVERITY, CONFIDENCE } from '../../core/constants.js';
import { fastHash } from '../../core/utils.js';

export class FindingsEngine {
  constructor() {
    this.findings = new Map();
    this.dismissedIds = new Set();
    this.falsePositiveIds = new Set();
  }

  /**
   * Generates a deterministic signature for deduplication.
   * @param {Object} finding
   * @returns {string}
   */
  generateSignature(finding) {
    const raw = `${finding.category}|${finding.id || finding.title}|${finding.affectedResource || ''}`;
    return fastHash(raw);
  }

  /**
   * Ingests a finding or an array of findings.
   * @param {Object|Array<Object>} items
   * @param {string} sourceModule
   */
  ingest(items, sourceModule = 'General') {
    if (!items) return;
    const list = Array.isArray(items) ? items : [items];

    for (const item of list) {
      if (!item || !item.title) continue;

      const signature = item.signature || this.generateSignature(item);

      // Check if already present
      if (this.findings.has(signature)) {
        const existing = this.findings.get(signature);
        existing.occurrences = (existing.occurrences || 1) + 1;
        existing.lastSeenAt = new Date().toISOString();
        continue;
      }

      const findingObj = {
        findingId: item.id || `FIND-${signature.slice(0, 8).toUpperCase()}`,
        signature,
        category: item.category || 'General Security',
        title: item.title,
        description: item.description || '',
        severity: item.severity || SEVERITY.INFORMATIONAL,
        confidence: item.confidence || CONFIDENCE.CONFIRMED,
        evidence: item.evidence || '',
        affectedResource: item.affectedResource || '',
        remediation: item.remediation || '',
        sourceModule,
        timestamp: item.timestamp || new Date().toISOString(),
        lastSeenAt: new Date().toISOString(),
        occurrences: 1,
        isDismissed: this.dismissedIds.has(signature),
        isFalsePositive: this.falsePositiveIds.has(signature)
      };

      this.findings.set(signature, findingObj);
    }
  }

  /**
   * Marks a finding as dismissed.
   * @param {string} signature
   */
  dismiss(signature) {
    this.dismissedIds.add(signature);
    if (this.findings.has(signature)) {
      this.findings.get(signature).isDismissed = true;
    }
  }

  /**
   * Marks a finding as a false positive.
   * @param {string} signature
   */
  markFalsePositive(signature) {
    this.falsePositiveIds.add(signature);
    if (this.findings.has(signature)) {
      this.findings.get(signature).isFalsePositive = true;
    }
  }

  /**
   * Clears all findings.
   */
  clear() {
    this.findings.clear();
  }

  /**
   * Queries findings with optional filters.
   * @param {Object} [filter={}]
   * @param {string} [filter.severity]
   * @param {string} [filter.category]
   * @param {string} [filter.search]
   * @param {boolean} [filter.includeDismissed=false]
   * @returns {Array<Object>}
   */
  query(filter = {}) {
    const {
      severity,
      category,
      search,
      includeDismissed = false
    } = filter;

    const queryStr = search ? search.toLowerCase().trim() : '';

    const severityOrder = {
      [SEVERITY.CRITICAL]: 0,
      [SEVERITY.HIGH]: 1,
      [SEVERITY.MEDIUM]: 2,
      [SEVERITY.LOW]: 3,
      [SEVERITY.INFORMATIONAL]: 4
    };

    return Array.from(this.findings.values())
      .filter(f => {
        if (!includeDismissed && (f.isDismissed || f.isFalsePositive)) return false;
        if (severity && f.severity !== severity) return false;
        if (category && f.category !== category) return false;
        if (queryStr) {
          const matchTitle = f.title.toLowerCase().includes(queryStr);
          const matchDesc = f.description.toLowerCase().includes(queryStr);
          const matchEv = f.evidence.toLowerCase().includes(queryStr);
          const matchRes = f.affectedResource.toLowerCase().includes(queryStr);
          if (!matchTitle && !matchDesc && !matchEv && !matchRes) return false;
        }
        return true;
      })
      .sort((a, b) => {
        const orderA = severityOrder[a.severity] ?? 5;
        const orderB = severityOrder[b.severity] ?? 5;
        return orderA - orderB;
      });
  }

  /**
   * Returns severity distribution statistics.
   * @returns {Object}
   */
  getStatistics() {
    const stats = {
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      informational: 0,
      dismissed: this.dismissedIds.size
    };

    for (const f of this.findings.values()) {
      if (f.isDismissed || f.isFalsePositive) continue;
      stats.total++;
      if (f.severity === SEVERITY.CRITICAL) stats.critical++;
      else if (f.severity === SEVERITY.HIGH) stats.high++;
      else if (f.severity === SEVERITY.MEDIUM) stats.medium++;
      else if (f.severity === SEVERITY.LOW) stats.low++;
      else if (f.severity === SEVERITY.INFORMATIONAL) stats.informational++;
    }

    return stats;
  }
}
