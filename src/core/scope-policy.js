/**
 * ScopeLens Platform - Scope Policy Engine
 * Enforces strict origin boundaries, tab isolation, and approved origin rules.
 */

import { safeParseUrl } from './utils.js';

export class ScopePolicy {
  constructor(topLevelOrigin = '', options = {}) {
    this.topLevelOrigin = topLevelOrigin;
    this.topLevelHostname = safeParseUrl(topLevelOrigin)?.hostname || '';
    this.allowSubdomains = options.allowSubdomains ?? true;
    this.thirdPartyMetadata = options.thirdPartyMetadata ?? true;
    this.approvedOrigins = new Set(options.approvedOrigins || []);
  }

  /**
   * Sets or updates the active top-level origin.
   * @param {string} origin
   */
  setOrigin(origin) {
    this.topLevelOrigin = origin;
    this.topLevelHostname = safeParseUrl(origin)?.hostname || '';
  }

  /**
   * Approves an external third-party origin for inspection.
   * @param {string} origin
   */
  approveOrigin(origin) {
    if (origin && typeof origin === 'string') {
      const u = safeParseUrl(origin);
      if (u) this.approvedOrigins.add(u.origin);
    }
  }

  /**
   * Revokes an approved origin.
   * @param {string} origin
   */
  revokeOrigin(origin) {
    this.approvedOrigins.delete(origin);
  }

  /**
   * Checks if a target URL is considered first-party (same origin or authorized subdomain).
   * @param {string} rawUrl
   * @returns {boolean}
   */
  isFirstParty(rawUrl) {
    const u = safeParseUrl(rawUrl);
    if (!u) return false;

    if (u.origin === this.topLevelOrigin) return true;

    if (this.allowSubdomains && this.topLevelHostname) {
      const host = u.hostname;
      return host === this.topLevelHostname || host.endsWith('.' + this.topLevelHostname);
    }

    return false;
  }

  /**
   * Checks if an origin is explicitly approved by the user.
   * @param {string} rawUrl
   * @returns {boolean}
   */
  isApprovedThirdParty(rawUrl) {
    const u = safeParseUrl(rawUrl);
    if (!u) return false;
    return this.approvedOrigins.has(u.origin);
  }

  /**
   * Evaluates if a request's metadata may be observed and logged.
   * @param {string} rawUrl
   * @returns {boolean}
   */
  canObserveMetadata(rawUrl) {
    if (!rawUrl || typeof rawUrl !== 'string') return false;
    const u = safeParseUrl(rawUrl);
    if (!u) return false;

    // Disallow privileged internal browser schemes
    if (/^(chrome|edge|chrome-extension|about|data|javascript|file):/i.test(u.protocol)) {
      return false;
    }

    if (this.isFirstParty(rawUrl) || this.isApprovedThirdParty(rawUrl)) {
      return true;
    }

    return Boolean(this.thirdPartyMetadata);
  }

  /**
   * Evaluates if full body inspection (request/response payload preview) is permitted.
   * Policy: Body inspection is permitted for first-party and explicitly approved origins only.
   * @param {string} rawUrl
   * @returns {boolean}
   */
  canInspectBody(rawUrl) {
    return this.isFirstParty(rawUrl) || this.isApprovedThirdParty(rawUrl);
  }
}
