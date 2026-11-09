/**
 * Module E - Browser Storage Intelligence
 * Inspects localStorage, sessionStorage, IndexedDB, Cookies, CacheStorage,
 * Service Workers, and Storage Quotas strictly for the active origin.
 */

import { safeJsonParse } from '../../core/utils.js';
import { SENSITIVE_KEY_PATTERN } from '../../core/constants.js';

/**
 * Evaluates storage key hygiene and sensitive credential exposure.
 * @param {string} key
 * @param {string} value
 * @returns {Object}
 */
export function analyzeStorageEntry(key, value) {
  const isSensitiveKey = SENSITIVE_KEY_PATTERN.test(key);
  const parsedJson = safeJsonParse(value);
  const isJson = parsedJson !== null && typeof parsedJson === 'object';
  const charLength = (value || '').length;
  const estimatedBytes = charLength * 2; // Approximate UTF-16 byte size

  return {
    key,
    charLength,
    estimatedBytes,
    isJson,
    isSensitiveKey,
    classification: isSensitiveKey ? 'Sensitive (masked)' : (isJson ? 'Structured JSON' : 'Plain Text')
  };
}

/**
 * Analyzes cookies and flags missing security attributes.
 * @param {Array<Object>} cookies
 * @returns {Object}
 */
export function auditCookies(cookies = []) {
  const total = cookies.length;
  let missingSecure = 0;
  let missingHttpOnly = 0;
  let missingSameSite = 0;
  let sameSiteNoneWithoutSecure = 0;
  const sensitiveCookiesInScript = [];

  const auditedCookies = cookies.map(c => {
    const isSensitive = SENSITIVE_KEY_PATTERN.test(c.name);
    const isSecure = Boolean(c.secure);
    const isHttpOnly = Boolean(c.httpOnly);
    const sameSite = c.sameSite || 'None';
    const isSession = Boolean(c.session || !c.expirationDate);

    const issues = [];
    if (!isSecure) {
      missingSecure++;
      issues.push('Missing Secure flag');
    }
    if (!isHttpOnly && isSensitive) {
      missingHttpOnly++;
      sensitiveCookiesInScript.push(c.name);
      issues.push('Sensitive cookie missing HttpOnly flag (accessible to XSS)');
    }
    if (!c.sameSite || c.sameSite === 'unspecified') {
      missingSameSite++;
      issues.push('Unspecified SameSite attribute');
    }
    if (sameSite.toLowerCase() === 'none' && !isSecure) {
      sameSiteNoneWithoutSecure++;
      issues.push('SameSite=None without Secure flag (will be rejected by modern browsers)');
    }

    return {
      name: c.name,
      domain: c.domain || 'host-only',
      path: c.path || '/',
      isSecure,
      isHttpOnly,
      sameSite,
      isSession,
      expiresAt: c.expirationDate ? new Date(c.expirationDate * 1000).toISOString() : 'Session',
      isHostOnly: Boolean(c.hostOnly),
      isSensitive,
      issues
    };
  });

  return {
    total,
    missingSecure,
    missingHttpOnly,
    missingSameSite,
    sameSiteNoneWithoutSecure,
    sensitiveCookiesInScript,
    cookies: auditedCookies
  };
}

/**
 * Calculates storage quota utilization summary.
 * @param {Object} quotaEstimate
 * @returns {Object}
 */
export function formatStorageQuota(quotaEstimate) {
  if (!quotaEstimate) return { quota: 0, usage: 0, percentage: 0 };
  const usage = quotaEstimate.usage || 0;
  const quota = quotaEstimate.quota || 0;
  const percentage = quota > 0 ? ((usage / quota) * 100).toFixed(2) : 0;

  return {
    usageBytes: usage,
    quotaBytes: quota,
    usagePercentage: parseFloat(percentage)
  };
}
