/**
 * ScopeLens Platform - Core Utilities
 */

/**
 * Safely parse a URL string with a fallback.
 * @param {string} raw
 * @param {string} [base]
 * @returns {URL|null}
 */
export function safeParseUrl(raw, base) {
  try {
    return base ? new URL(raw, base) : new URL(raw);
  } catch {
    return null;
  }
}

/**
 * Decodes a Base64 or Base64URL encoded string safely with UTF-8 support.
 * @param {string} str
 * @returns {string|null}
 */
export function decodeBase64Utf8(str) {
  try {
    const b64 = str.replace(/-/g, '+').replace(/_/g, '/');
    const padded = b64.padEnd(Math.ceil(b64.length / 4) * 4, '=');
    const binary = atob(padded);
    const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  } catch {
    return null;
  }
}

/**
 * Safely parses a JSON string, returns fallback on error.
 * @param {string} text
 * @param {*} [fallback=null]
 * @returns {*}
 */
export function safeJsonParse(text, fallback = null) {
  if (typeof text !== 'string') return fallback;
  try {
    return JSON.parse(text);
  } catch {
    return fallback;
  }
}

/**
 * Formats byte counts into human-readable strings (B, KB, MB, GB).
 * @param {number} bytes
 * @param {number} [decimals=1]
 * @returns {string}
 */
export function formatBytes(bytes, decimals = 1) {
  if (bytes === null || bytes === undefined || isNaN(bytes)) return '—';
  if (bytes === 0) return '0 B';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(Math.abs(bytes)) / Math.log(k));
  const val = parseFloat((bytes / Math.pow(k, i)).toFixed(dm));
  return `${val} ${sizes[i] || 'B'}`;
}

/**
 * Formats millisecond duration into readable string.
 * @param {number} ms
 * @returns {string}
 */
export function formatDuration(ms) {
  if (ms === null || ms === undefined || isNaN(ms)) return '—';
  if (ms < 1000) return `${Math.round(ms)} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

/**
 * Formats seconds difference into a human-friendly relative time.
 * @param {number} secondsDiff
 * @returns {string}
 */
export function formatRelativeTime(secondsDiff) {
  const abs = Math.abs(secondsDiff);
  if (abs < 60) return `${Math.round(abs)}s`;
  if (abs < 3600) return `${Math.round(abs / 60)}m`;
  if (abs < 86400) return `${Math.round(abs / 3600)}h`;
  const days = Math.round(abs / 86400);
  if (days < 30) return `${days}d`;
  const months = Math.round(days / 30);
  return `${months}mo`;
}

/**
 * Computes a fast deterministic 32-bit FNV-1a hash of a string.
 * @param {string} str
 * @returns {string}
 */
export function fastHash(str) {
  let hash = 2166136261;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
  }
  return (hash >>> 0).toString(16);
}

/**
 * Deep clones any serializable object.
 * @param {*} obj
 * @returns {*}
 */
export function deepClone(obj) {
  if (obj === null || typeof obj !== 'object') return obj;
  if (typeof structuredClone === 'function') {
    try {
      return structuredClone(obj);
    } catch {
      // Fallback
    }
  }
  return JSON.parse(JSON.stringify(obj));
}

/**
 * Checks if two origins are identical.
 * @param {string} url1
 * @param {string} url2
 * @returns {boolean}
 */
export function isSameOrigin(url1, url2) {
  try {
    return new URL(url1).origin === new URL(url2).origin;
  } catch {
    return false;
  }
}
