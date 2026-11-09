/**
 * ScopeLens Platform - Sensitive Data Redactor
 * Automatically sanitizes and masks credentials, authorization headers,
 * API tokens, private keys, and sensitive parameters.
 */

import { SENSITIVE_KEY_PATTERN, JWT_PATTERN, SECRET_PATTERNS } from './constants.js';

export const REDACTED_PLACEHOLDER = '[REDACTED]';

/**
 * Sanitizes a URL by masking sensitive query parameters and stripping embedded credentials.
 * @param {string} rawUrl
 * @returns {string}
 */
export function sanitizeUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') return '';
  try {
    const url = new URL(rawUrl);
    for (const key of [...url.searchParams.keys()]) {
      if (SENSITIVE_KEY_PATTERN.test(key)) {
        url.searchParams.set(key, REDACTED_PLACEHOLDER);
      }
    }
    url.username = '';
    url.password = '';
    return decodeURIComponent(url.toString()).replace(/\[REDACTED\]/g, REDACTED_PLACEHOLDER);
  } catch {
    return rawUrl;
  }
}

/**
 * Redacts a list or map of HTTP headers.
 * @param {Array<{name: string, value: string}>|Record<string, string>} headers
 * @returns {Array<{name: string, value: string}>}
 */
export function sanitizeHeaders(headers) {
  if (!headers) return [];

  // If array format [{name, value}]
  if (Array.isArray(headers)) {
    return headers.map(({ name, value }) => {
      const isSensitive = SENSITIVE_KEY_PATTERN.test(name);
      return {
        name,
        value: isSensitive ? REDACTED_PLACEHOLDER : sanitizeString(value)
      };
    });
  }

  // If object format { headerName: headerValue }
  if (typeof headers === 'object') {
    return Object.entries(headers).map(([name, value]) => {
      const isSensitive = SENSITIVE_KEY_PATTERN.test(name);
      return {
        name,
        value: isSensitive ? REDACTED_PLACEHOLDER : sanitizeString(String(value ?? ''))
      };
    });
  }

  return [];
}

/**
 * Recursively redacts sensitive keys and values in arbitrary JSON data or objects.
 * @param {*} data
 * @returns {*}
 */
export function sanitizeData(data) {
  if (data === null || data === undefined) return data;

  if (Array.isArray(data)) {
    return data.map(sanitizeData);
  }

  if (typeof data === 'object') {
    const cleaned = {};
    for (const [key, val] of Object.entries(data)) {
      if (val !== null && typeof val === 'object') {
        cleaned[key] = sanitizeData(val);
      } else if (SENSITIVE_KEY_PATTERN.test(key)) {
        cleaned[key] = REDACTED_PLACEHOLDER;
      } else {
        cleaned[key] = sanitizeData(val);
      }
    }
    return cleaned;
  }

  if (typeof data === 'string') {
    if (data.startsWith('http://') || data.startsWith('https://')) {
      return sanitizeUrl(data);
    }
    return sanitizeString(data);
  }

  return data;
}

/**
 * Scans a plain text string and masks bearer tokens, secrets, JWTs, and API keys.
 * @param {string} text
 * @param {number} [maxLength=15000]
 * @returns {string}
 */
export function sanitizeString(text, maxLength = 15000) {
  if (!text || typeof text !== 'string') return '';

  let sanitized = text;

  // Mask Bearer tokens
  sanitized = sanitized.replace(/\bBearer\s+[A-Za-z0-9\-._~+/]+=*/gi, 'Bearer [REDACTED]');

  // Mask Basic Auth credentials
  sanitized = sanitized.replace(/\bBasic\s+[A-Za-z0-9+/]+=*/gi, 'Basic [REDACTED]');

  // Mask JWTs
  sanitized = sanitized.replace(JWT_PATTERN, '[JWT REDACTED]');

  // Mask AWS Keys
  sanitized = sanitized.replace(SECRET_PATTERNS.AWS_KEY, 'AKIA[REDACTED]');

  // Mask Google API Keys
  sanitized = sanitized.replace(SECRET_PATTERNS.GOOGLE_API_KEY, 'AIza[REDACTED]');

  // Mask GitHub Tokens
  sanitized = sanitized.replace(SECRET_PATTERNS.GITHUB_TOKEN, 'gh_[REDACTED]');

  // Mask Stripe Keys
  sanitized = sanitized.replace(SECRET_PATTERNS.STRIPE_SECRET, 'sk_[REDACTED]');
  sanitized = sanitized.replace(SECRET_PATTERNS.STRIPE_PUBLISHABLE, 'pk_[REDACTED]');

  // Mask Private Keys
  sanitized = sanitized.replace(SECRET_PATTERNS.PRIVATE_KEY, '-----BEGIN PRIVATE KEY-----\n[REDACTED]\n-----END PRIVATE KEY-----');

  // Truncate if exceeds max length
  if (sanitized.length > maxLength) {
    sanitized = sanitized.slice(0, maxLength) + '\n... [truncated preview]';
  }

  return sanitized;
}
