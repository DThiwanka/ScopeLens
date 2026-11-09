/**
 * Module D - Token & Authentication Intelligence
 * Detects JWT, JWS, JWE, OAuth, Bearer tokens, and session identifiers.
 * Safely decodes headers and payloads locally with expiration analysis and algorithm audits.
 */

import { decodeBase64Utf8, safeJsonParse, formatRelativeTime } from '../../core/utils.js';
import { JWT_PATTERN, SECRET_PATTERNS } from '../../core/constants.js';

export const TOKEN_TYPES = {
  JWT_SIGNED: 'JWT (Signed / JWS)',
  JWT_ENCRYPTED: 'JWE (Encrypted JWT)',
  OAUTH_BEARER: 'OAuth Bearer Token',
  SESSION_IDENTIFIER: 'Session Identifier',
  API_KEY: 'API Key / Secret',
  UNKNOWN: 'Unknown Format'
};

export const ALGORITHM_INFO = {
  HS256: { type: 'Symmetric (HMAC)', status: 'Standard', risk: 'Low (if key is sufficiently long)' },
  HS384: { type: 'Symmetric (HMAC)', status: 'Standard', risk: 'Low' },
  HS512: { type: 'Symmetric (HMAC)', status: 'Standard', risk: 'Low' },
  RS256: { type: 'Asymmetric (RSA PKCS#1 v1.5)', status: 'Industry Standard', risk: 'Low' },
  RS384: { type: 'Asymmetric (RSA PKCS#1 v1.5)', status: 'Industry Standard', risk: 'Low' },
  RS512: { type: 'Asymmetric (RSA PKCS#1 v1.5)', status: 'Industry Standard', risk: 'Low' },
  ES256: { type: 'Asymmetric (ECDSA P-256)', status: 'Recommended Modern Standard', risk: 'Low' },
  ES384: { type: 'Asymmetric (ECDSA P-384)', status: 'Recommended Modern Standard', risk: 'Low' },
  ES512: { type: 'Asymmetric (ECDSA P-521)', status: 'Recommended Modern Standard', risk: 'Low' },
  EdDSA: { type: 'Asymmetric (Edwards-curve / Ed25519)', status: 'Modern & Highly Secure', risk: 'Low' },
  none: { type: 'None (Unsigned)', status: 'CRITICAL INSECURITY', risk: 'CRITICAL: Token is completely unsigned and can be forged by anyone!' }
};

/**
 * Checks if a string has the structure of a JWE (JSON Web Encryption: 5 base64url segments).
 * @param {string} token
 * @returns {boolean}
 */
export function isJweFormat(token) {
  if (typeof token !== 'string') return false;
  const parts = token.trim().split('.');
  return parts.length === 5 && parts.every(p => /^[A-Za-z0-9_-]+$/.test(p));
}

/**
 * Parses and audits a JWT or JWE token safely.
 * @param {string} tokenString
 * @param {string} [source='unknown']
 * @returns {Object|null}
 */
export function parseToken(tokenString, source = 'unknown') {
  if (!tokenString || typeof tokenString !== 'string') return null;
  const trimmed = tokenString.trim();

  // Check if JWE (5 parts)
  if (isJweFormat(trimmed)) {
    const parts = trimmed.split('.');
    const headerJson = decodeBase64Utf8(parts[0]);
    const header = safeJsonParse(headerJson, {});
    return {
      type: TOKEN_TYPES.JWT_ENCRYPTED,
      segments: 5,
      isEncrypted: true,
      header,
      payload: null,
      algorithm: header.alg || 'unknown',
      encryptionAlg: header.enc || 'unknown',
      note: 'JWE detected (5 segments). The token payload is encrypted. Decryption requires the private/shared key.',
      maskedValue: `${trimmed.slice(0, 10)}...[ENCRYPTED]...${trimmed.slice(-8)}`,
      source,
      detectedAt: new Date().toISOString()
    };
  }

  // Check if standard JWT (3 parts)
  const parts = trimmed.split('.');
  if (parts.length !== 3) return null;

  const headerJson = decodeBase64Utf8(parts[0]);
  const payloadJson = decodeBase64Utf8(parts[1]);
  if (!headerJson && !payloadJson) return null;

  const header = safeJsonParse(headerJson, {});
  const payload = safeJsonParse(payloadJson, {});

  const alg = String(header.alg || 'unknown');
  const algMeta = ALGORITHM_INFO[alg] || { type: 'Unknown Algorithm', status: 'Non-standard', risk: 'Review Required' };
  const isWeakAlg = alg.toLowerCase() === 'none';

  // Expiration and Timing Analysis
  const nowSec = Math.floor(Date.now() / 1000);
  let expiryInfo = { status: 'none', label: 'No expiration (exp) claim', secondsRemaining: null };

  if (typeof payload.exp === 'number') {
    const diff = payload.exp - nowSec;
    expiryInfo.secondsRemaining = diff;
    expiryInfo.expDate = new Date(payload.exp * 1000).toISOString();

    if (diff <= 0) {
      expiryInfo.status = 'expired';
      expiryInfo.label = `Expired (${formatRelativeTime(diff)} ago)`;
    } else if (diff < 900) { // < 15 mins
      expiryInfo.status = 'expiring_soon';
      expiryInfo.label = `Expiring soon (in ${formatRelativeTime(diff)})`;
    } else {
      expiryInfo.status = 'active';
      expiryInfo.label = `Active (valid for ${formatRelativeTime(diff)})`;
    }
  }

  // Issued at & Not Before
  let issuedAtDate = payload.iat ? new Date(payload.iat * 1000).toISOString() : null;
  let notBeforeDate = payload.nbf ? new Date(payload.nbf * 1000).toISOString() : null;

  return {
    type: TOKEN_TYPES.JWT_SIGNED,
    segments: 3,
    isEncrypted: false,
    header,
    payload,
    algorithm: alg,
    algorithmMeta: algMeta,
    isWeakAlg,
    keyId: header.kid || null,
    claims: {
      issuer: payload.iss || null,
      subject: payload.sub || null,
      audience: payload.aud || null,
      expiration: payload.exp || null,
      issuedAt: payload.iat || null,
      notBefore: payload.nbf || null,
      jwtId: payload.jti || null
    },
    timing: {
      expiry: expiryInfo,
      issuedAt: issuedAtDate,
      notBefore: notBeforeDate
    },
    maskedValue: `${trimmed.slice(0, 10)}...[SIGNATURE REDACTED]...${trimmed.slice(-8)}`,
    source,
    detectedAt: new Date().toISOString()
  };
}

/**
 * Scans an arbitrary text or storage collection to discover all tokens and secrets.
 * @param {Array<{key: string, value: string, source: string}>} entries
 * @returns {Array<Object>}
 */
export function inventoryTokens(entries = []) {
  const inventory = [];

  for (const { key, value, source } of entries) {
    if (!value || typeof value !== 'string') continue;

    // 1. Search for JWTs
    const jwtMatches = value.match(JWT_PATTERN) || [];
    for (const match of jwtMatches.slice(0, 10)) {
      const parsed = parseToken(match, `${source}:${key}`);
      if (parsed) inventory.push(parsed);
    }

    // 2. Search for JWE (5 parts)
    const jweCandidate = value.trim();
    if (isJweFormat(jweCandidate)) {
      const parsed = parseToken(jweCandidate, `${source}:${key}`);
      if (parsed) inventory.push(parsed);
    }

    // 3. Search for API keys
    for (const [secType, pattern] of Object.entries(SECRET_PATTERNS)) {
      const matches = value.match(pattern);
      if (matches) {
        matches.forEach(m => {
          inventory.push({
            type: TOKEN_TYPES.API_KEY,
            keyName: key,
            secretCategory: secType,
            maskedValue: `${m.slice(0, 6)}...[REDACTED]...${m.slice(-4)}`,
            source: `${source}:${key}`,
            detectedAt: new Date().toISOString()
          });
        });
      }
    }
  }

  return inventory;
}
