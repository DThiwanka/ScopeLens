/**
 * Tests for Module D: Token & Authentication Intelligence
 */

import { assertEqual, assertTrue, assertFalse } from './test-utils.js';
import { parseToken, isJweFormat, inventoryTokens, TOKEN_TYPES } from '../src/modules/tokens/token-detector.js';

export function runTokenDetectorTests() {
  // Helper to create base64url string
  const toB64Url = obj => Buffer.from(JSON.stringify(obj)).toString('base64url');

  // 1. Valid Active JWT
  const activeHeader = { alg: 'RS256', typ: 'JWT', kid: 'key-2026-v1' };
  const futureExp = Math.floor(Date.now() / 1000) + 7200; // 2 hours in future
  const activePayload = { sub: 'user_123', iss: 'https://auth.example.com', exp: futureExp, iat: Math.floor(Date.now() / 1000) };
  const mockJwt = `${toB64Url(activeHeader)}.${toB64Url(activePayload)}.signaturePart12345`;

  const parsedActive = parseToken(mockJwt, 'localStorage:auth_token');
  assertTrue(parsedActive !== null, 'Parses standard JWT');
  assertEqual(parsedActive.type, TOKEN_TYPES.JWT_SIGNED, 'Correct JWT signed type');
  assertEqual(parsedActive.algorithm, 'RS256', 'Extracts RS256 algorithm');
  assertEqual(parsedActive.claims.subject, 'user_123', 'Extracts sub claim');
  assertEqual(parsedActive.claims.issuer, 'https://auth.example.com', 'Extracts iss claim');
  assertEqual(parsedActive.keyId, 'key-2026-v1', 'Extracts kid');
  assertEqual(parsedActive.timing.expiry.status, 'active', 'Expiry status is active');
  assertFalse(parsedActive.isWeakAlg, 'RS256 is not weak');

  // 2. Insecure alg: none JWT
  const noneHeader = { alg: 'none', typ: 'JWT' };
  const noneJwt = `${toB64Url(noneHeader)}.${toB64Url(activePayload)}.`;
  const parsedNone = parseToken(noneJwt, 'sessionStorage:token');
  assertTrue(parsedNone.isWeakAlg, 'Flags alg: none as weak/dangerous');

  // 3. Expired JWT
  const expiredPayload = { sub: 'user_old', exp: Math.floor(Date.now() / 1000) - 3600 }; // 1 hr ago
  const expiredJwt = `${toB64Url(activeHeader)}.${toB64Url(expiredPayload)}.signaturePart12345`;
  const parsedExpired = parseToken(expiredJwt, 'cookie:session');
  assertEqual(parsedExpired.timing.expiry.status, 'expired', 'Identifies expired token');

  // 4. JWE Format (5 segments)
  const jweToken = 'eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.sampleKeySegment.sampleIv.sampleCiphertext.sampleTag';
  assertTrue(isJweFormat(jweToken), 'Identifies JWE format');
  const parsedJwe = parseToken(jweToken, 'localStorage:encrypted_token');
  assertTrue(parsedJwe.isEncrypted, 'Identifies encrypted JWE');
  assertEqual(parsedJwe.segments, 5, 'JWE has 5 segments');

  // 5. Inventory Scan with Mixed Secrets
  const storageEntries = [
    { key: 'access_token', value: mockJwt, source: 'localStorage' },
    { key: 'aws_config', value: 'Credentials: AKIAIOSFODNN7EXAMPLE', source: 'localStorage' },
    { key: 'plain_item', value: 'normal-user-preference', source: 'localStorage' }
  ];

  const inventory = inventoryTokens(storageEntries);
  assertTrue(inventory.length >= 2, 'Finds multiple tokens and secrets');
  assertTrue(inventory.some(t => t.type === TOKEN_TYPES.JWT_SIGNED), 'Finds JWT in inventory');
  assertTrue(inventory.some(t => t.type === TOKEN_TYPES.API_KEY), 'Finds AWS Key in inventory');
}
