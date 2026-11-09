/**
 * Tests for Sensitive Data Redactor
 */

import { assertEqual, assertTrue, assertFalse } from './test-utils.js';
import { sanitizeUrl, sanitizeHeaders, sanitizeData, sanitizeString, REDACTED_PLACEHOLDER } from '../src/core/redactor.js';

export function runRedactorTests() {
  // 1. URL Redaction
  const secretUrl = 'https://example.com/callback?token=secret12345&state=ok&api_key=mykey99';
  const cleanUrl = sanitizeUrl(secretUrl);
  assertTrue(cleanUrl.includes('token=' + REDACTED_PLACEHOLDER), 'Redacts token in URL query');
  assertTrue(cleanUrl.includes('api_key=' + REDACTED_PLACEHOLDER), 'Redacts api_key in URL query');
  assertTrue(cleanUrl.includes('state=ok'), 'Preserves non-sensitive query params');

  const embeddedCredsUrl = 'https://admin:password123@example.com/dashboard';
  const strippedCreds = sanitizeUrl(embeddedCredsUrl);
  assertFalse(strippedCreds.includes('password123'), 'Strips embedded HTTP username/password');

  // 2. Headers Redaction
  const rawHeaders = [
    { name: 'Authorization', value: 'Bearer eyJhbGciOiJIUzI1NiJ9.sample.sig' },
    { name: 'Cookie', value: 'session_id=abcdef12345; theme=dark' },
    { name: 'Content-Type', value: 'application/json' }
  ];
  const cleanedHeaders = sanitizeHeaders(rawHeaders);
  assertEqual(cleanedHeaders.find(h => h.name === 'Authorization').value, REDACTED_PLACEHOLDER, 'Masks Authorization header');
  assertEqual(cleanedHeaders.find(h => h.name === 'Cookie').value, REDACTED_PLACEHOLDER, 'Masks Cookie header');
  assertEqual(cleanedHeaders.find(h => h.name === 'Content-Type').value, 'application/json', 'Preserves benign headers');

  // 3. Deep Object Sanitization
  const payload = {
    user: 'alice',
    auth: {
      password: 'superSecretPassword!',
      token: 'jwt-like-value'
    },
    settings: {
      theme: 'dark'
    }
  };
  const sanitizedObj = sanitizeData(payload);
  assertEqual(sanitizedObj.auth.password, REDACTED_PLACEHOLDER, 'Deeply redacts nested password');
  assertEqual(sanitizedObj.auth.token, REDACTED_PLACEHOLDER, 'Deeply redacts nested token');
  assertEqual(sanitizedObj.settings.theme, 'dark', 'Preserves benign nested settings');

  // 4. String Pattern Redaction
  const textWithBearer = 'Sending request with header: Bearer abc123def456xyz';
  assertTrue(sanitizeString(textWithBearer).includes('Bearer [REDACTED]'), 'Redacts Bearer in text');
}
