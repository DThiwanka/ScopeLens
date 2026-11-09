/**
 * Tests for Deep CORS & Preflight Cache Security Auditor
 */

import { assertEqual, assertTrue } from './test-utils.js';
import { CorsAuditor } from '../src/modules/security/cors-auditor.js';

export function runCorsAuditorTests() {
  const auditor = new CorsAuditor();

  // Test 1: Wildcard origin with credentials
  const badCors = auditor.auditCors({
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Credentials': 'true'
  }, 'https://api.example.com/me');

  assertTrue(badCors.some(f => f.id === 'SEC-CORS-WILDCARD-CREDENTIALS'), 'Flags wildcard with credentials');

  // Test 2: Missing Vary: Origin cache poisoning risk
  const cachePoison = auditor.auditCors({
    'Access-Control-Allow-Origin': 'https://app.client.com',
    'Access-Control-Allow-Credentials': 'true'
    // Vary header omitted
  }, 'https://api.example.com/data', 'https://app.client.com');

  assertTrue(cachePoison.some(f => f.id === 'SEC-CORS-CACHE-POISONING-RISK'), 'Flags missing Vary: Origin');

  // Test 3: Null origin allowed
  const nullOrigin = auditor.auditCors({
    'Access-Control-Allow-Origin': 'null'
  }, 'https://api.example.com/public');

  assertTrue(nullOrigin.some(f => f.id === 'SEC-CORS-NULL-ORIGIN'), 'Flags null origin');

  // Test 4: Sensitive Exposed Headers
  const exposeAuth = auditor.auditCors({
    'Access-Control-Allow-Origin': 'https://trusted.com',
    'Access-Control-Expose-Headers': 'Authorization, X-Custom-Header, Set-Cookie'
  }, 'https://api.example.com/login');

  assertTrue(exposeAuth.some(f => f.id === 'SEC-CORS-SENSITIVE-EXPOSE-HEADERS'), 'Flags exposed Authorization & Set-Cookie headers');

  // Test 5: Safe CORS configuration
  const safeCors = auditor.auditCors({
    'Access-Control-Allow-Origin': 'https://app.client.com',
    'Access-Control-Allow-Credentials': 'true',
    'Vary': 'Origin, Accept-Encoding',
    'Access-Control-Max-Age': '3600',
    'Access-Control-Expose-Headers': 'X-Request-Id'
  }, 'https://api.example.com/data', 'https://app.client.com');

  assertEqual(safeCors.length, 0, 'No findings on secure CORS configuration with Vary: Origin');
}
