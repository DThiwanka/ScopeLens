/**
 * Tests for Phase 4: Authentication & OAuth/OIDC Flow Mapper
 */

import { assertEqual, assertTrue } from './test-utils.js';
import { AuthFlowMapper, AUTH_FLOW_TYPES } from '../src/modules/auth/auth-flow-mapper.js';

export function runAuthFlowMapperTests() {
  const mapper = new AuthFlowMapper();

  // Test 1: Insecure OAuth request (missing state, missing PKCE, insecure redirect)
  const insecureAuth = mapper.inspectTransaction({
    url: 'https://auth.example.com/oauth/authorize?client_id=client_123&response_type=code&redirect_uri=http://app.example.com/callback',
    method: 'GET',
    status: 302
  });

  assertTrue(insecureAuth !== null, 'Detected OAuth Authorize flow');
  assertEqual(insecureAuth.type, AUTH_FLOW_TYPES.OAUTH_AUTHORIZE, 'Flow type is OAUTH_AUTHORIZE');
  assertEqual(insecureAuth.parameters.clientId, '[PRESENT]', 'Client ID is masked/flagged present');
  assertTrue(!insecureAuth.parameters.hasState, 'Detected missing state');
  assertTrue(!insecureAuth.parameters.hasPkce, 'Detected missing PKCE');

  // Verify warnings generated
  const warnings = mapper.getAllWarnings();
  assertTrue(warnings.some(w => w.id === 'AUTH_MISSING_STATE'), 'Generates AUTH_MISSING_STATE warning');
  assertTrue(warnings.some(w => w.id === 'AUTH_MISSING_PKCE'), 'Generates AUTH_MISSING_PKCE warning');
  assertTrue(warnings.some(w => w.id === 'AUTH_INSECURE_REDIRECT_URI'), 'Generates AUTH_INSECURE_REDIRECT_URI warning');

  // Test 2: Secure OAuth request with PKCE (S256), state, and HTTPS redirect
  const secureMapper = new AuthFlowMapper();
  const secureAuth = secureMapper.inspectTransaction({
    url: 'https://auth.example.com/oauth/authorize?client_id=client_123&response_type=code&state=xyz987&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&redirect_uri=https://app.example.com/callback',
    method: 'GET',
    status: 302
  });

  assertTrue(secureAuth !== null, 'Detected secure auth flow');
  assertTrue(secureAuth.parameters.hasState, 'State is present');
  assertTrue(secureAuth.parameters.hasPkce, 'PKCE is present');
  assertEqual(secureAuth.parameters.codeChallengeMethod, 'S256', 'PKCE method is S256');
  assertEqual(secureAuth.warnings.length, 0, 'No warnings for secure OAuth 2.1 flow');

  // Test 3: Token endpoint
  const tokenTx = secureMapper.inspectTransaction({
    url: 'https://auth.example.com/oauth/token',
    method: 'POST',
    status: 200
  });
  assertTrue(tokenTx !== null, 'Detected Token exchange endpoint');
  assertEqual(tokenTx.type, AUTH_FLOW_TYPES.OAUTH_TOKEN, 'Flow type is OAUTH_TOKEN');
}
