/**
 * ScopeLens Platform - Authentication & OAuth/OIDC Flow Mapper
 * Traces authentication redirects, validates OAuth 2.0 / OIDC parameters,
 * detects PKCE and CSRF protections, and highlights protocol vulnerabilities.
 */

import { safeParseUrl } from '../../core/utils.js';

export const AUTH_FLOW_TYPES = {
  OAUTH_AUTHORIZE: 'oauth_authorize',
  OAUTH_TOKEN: 'oauth_token',
  OAUTH_USERINFO: 'oauth_userinfo',
  OAUTH_REVOKE: 'oauth_revoke',
  LOGOUT: 'logout',
  SAML_SSO: 'saml_sso',
  SESSION_REFRESH: 'session_refresh',
  UNKNOWN: 'unknown'
};

export class AuthFlowMapper {
  constructor() {
    this.events = [];
    this.flows = [];
  }

  /**
   * Evaluates a URL or HTTP transaction for OAuth/OIDC or authentication flow patterns.
   * @param {Object} transaction
   * @param {string} transaction.url
   * @param {string} [transaction.method='GET']
   * @param {number} [transaction.status=200]
   * @param {Object} [transaction.headers={}]
   * @param {string} [transaction.timestamp]
   * @returns {Object|null} Auth step if detected, else null
   */
  inspectTransaction(transaction) {
    if (!transaction || !transaction.url) return null;

    const parsed = safeParseUrl(transaction.url);
    if (!parsed) return null;

    const path = parsed.pathname.toLowerCase();
    const searchParams = parsed.searchParams;

    // 1. OAuth / OIDC Authorize endpoint detection
    const isAuthorize = /oauth|oidc|auth/i.test(path) && (
      path.endsWith('/authorize') ||
      path.endsWith('/auth') ||
      path.includes('/oauth2/v2.0/authorize') ||
      path.includes('/as/authorization.oauth2') ||
      searchParams.has('response_type') ||
      searchParams.has('client_id')
    );

    // 2. Token Exchange endpoint
    const isToken = (path.endsWith('/token') || path.includes('/oauth/token')) && transaction.method === 'POST';

    // 3. Userinfo endpoint
    const isUserInfo = path.endsWith('/userinfo') || path.endsWith('/me') || path.includes('/oauth/userinfo');

    // 4. Logout / End Session
    const isLogout = path.includes('/logout') || path.endsWith('/endsession') || path.includes('/signout');

    let flowType = AUTH_FLOW_TYPES.UNKNOWN;
    if (isAuthorize) flowType = AUTH_FLOW_TYPES.OAUTH_AUTHORIZE;
    else if (isToken) flowType = AUTH_FLOW_TYPES.OAUTH_TOKEN;
    else if (isUserInfo) flowType = AUTH_FLOW_TYPES.OAUTH_USERINFO;
    else if (isLogout) flowType = AUTH_FLOW_TYPES.LOGOUT;
    else return null;

    // Extract non-sensitive parameters
    const params = {
      responseType: searchParams.get('response_type') || null,
      clientId: searchParams.get('client_id') ? '[PRESENT]' : null,
      redirectUri: searchParams.get('redirect_uri') || null,
      scope: searchParams.get('scope') || null,
      hasState: searchParams.has('state'),
      hasNonce: searchParams.has('nonce'),
      codeChallengeMethod: searchParams.get('code_challenge_method') || (searchParams.has('code_challenge') ? 'plain' : null),
      hasPkce: searchParams.has('code_challenge'),
      prompt: searchParams.get('prompt') || null
    };

    // Analyze security weaknesses
    const warnings = [];

    if (flowType === AUTH_FLOW_TYPES.OAUTH_AUTHORIZE) {
      // CSRF check
      if (!params.hasState) {
        warnings.push({
          id: 'AUTH_MISSING_STATE',
          title: 'Missing OAuth State Parameter',
          severity: 'HIGH',
          description: 'Authorization request lacks a "state" parameter, exposing users to Cross-Site Request Forgery (CSRF) in the OAuth callback.'
        });
      }

      // PKCE check (OAuth 2.1 recommended)
      if (!params.hasPkce) {
        warnings.push({
          id: 'AUTH_MISSING_PKCE',
          title: 'Missing PKCE (Proof Key for Code Exchange)',
          severity: 'MEDIUM',
          description: 'Authorization request does not use PKCE (code_challenge). PKCE is required by OAuth 2.1 to prevent authorization code interception.'
        });
      } else if (params.codeChallengeMethod === 'plain') {
        warnings.push({
          id: 'AUTH_WEAK_PKCE_PLAIN',
          title: 'Weak PKCE Code Challenge Method (plain)',
          severity: 'MEDIUM',
          description: 'PKCE method is configured as "plain" instead of "S256" (SHA-256).'
        });
      }

      // Implicit flow deprecation
      if (params.responseType && (params.responseType.includes('token') || params.responseType === 'id_token')) {
        warnings.push({
          id: 'AUTH_DEPRECATED_IMPLICIT_FLOW',
          title: 'Deprecated OAuth 2.0 Implicit Grant',
          severity: 'HIGH',
          description: 'Implicit flow returns access tokens in URL hash fragments, exposing tokens to access logs, browser history, and referrer leaks. Authorization Code with PKCE must be used instead.'
        });
      }

      // Insecure redirect URI
      if (params.redirectUri && params.redirectUri.startsWith('http://') && !params.redirectUri.includes('localhost') && !params.redirectUri.includes('127.0.0.1')) {
        warnings.push({
          id: 'AUTH_INSECURE_REDIRECT_URI',
          title: 'Insecure HTTP OAuth Redirect URI',
          severity: 'CRITICAL',
          description: 'The redirect_uri uses cleartext HTTP, allowing man-in-the-middle attackers to intercept authorization codes.'
        });
      }
    }

    const event = {
      type: flowType,
      url: transaction.url,
      hostname: parsed.hostname,
      pathname: parsed.pathname,
      method: transaction.method || 'GET',
      status: transaction.status || 200,
      timestamp: transaction.timestamp || new Date().toISOString(),
      parameters: params,
      warnings
    };

    this.events.push(event);
    return event;
  }

  /**
   * Returns all recorded authentication events.
   * @returns {Array<Object>}
   */
  getEvents() {
    return [...this.events];
  }

  /**
   * Collects all security warnings discovered across observed authentication flows.
   * @returns {Array<Object>}
   */
  getAllWarnings() {
    const list = [];
    for (const evt of this.events) {
      if (evt.warnings && evt.warnings.length) {
        list.push(...evt.warnings.map(w => ({ ...w, origin: evt.hostname, url: evt.url })));
      }
    }
    return list;
  }
}
