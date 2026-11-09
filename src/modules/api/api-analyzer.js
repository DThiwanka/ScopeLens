/**
 * Module H - API Discovery & Inspection
 * Analyzes observed network traffic to identify REST, GraphQL, and JSON API endpoints,
 * abstracts route patterns, inspects payload structures safely, and builds an API inventory.
 */

import { safeParseUrl } from '../../core/utils.js';
import { sanitizeUrl } from '../../core/redactor.js';

/**
 * Normalizes an API path into an abstracted pattern (e.g., /api/v1/users/123 -> /api/v1/users/{id}).
 * @param {string} pathname
 * @returns {string}
 */
export function abstractRoutePattern(pathname) {
  if (!pathname || typeof pathname !== 'string') return '/';

  // Replace numeric IDs: /users/12345 -> /users/{id}
  let pattern = pathname.replace(/\/\d+(?=\/|$)/g, '/{id}');

  // Replace UUIDs: /items/550e8400-e29b-41d4-a716-446655440000 -> /items/{uuid}
  pattern = pattern.replace(/\/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?=\/|$)/g, '/{uuid}');

  // Replace MongoDB ObjectIDs (24 hex characters)
  pattern = pattern.replace(/\/[0-9a-fA-F]{24}(?=\/|$)/g, '/{objectId}');

  // Replace hash-like tokens (32+ alphanumeric)
  pattern = pattern.replace(/\/[A-Za-z0-9_-]{32,}(?=\/|$)/g, '/{token}');

  return pattern;
}

/**
 * Detects if a request is a GraphQL query or mutation.
 * @param {Object} request
 * @returns {boolean}
 */
export function isGraphQL(request) {
  const url = request.url || '';
  if (url.includes('/graphql') || url.includes('/gql')) return true;

  const postData = request.postData || request.request?.postData?.text || '';
  if (typeof postData === 'string' && postData.trim()) {
    try {
      const parsed = JSON.parse(postData);
      if (parsed && (typeof parsed.query === 'string' || typeof parsed.mutation === 'string')) {
        return true;
      }
    } catch {
      if (/\b(?:query|mutation)\s*(?:[A-Za-z0-9_]+)?\s*\{/.test(postData)) {
        return true;
      }
    }
  }
  return false;
}

/**
 * Extracts API version from pathname if present.
 * @param {string} pathname
 * @returns {string|null}
 */
export function extractApiVersion(pathname) {
  const match = pathname.match(/\/(v\d+(?:\.\d+)?|api\/\d{4}-\d{2})\//i);
  return match ? match[1] : null;
}

/**
 * Builds a structured inventory of all observed API endpoints.
 * @param {Array<Object>} requests
 * @returns {Object}
 */
export function analyzeApiTraffic(requests = []) {
  const apiMap = new Map();
  const statusDistribution = {};
  let totalApiRequests = 0;
  let restCount = 0;
  let graphQlCount = 0;

  for (const req of requests) {
    const rawUrl = req.url || req.request?.url || '';
    const urlObj = safeParseUrl(rawUrl);
    if (!urlObj) continue;

    const mime = (req.mimeType || req.response?.content?.mimeType || '').toLowerCase();
    const pathname = urlObj.pathname;
    const isJsonMime = mime.includes('json');
    const isApiPath = pathname.includes('/api/') || pathname.startsWith('/api') || pathname.includes('/v1/') || pathname.includes('/v2/') || pathname.includes('/graphql');

    if (!isJsonMime && !isApiPath) {
      continue;
    }

    totalApiRequests++;
    const method = (req.method || req.request?.method || 'GET').toUpperCase();
    const status = req.status || req.response?.status || 0;
    const isGql = isGraphQL(req);

    if (isGql) graphQlCount++;
    else restCount++;

    const pattern = abstractRoutePattern(pathname);
    const key = `${method} ${urlObj.hostname}${pattern}`;

    // Track status distribution
    const statusKey = String(status || 'unknown');
    statusDistribution[statusKey] = (statusDistribution[statusKey] || 0) + 1;

    // Detect auth headers presence without exposing values
    const headers = req.headers || req.request?.headers || [];
    const hasAuth = Array.isArray(headers)
      ? headers.some(h => /^(authorization|x-api-key|x-auth-token|api-key)$/i.test(h.name || ''))
      : Boolean(headers['authorization'] || headers['x-api-key'] || headers['x-auth-token']);

    if (!apiMap.has(key)) {
      apiMap.set(key, {
        key,
        method,
        host: urlObj.hostname,
        pathnamePattern: pattern,
        sampleUrl: sanitizeUrl(rawUrl),
        apiType: isGql ? 'GraphQL' : 'REST / JSON API',
        apiVersion: extractApiVersion(pathname),
        requestCount: 0,
        hasAuthHeader: hasAuth,
        statuses: new Set(),
        durationsMs: []
      });
    }

    const entry = apiMap.get(key);
    entry.requestCount++;
    if (status) entry.statuses.add(status);
    if (req.time || req.durationMs) {
      entry.durationsMs.push(Math.round(req.time || req.durationMs));
    }
  }

  const endpoints = Array.from(apiMap.values()).map(ep => {
    const avgDuration = ep.durationsMs.length
      ? Math.round(ep.durationsMs.reduce((a, b) => a + b, 0) / ep.durationsMs.length)
      : null;

    return {
      ...ep,
      statuses: Array.from(ep.statuses).sort((a, b) => a - b),
      averageDurationMs: avgDuration,
      durationsMs: undefined // Exclude raw array
    };
  }).sort((a, b) => b.requestCount - a.requestCount);

  return {
    totalApiRequests,
    restCount,
    graphQlCount,
    uniqueEndpointsCount: endpoints.length,
    statusDistribution,
    endpoints
  };
}
