/**
 * ScopeLens Platform - OpenAPI 3.0.3 Draft Specification Generator
 * Compiles observed API requests, route patterns, methods, query parameters,
 * and status codes into a valid, standard OpenAPI 3.0 specification.
 */

export class OpenApiGenerator {
  /**
   * Generates an OpenAPI 3.0.3 specification from observed API endpoints.
   * @param {Object} options
   * @param {string} options.title
   * @param {string} options.targetOrigin
   * @param {Array<Object>} options.endpoints - Output from API Analyzer (e.g. pathnamePattern, method, statuses, etc.)
   * @param {Array<Object>} [options.sampleRequests=[]] - Raw requests for parameter and payload inference
   * @returns {Object} Valid OpenAPI 3.0.3 document
   */
  generateSpec({ title = 'Inspected API', targetOrigin = 'https://api.example.com', endpoints = [], sampleRequests = [] }) {
    const paths = {};

    for (const ep of endpoints) {
      const pathPattern = ep.pathnamePattern || '/';
      if (!paths[pathPattern]) {
        paths[pathPattern] = {};
      }

      const method = (ep.method || 'GET').toLowerCase();
      const pathParams = [];

      // Extract path variables e.g. /users/{id}
      const pathVarMatches = pathPattern.match(/\{([^}]+)\}/g);
      if (pathVarMatches) {
        for (const pv of pathVarMatches) {
          const varName = pv.replace(/[{}]/g, '');
          pathParams.push({
            name: varName,
            in: 'path',
            required: true,
            schema: {
              type: varName.includes('uuid') ? 'string' : (varName === 'id' || varName.endsWith('Id') ? 'string' : 'string')
            },
            description: `Auto-discovered path parameter: ${varName}`
          });
        }
      }

      // Infer query parameters from sample requests matching this endpoint
      const queryParams = new Map();
      const matchingSamples = sampleRequests.filter(r => {
        try {
          const u = new URL(r.url);
          return u.pathname === ep.pathname || r.pathnamePattern === ep.pathnamePattern;
        } catch {
          return false;
        }
      });

      for (const sample of matchingSamples) {
        try {
          const u = new URL(sample.url);
          for (const [qKey, qVal] of u.searchParams.entries()) {
            if (!queryParams.has(qKey)) {
              queryParams.set(qKey, {
                name: qKey,
                in: 'query',
                required: false,
                schema: { type: isNaN(Number(qVal)) ? 'string' : 'number' }
              });
            }
          }
        } catch {}
      }

      const allParams = [...pathParams, ...Array.from(queryParams.values())];

      // Build responses map
      const responses = {};
      const observedStatuses = ep.statuses && ep.statuses.length ? ep.statuses : [200];
      for (const status of observedStatuses) {
        responses[String(status)] = {
          description: this._getStatusDescription(status),
          content: {
            'application/json': {
              schema: { type: 'object' }
            }
          }
        };
      }

      // Assemble operation
      paths[pathPattern][method] = {
        summary: `${ep.method} ${pathPattern}`,
        description: `Discovered by ScopeLens. Category: ${ep.apiType || 'REST API'}. Observed ${ep.requestCount || 1} request(s).`,
        operationId: `${method}_${pathPattern.replace(/[^a-zA-Z0-9]/g, '_').replace(/^_+|_+$/g, '')}`,
        parameters: allParams.length ? allParams : undefined,
        responses
      };

      // Add requestBody placeholder for POST, PUT, PATCH
      if (['post', 'put', 'patch'].includes(method)) {
        paths[pathPattern][method].requestBody = {
          description: 'Auto-detected request payload',
          required: false,
          content: {
            'application/json': {
              schema: { type: 'object' }
            }
          }
        };
      }
    }

    return {
      openapi: '3.0.3',
      info: {
        title: `${title} - Draft Specification`,
        description: 'Auto-generated OpenAPI 3.0.3 draft by ScopeLens Web Security & Network Intelligence Platform based on passively observed network transactions.',
        version: '1.0.0'
      },
      servers: [
        {
          url: targetOrigin,
          description: 'Inspected target host'
        }
      ],
      paths
    };
  }

  _getStatusDescription(status) {
    const code = Number(status);
    if (code === 200) return 'OK - Successful response';
    if (code === 201) return 'Created - Resource created';
    if (code === 204) return 'No Content - Action completed';
    if (code === 301 || code === 302) return 'Redirect - Resource relocated';
    if (code === 400) return 'Bad Request - Validation error';
    if (code === 401) return 'Unauthorized - Authentication required';
    if (code === 403) return 'Forbidden - Insufficient permissions';
    if (code === 404) return 'Not Found - Resource does not exist';
    if (code === 500) return 'Internal Server Error';
    return `HTTP ${code} Response`;
  }
}
