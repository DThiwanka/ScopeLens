/**
 * Tests for OpenAPI 3.0.3 Specification Generator
 */

import { assertEqual, assertTrue } from './test-utils.js';
import { OpenApiGenerator } from '../src/modules/api/openapi-generator.js';

export function runOpenApiGeneratorTests() {
  const generator = new OpenApiGenerator();

  const mockEndpoints = [
    {
      pathnamePattern: '/api/v1/users/{id}',
      method: 'GET',
      apiType: 'REST',
      requestCount: 5,
      statuses: [200, 404]
    },
    {
      pathnamePattern: '/api/v1/users',
      method: 'POST',
      apiType: 'REST',
      requestCount: 2,
      statuses: [201, 400]
    }
  ];

  const mockSamples = [
    { url: 'https://api.example.com/api/v1/users/42?include_profile=true&limit=10', pathnamePattern: '/api/v1/users/{id}' }
  ];

  const spec = generator.generateSpec({
    title: 'Customer API',
    targetOrigin: 'https://api.example.com',
    endpoints: mockEndpoints,
    sampleRequests: mockSamples
  });

  assertEqual(spec.openapi, '3.0.3', 'Generates OpenAPI 3.0.3 spec');
  assertEqual(spec.servers[0].url, 'https://api.example.com', 'Sets server target');
  assertTrue(Boolean(spec.paths['/api/v1/users/{id}']), 'Path with path variable exists');
  assertTrue(Boolean(spec.paths['/api/v1/users/{id}'].get), 'GET operation created');
  assertTrue(Boolean(spec.paths['/api/v1/users'].post), 'POST operation created');
  assertTrue(Boolean(spec.paths['/api/v1/users'].post.requestBody), 'POST has requestBody');

  // Verify parameters on GET /users/{id}
  const params = spec.paths['/api/v1/users/{id}'].get.parameters;
  assertTrue(params.some(p => p.name === 'id' && p.in === 'path'), 'Path parameter id detected');
  assertTrue(params.some(p => p.name === 'include_profile' && p.in === 'query'), 'Query param include_profile inferred');

  // Verify responses
  const getResponses = spec.paths['/api/v1/users/{id}'].get.responses;
  assertTrue(Boolean(getResponses['200']), '200 response defined');
  assertTrue(Boolean(getResponses['404']), '404 response defined');
}
