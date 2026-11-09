/**
 * Tests for Module H: API Discovery & Inspection
 */

import { assertEqual, assertTrue } from './test-utils.js';
import { abstractRoutePattern, isGraphQL, analyzeApiTraffic } from '../src/modules/api/api-analyzer.js';

export function runApiAnalyzerTests() {
  // 1. Abstract Route Patterns
  assertEqual(abstractRoutePattern('/api/v1/users/12345'), '/api/v1/users/{id}', 'Abstracts numeric IDs');
  assertEqual(abstractRoutePattern('/api/v2/orders/550e8400-e29b-41d4-a716-446655440000/items'), '/api/v2/orders/{uuid}/items', 'Abstracts UUIDs');
  assertEqual(abstractRoutePattern('/api/posts/507f1f77bcf86cd799439011'), '/api/posts/{objectId}', 'Abstracts MongoDB ObjectIDs');

  // 2. GraphQL Detection
  assertTrue(isGraphQL({ url: 'https://example.com/graphql' }), 'Detects GraphQL from URL path');
  assertTrue(isGraphQL({ url: 'https://example.com/api', postData: '{"query":"{ users { id name } }"}' }), 'Detects GraphQL from JSON payload');

  // 3. API Traffic Analysis
  const mockRequests = [
    { url: 'https://example.com/api/v1/users/1', method: 'GET', status: 200, mimeType: 'application/json', time: 120 },
    { url: 'https://example.com/api/v1/users/2', method: 'GET', status: 200, mimeType: 'application/json', time: 140 },
    { url: 'https://example.com/graphql', method: 'POST', status: 200, mimeType: 'application/json', time: 250, postData: 'query { me { id } }' },
    { url: 'https://example.com/style.css', method: 'GET', status: 200, mimeType: 'text/css', time: 40 }
  ];

  const analysis = analyzeApiTraffic(mockRequests);
  assertEqual(analysis.totalApiRequests, 3, 'Counts API requests and ignores CSS');
  assertEqual(analysis.graphQlCount, 1, 'Counts 1 GraphQL request');
  assertEqual(analysis.restCount, 2, 'Counts 2 REST requests');
  assertEqual(analysis.uniqueEndpointsCount, 2, 'Groups repeated route /users/{id} together');
}
