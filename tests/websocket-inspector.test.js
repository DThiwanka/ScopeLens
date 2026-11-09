/**
 * Tests for WebSocket & Server-Sent Events Inspector
 */

import { assertEqual, assertTrue } from './test-utils.js';
import { WebSocketInspector } from '../src/modules/network/websocket-inspector.js';

export function runWebSocketInspectorTests() {
  const inspector = new WebSocketInspector();

  const mockTraffic = [
    {
      url: 'ws://insecure.example.com/chat',
      status: 101,
      headers: { 'Upgrade': 'websocket', 'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==' }
    },
    {
      url: 'wss://secure.example.com/live',
      status: 101,
      headers: { 'Upgrade': 'websocket' }
    },
    {
      url: 'https://example.com/api/events',
      status: 200,
      mimeType: 'text/event-stream',
      headers: { 'Content-Type': 'text/event-stream' }
    }
  ];

  const result = inspector.inspectStreams(mockTraffic, 'https://example.com');

  assertEqual(result.webSockets.length, 2, 'Detects 2 WebSocket connections');
  assertEqual(result.sseStreams.length, 1, 'Detects 1 Server-Sent Events stream');
  assertTrue(result.findings.some(f => f.id === 'SEC-WS-UNENCRYPTED-STREAM'), 'Flags unencrypted ws:// on HTTPS origin');
}
