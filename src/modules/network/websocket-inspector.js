/**
 * ScopeLens Platform - WebSocket & Server-Sent Events (SSE) Inspector
 * Identifies real-time streaming connections, protocols, and transport security flaws.
 */

import { SEVERITY, CONFIDENCE } from '../../core/constants.js';

export class WebSocketInspector {
  /**
   * Evaluates network transactions for WebSocket handshakes and Server-Sent Events.
   * @param {Array<Object>} networkItems
   * @param {string} [topOrigin='']
   * @returns {{ webSockets: Array<Object>, sseStreams: Array<Object>, findings: Array<Object> }}
   */
  inspectStreams(networkItems = [], topOrigin = '') {
    const webSockets = [];
    const sseStreams = [];
    const findings = [];
    const isTopHttps = topOrigin.startsWith('https://');

    for (const item of networkItems) {
      const url = item.url || '';
      const mime = (item.mimeType || '').toLowerCase();
      const headers = item.headers || {};
      const norm = {};
      if (Array.isArray(headers)) {
        headers.forEach(([k, v]) => { if (k) norm[k.toLowerCase()] = String(v).trim(); });
      } else {
        Object.entries(headers).forEach(([k, v]) => { if (k) norm[k.toLowerCase()] = String(v).trim(); });
      }

      const isWsUrl = /^wss?:\/\//i.test(url);
      const isWsUpgrade = norm['upgrade']?.toLowerCase() === 'websocket' || Boolean(norm['sec-websocket-key']);
      const isSse = mime.includes('text/event-stream') || norm['content-type']?.includes('text/event-stream');

      // 1. WebSocket Detection
      if (isWsUrl || isWsUpgrade) {
        const isPlainWs = url.startsWith('ws://') || (!url.startsWith('wss://') && !isTopHttps);
        const record = {
          url,
          protocol: isPlainWs ? 'ws' : 'wss',
          status: item.status,
          remoteIp: item.remoteIp || '—',
          extensions: norm['sec-websocket-extensions'] || 'none',
          subprotocols: norm['sec-websocket-protocol'] || 'none',
          observedAt: item.seenAt || new Date().toISOString()
        };
        webSockets.push(record);

        // Security check: Plain unencrypted WebSocket on HTTPS page
        if (isTopHttps && isPlainWs) {
          findings.push({
            id: 'SEC-WS-UNENCRYPTED-STREAM',
            category: 'Transport Security',
            title: 'Unencrypted WebSocket (ws://) Connection on HTTPS Origin',
            description: `The page initiated an unencrypted WebSocket stream to "${url}".`,
            severity: SEVERITY.HIGH,
            confidence: CONFIDENCE.CONFIRMED,
            evidence: `Target: ${url}`,
            affectedResource: url,
            explanation: 'Plain ws:// connections lack TLS encryption, allowing local network adversaries to eavesdrop on and tamper with real-time messages.',
            remediation: 'Always use secure WebSockets (wss://) on production websites.'
          });
        }
      }

      // 2. Server-Sent Events (SSE) Detection
      if (isSse) {
        sseStreams.push({
          url,
          status: item.status,
          remoteIp: item.remoteIp || '—',
          observedAt: item.seenAt || new Date().toISOString()
        });
      }
    }

    return { webSockets, sseStreams, findings };
  }
}
