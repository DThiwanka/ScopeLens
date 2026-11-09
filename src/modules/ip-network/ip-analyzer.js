/**
 * Module A - IP & Network Intelligence Analyzer
 * Analyzes remote IP addresses, connection ports, IPv4/IPv6 classification,
 * first-party vs third-party host separation, and request grouping.
 */

import { safeParseUrl } from '../../core/utils.js';

export const IP_TYPES = {
  IPV4: 'IPv4',
  IPV6: 'IPv6',
  UNKNOWN: 'Unknown'
};

export const IP_SCOPES = {
  PUBLIC: 'Public',
  PRIVATE: 'Private (RFC 1918)',
  LOOPBACK: 'Loopback',
  LINK_LOCAL: 'Link-Local',
  CARRIER_GRADE_NAT: 'Carrier-Grade NAT',
  SPECIAL: 'Special/Reserved',
  UNKNOWN: 'Unknown'
};

/**
 * Detects if a string is a valid IPv4 or IPv6 address.
 * @param {string} ip
 * @returns {string}
 */
export function getIpType(ip) {
  if (!ip || typeof ip !== 'string') return IP_TYPES.UNKNOWN;
  const trimmed = ip.trim();

  // IPv4 check
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(trimmed)) {
    const parts = trimmed.split('.').map(p => parseInt(p, 10));
    if (parts.every(p => !isNaN(p) && p >= 0 && p <= 255)) {
      return IP_TYPES.IPV4;
    }
  }

  // IPv6 check
  if (trimmed.includes(':') && /^[0-9a-fA-F:]+$/.test(trimmed)) {
    try {
      const u = new URL(`http://[${trimmed}]`);
      if (u.hostname === `[${trimmed.toLowerCase()}]`) {
        return IP_TYPES.IPV6;
      }
    } catch {
      // Fallback
    }
  }

  return IP_TYPES.UNKNOWN;
}

/**
 * Classifies the network scope of an IPv4 or IPv6 address.
 * @param {string} ip
 * @returns {string}
 */
export function classifyIpScope(ip) {
  if (!ip || typeof ip !== 'string') return IP_SCOPES.UNKNOWN;
  const trimmed = ip.trim();

  // IPv4 Classifications
  if (getIpType(trimmed) === IP_TYPES.IPV4) {
    const parts = trimmed.split('.').map(p => parseInt(p, 10));
    if (parts.some(p => isNaN(p) || p < 0 || p > 255)) return IP_SCOPES.UNKNOWN;

    // Loopback 127.0.0.0/8
    if (parts[0] === 127) return IP_SCOPES.LOOPBACK;

    // RFC 1918 Private: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    if (parts[0] === 10) return IP_SCOPES.PRIVATE;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return IP_SCOPES.PRIVATE;
    if (parts[0] === 192 && parts[1] === 168) return IP_SCOPES.PRIVATE;

    // Link-local: 169.254.0.0/16
    if (parts[0] === 169 && parts[1] === 254) return IP_SCOPES.LINK_LOCAL;

    // CGNAT RFC 6598: 100.64.0.0/10
    if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return IP_SCOPES.CARRIER_GRADE_NAT;

    // 0.0.0.0 or 255.255.255.255
    if (parts[0] === 0 || parts[0] >= 224) return IP_SCOPES.SPECIAL;

    return IP_SCOPES.PUBLIC;
  }

  // IPv6 Classifications
  if (getIpType(trimmed) === IP_TYPES.IPV6) {
    const lower = trimmed.toLowerCase();
    if (lower === '::1') return IP_SCOPES.LOOPBACK;
    if (lower.startsWith('fe80:')) return IP_SCOPES.LINK_LOCAL;
    if (lower.startsWith('fc00:') || lower.startsWith('fd')) return IP_SCOPES.PRIVATE;
    return IP_SCOPES.PUBLIC;
  }

  return IP_SCOPES.UNKNOWN;
}

/**
 * Processes a collection of captured network records into structured IP intelligence.
 * @param {Array<Object>} records
 * @param {string} targetOrigin
 * @returns {Object}
 */
export function analyzeIpIntelligence(records = [], targetOrigin = '') {
  const targetHost = targetOrigin ? safeParseUrl(targetOrigin)?.hostname || '' : '';

  const ipMap = new Map();
  const domainMap = new Map();
  const portSet = new Set();

  let ipv4Count = 0;
  let ipv6Count = 0;
  let firstPartyCount = 0;
  let thirdPartyCount = 0;

  for (const record of records) {
    const ip = record.remoteIp;
    const urlObj = safeParseUrl(record.url);
    const host = urlObj ? urlObj.hostname : 'unknown';
    const isFirstParty = targetHost ? (host === targetHost || host.endsWith('.' + targetHost)) : true;

    if (isFirstParty) firstPartyCount++;
    else thirdPartyCount++;

    if (record.remotePort) {
      portSet.add(record.remotePort);
    }

    // Process IP
    if (ip && ip !== 'Not exposed by browser' && ip !== '—') {
      const type = getIpType(ip);
      const scope = classifyIpScope(ip);

      if (!ipMap.has(ip)) {
        if (type === IP_TYPES.IPV4) ipv4Count++;
        if (type === IP_TYPES.IPV6) ipv6Count++;

        ipMap.set(ip, {
          ip,
          type,
          scope,
          isPublic: scope === IP_SCOPES.PUBLIC,
          hosts: new Set(),
          ports: new Set(),
          protocols: new Set(),
          requestCount: 0,
          firstSeen: record.seenAt,
          lastSeen: record.seenAt
        });
      }

      const ipEntry = ipMap.get(ip);
      ipEntry.hosts.add(host);
      if (record.remotePort) ipEntry.ports.add(record.remotePort);
      if (record.protocol) ipEntry.protocols.add(record.protocol);
      ipEntry.requestCount++;
      ipEntry.lastSeen = record.seenAt;
    }

    // Process Domain
    if (host && host !== 'unknown') {
      if (!domainMap.has(host)) {
        domainMap.set(host, {
          hostname: host,
          isFirstParty,
          requestCount: 0,
          ips: new Set(),
          statuses: new Map(),
          totalBytes: 0
        });
      }
      const domEntry = domainMap.get(host);
      domEntry.requestCount++;
      if (ip && ip !== 'Not exposed by browser') domEntry.ips.add(ip);
      const statusKey = String(record.status || 'unknown');
      domEntry.statuses.set(statusKey, (domEntry.statuses.get(statusKey) || 0) + 1);
    }
  }

  // Convert Sets to Arrays for serialization
  const endpoints = Array.from(ipMap.values()).map(entry => ({
    ...entry,
    hosts: Array.from(entry.hosts),
    ports: Array.from(entry.ports).sort((a, b) => a - b),
    protocols: Array.from(entry.protocols)
  })).sort((a, b) => b.requestCount - a.requestCount);

  const domains = Array.from(domainMap.values()).map(d => ({
    ...d,
    ips: Array.from(d.ips),
    statuses: Object.fromEntries(d.statuses)
  })).sort((a, b) => b.requestCount - a.requestCount);

  const observedPorts = Array.from(portSet).sort((a, b) => a - b);

  return {
    totalRecords: records.length,
    distinctIps: ipMap.size,
    ipv4Count,
    ipv6Count,
    firstPartyRequests: firstPartyCount,
    thirdPartyRequests: thirdPartyCount,
    observedPorts,
    endpoints,
    domains,
    frequentlyContactedHosts: domains.slice(0, 10)
  };
}
