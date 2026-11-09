/**
 * ScopeLens Platform - Multi-Resolver DNS Comparison & DKIM Discovery
 * Queries multiple independent DoH resolvers (Cloudflare, Google, Quad9) in parallel
 * to verify DNS propagation, detect discrepancies, and discover DKIM public keys.
 */

export const DOH_RESOLVERS = [
  { id: 'cloudflare', name: 'Cloudflare (1.1.1.1)', endpoint: 'https://cloudflare-dns.com/dns-query', format: 'dns-json' },
  { id: 'google', name: 'Google (8.8.8.8)', endpoint: 'https://dns.google/resolve', format: 'google-json' },
  { id: 'quad9', name: 'Quad9 (9.9.9.9)', endpoint: 'https://dns.quad9.net/dns-query', format: 'dns-json' }
];

export const COMMON_DKIM_SELECTORS = [
  'default', 'google', 'k1', 's1', 's2', 'selector1', 'mail', 'dkim', 'cm', 'smtp', 'mandrill'
];

export class MultiResolverService {
  constructor(fetchFn = (typeof fetch !== 'undefined' ? fetch : null)) {
    this.fetchFn = fetchFn;
  }

  /**
   * Compares DNS resolution across multiple public DoH resolvers for a record type.
   * @param {string} hostname
   * @param {string} [type='A']
   * @returns {Promise<Object>} Comparison results with parity analysis
   */
  async compareResolvers(hostname, type = 'A') {
    const cleanHost = String(hostname || '').trim().replace(/\.$/, '');
    const resolverResults = [];

    for (const r of DOH_RESOLVERS) {
      try {
        const url = `${r.endpoint}?name=${encodeURIComponent(cleanHost)}&type=${type}`;
        const res = await this.fetchFn(url, {
          headers: { accept: 'application/dns-json' },
          cache: 'no-store'
        });

        if (!res.ok) {
          resolverResults.push({ resolver: r.id, name: r.name, status: res.status, answers: [], error: `HTTP ${res.status}` });
          continue;
        }

        const data = await res.json();
        const answers = (data.Answer || []).map(a => a.data).sort();
        resolverResults.push({
          resolver: r.id,
          name: r.name,
          status: data.Status,
          dnssec: Boolean(data.AD),
          answers
        });
      } catch (err) {
        resolverResults.push({ resolver: r.id, name: r.name, status: -1, answers: [], error: err.message });
      }
    }

    // Check parity among successful resolvers
    const successful = resolverResults.filter(r => !r.error && r.status === 0);
    let parity = true;
    let baseline = null;

    if (successful.length > 1) {
      baseline = successful[0].answers.join(',');
      for (let i = 1; i < successful.length; i++) {
        if (successful[i].answers.join(',') !== baseline) {
          parity = false;
          break;
        }
      }
    }

    return {
      hostname: cleanHost,
      type,
      resolvers: resolverResults,
      inSync: parity,
      summary: parity
        ? 'DNS answers are consistent across all queried public resolvers.'
        : 'Discrepancy detected between resolvers. This may indicate ongoing DNS propagation or GeoDNS routing.'
    };
  }

  /**
   * Probes common DKIM selectors for a target domain.
   * @param {string} hostname
   * @param {Array<string>} [selectors=COMMON_DKIM_SELECTORS]
   * @returns {Promise<Array<Object>>} Discovered DKIM keys
   */
  async discoverDkimSelectors(hostname, selectors = COMMON_DKIM_SELECTORS) {
    const cleanHost = String(hostname || '').trim().replace(/\.$/, '');
    const discovered = [];

    for (const sel of selectors) {
      const dkimHost = `${sel}._domainkey.${cleanHost}`;
      try {
        const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(dkimHost)}&type=TXT`;
        const res = await this.fetchFn(url, {
          headers: { accept: 'application/dns-json' },
          cache: 'no-store'
        });

        if (!res.ok) continue;
        const data = await res.json();
        const answers = data.Answer || [];

        for (const ans of answers) {
          const raw = String(ans.data || '').replace(/^"|"$/g, '').trim();
          if (/v=DKIM1/i.test(raw) || /p=[A-Za-z0-9+/=]+/i.test(raw)) {
            // Extract key algorithm and public key snippet
            const kMatch = raw.match(/k=([^;\s]+)/i);
            const pMatch = raw.match(/p=([^;\s]+)/i);
            discovered.push({
              selector: sel,
              domain: cleanHost,
              host: dkimHost,
              keyType: kMatch ? kMatch[1] : 'rsa',
              publicKeySnippet: pMatch ? pMatch[1].slice(0, 32) + '...' : '[PRESENT]',
              rawRecord: raw,
              ttl: ans.TTL
            });
            break;
          }
        }
      } catch {}
    }

    return discovered;
  }
}
