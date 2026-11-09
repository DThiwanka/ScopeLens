/**
 * Module B - Advanced DNS Analysis Service
 * Queries DoH resolvers (Cloudflare, Google, Quad9) for comprehensive DNS inspection,
 * validates DNSSEC, parses SPF/DMARC policies, and detects mail/nameserver providers.
 */

import { DNS_RECORD_TYPES } from '../../core/constants.js';

export const DOH_RESOLVERS = {
  CLOUDFLARE: {
    id: 'cloudflare',
    name: 'Cloudflare DoH',
    endpoint: 'https://cloudflare-dns.com/dns-query'
  },
  GOOGLE: {
    id: 'google',
    name: 'Google Public DNS',
    endpoint: 'https://dns.google/resolve'
  }
};

/**
 * Identifies well-known mail providers based on MX hostnames.
 * @param {Array<string>} mxHosts
 * @returns {Array<string>}
 */
export function identifyMailProviders(mxHosts = []) {
  const providers = new Set();
  const lowerHosts = mxHosts.map(h => h.toLowerCase());

  for (const host of lowerHosts) {
    if (host.includes('google.com') || host.includes('googlemail.com') || host.includes('aspmx.l.google.com')) {
      providers.add('Google Workspace / Gmail');
    } else if (host.includes('outlook.com') || host.includes('microsoft.com') || host.includes('protection.outlook.com')) {
      providers.add('Microsoft 365 / Exchange Online');
    } else if (host.includes('protonmail.ch') || host.includes('proton.me')) {
      providers.add('Proton Mail');
    } else if (host.includes('zoho.com') || host.includes('zoho.eu')) {
      providers.add('Zoho Mail');
    } else if (host.includes('fastmail.com') || host.includes('messagingengine.com')) {
      providers.add('Fastmail');
    } else if (host.includes('mimecast.com')) {
      providers.add('Mimecast Gateway');
    } else if (host.includes('proofpoint.com') || host.includes('pphosted.com')) {
      providers.add('Proofpoint Protection');
    } else if (host.includes('sendgrid.net')) {
      providers.add('Twilio SendGrid');
    } else if (host.includes('mailgun.org')) {
      providers.add('Mailgun');
    } else if (host.includes('amazonses.com')) {
      providers.add('Amazon SES');
    } else if (host.includes('icloud.com') || host.includes('apple.com')) {
      providers.add('Apple iCloud Mail');
    }
  }

  return Array.from(providers);
}

/**
 * Identifies DNS / Nameserver providers based on NS records.
 * @param {Array<string>} nsHosts
 * @returns {Array<string>}
 */
export function identifyNameserverProviders(nsHosts = []) {
  const providers = new Set();
  const lowerHosts = nsHosts.map(h => h.toLowerCase());

  for (const host of lowerHosts) {
    if (host.includes('cloudflare.com')) providers.add('Cloudflare');
    else if (host.includes('awsdns')) providers.add('Amazon Route 53');
    else if (host.includes('googledomains.com') || host.includes('google.com')) providers.add('Google Cloud DNS');
    else if (host.includes('azure-dns')) providers.add('Microsoft Azure DNS');
    else if (host.includes('digitalocean.com')) providers.add('DigitalOcean');
    else if (host.includes('dnsimple.com')) providers.add('DNSimple');
    else if (host.includes('namecheap.com')) providers.add('Namecheap DNS');
    else if (host.includes('godaddy.com') || host.includes('domaincontrol.com')) providers.add('GoDaddy DNS');
  }

  return Array.from(providers);
}

/**
 * Parses and audits an SPF (Sender Policy Framework) TXT record.
 * @param {string} spfText
 * @returns {Object}
 */
export function parseSpfRecord(spfText) {
  if (!spfText || typeof spfText !== 'string' || !spfText.startsWith('v=spf1')) {
    return null;
  }

  const parts = spfText.split(/\s+/).filter(Boolean);
  const version = parts[0];
  const mechanisms = parts.slice(1);

  const includes = [];
  const ip4 = [];
  const ip6 = [];
  let allPolicy = 'none';

  for (const m of mechanisms) {
    if (m.startsWith('include:')) includes.push(m.slice(8));
    else if (m.startsWith('ip4:')) ip4.push(m.slice(4));
    else if (m.startsWith('ip6:')) ip6.push(m.slice(4));
    else if (m === '-all') allPolicy = 'Hard Fail (-all, strict)';
    else if (m === '~all') allPolicy = 'Soft Fail (~all, transition)';
    else if (m === '?all') allPolicy = 'Neutral (?all)';
    else if (m === '+all') allPolicy = 'Pass (+all, dangerous: permits all senders)';
  }

  const warnings = [];
  if (allPolicy.includes('+all')) {
    warnings.push('SPF record ends with +all which permits unauthorized parties to spoof emails from this domain.');
  } else if (allPolicy === 'none') {
    warnings.push('SPF record lacks an explicit catch-all mechanism (-all or ~all).');
  }

  return {
    raw: spfText,
    version,
    allPolicy,
    includes,
    ip4,
    ip6,
    warnings,
    isStrict: allPolicy.includes('-all')
  };
}

/**
 * Parses and audits a DMARC record string.
 * @param {string} dmarcText
 * @returns {Object}
 */
export function parseDmarcRecord(dmarcText) {
  if (!dmarcText || typeof dmarcText !== 'string' || !dmarcText.startsWith('v=DMARC1')) {
    return null;
  }

  const tags = {};
  const tokens = dmarcText.split(';').map(t => t.trim()).filter(Boolean);

  for (const token of tokens) {
    const eqIdx = token.indexOf('=');
    if (eqIdx !== -1) {
      const key = token.slice(0, eqIdx).trim().toLowerCase();
      const val = token.slice(eqIdx + 1).trim();
      tags[key] = val;
    }
  }

  const policy = tags.p || 'none';
  const subdomainPolicy = tags.sp || policy;
  const percentage = tags.pct || '100';
  const rua = tags.rua || null;
  const ruf = tags.ruf || null;

  const warnings = [];
  if (policy === 'none') {
    warnings.push('DMARC policy is set to p=none (monitoring only, not rejecting or quarantining spoofed emails).');
  }
  if (!rua) {
    warnings.push('No aggregate reporting address (rua) configured to receive authentication failure reports.');
  }

  return {
    raw: dmarcText,
    policy,
    subdomainPolicy,
    percentage: parseInt(percentage, 10),
    rua,
    ruf,
    warnings,
    isEnforced: policy === 'reject' || policy === 'quarantine'
  };
}

/**
 * Performs a comprehensive DNS lookup across multiple record types via Cloudflare DoH.
 * @param {string} hostname
 * @param {string} [resolverUrl]
 * @returns {Promise<Object>}
 */
export async function queryDns(hostname, resolverUrl = DOH_RESOLVERS.CLOUDFLARE.endpoint) {
  const cleanHost = String(hostname || '').trim().replace(/\.$/, '');
  if (!cleanHost || cleanHost.length > 253 || /[^a-zA-Z0-9.-]/.test(cleanHost)) {
    throw new Error('Invalid domain or hostname format.');
  }

  let dnssecValidated = false;
  const records = {};
  const allTxtRecords = [];
  const mxHostnames = [];
  const nsHostnames = [];

  const typesToQuery = [...DNS_RECORD_TYPES];

  const results = await Promise.all(typesToQuery.map(async type => {
    try {
      const url = `${resolverUrl}?name=${encodeURIComponent(cleanHost)}&type=${type}`;
      const resp = await fetch(url, { headers: { accept: 'application/dns-json' }, cache: 'no-store' });
      if (!resp.ok) return { type, status: resp.status, answers: [], error: `HTTP ${resp.status}` };
      const data = await resp.json();
      if (data.AD) dnssecValidated = true;

      const answers = (data.Answer || []).map(a => ({
        name: a.name,
        type: a.type,
        ttl: a.TTL,
        data: String(a.data || '').replace(/^"|"$/g, '')
      }));

      records[type] = answers;

      if (type === 'TXT') {
        answers.forEach(a => allTxtRecords.push(a.data));
      } else if (type === 'MX') {
        answers.forEach(a => {
          const parts = a.data.split(/\s+/);
          if (parts.length > 1) mxHostnames.push(parts[1]);
          else mxHostnames.push(a.data);
        });
      } else if (type === 'NS') {
        answers.forEach(a => nsHostnames.push(a.data));
      }

      return { type, status: data.Status, answers };
    } catch (err) {
      return { type, status: -1, answers: [], error: err.message };
    }
  }));

  // Also query _dmarc.hostname for DMARC record
  let dmarcRecord = null;
  try {
    const dmarcUrl = `${resolverUrl}?name=${encodeURIComponent(`_dmarc.${cleanHost}`)}&type=TXT`;
    const dmarcResp = await fetch(dmarcUrl, { headers: { accept: 'application/dns-json' }, cache: 'no-store' });
    if (dmarcResp.ok) {
      const dmarcData = await dmarcResp.json();
      const txt = (dmarcData.Answer || []).map(a => String(a.data || '').replace(/^"|"$/g, '')).find(t => t.startsWith('v=DMARC1'));
      if (txt) dmarcRecord = parseDmarcRecord(txt);
    }
  } catch {
    // DMARC query optional
  }

  // Find SPF record in TXT
  const spfTxt = allTxtRecords.find(t => t.startsWith('v=spf1'));
  const spfRecord = spfTxt ? parseSpfRecord(spfTxt) : null;

  const mailProviders = identifyMailProviders(mxHostnames);
  const nameserverProviders = identifyNameserverProviders(nsHostnames);

  return {
    hostname: cleanHost,
    dnssecValidated,
    records,
    results,
    spfRecord,
    dmarcRecord,
    mailProviders,
    nameserverProviders,
    queriedAt: new Date().toISOString(),
    resolver: resolverUrl
  };
}
