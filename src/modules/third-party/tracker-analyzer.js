/**
 * Module I - Third-Party Tracking & Dependency Intelligence
 * Identifies external domains, categorizes services (analytics, ads, CDNs, fonts, social, trackers),
 * and generates dependency graph nodes and links for visualization.
 */

import { safeParseUrl } from '../../core/utils.js';

export const TRACKER_CATEGORIES = {
  ANALYTICS: 'Analytics',
  ADVERTISING: 'Advertising / Marketing',
  TRACKER: 'Tracking Pixel',
  CDN: 'Content Delivery Network',
  FONTS: 'Web Fonts',
  VIDEO: 'Video Streaming / Media',
  SOCIAL: 'Social Media Integration',
  PAYMENT: 'Payment Gateway',
  ESSENTIAL: 'External Dependency'
};

const KNOWN_DOMAINS = [
  // Analytics
  { pattern: /google-analytics\.com|analytics\.google\.com|googletagmanager\.com/, category: TRACKER_CATEGORIES.ANALYTICS, provider: 'Google' },
  { pattern: /hotjar\.com/, category: TRACKER_CATEGORIES.ANALYTICS, provider: 'Hotjar' },
  { pattern: /segment\.io|segment\.com/, category: TRACKER_CATEGORIES.ANALYTICS, provider: 'Twilio Segment' },
  { pattern: /mixpanel\.com/, category: TRACKER_CATEGORIES.ANALYTICS, provider: 'Mixpanel' },
  { pattern: /clarity\.ms/, category: TRACKER_CATEGORIES.ANALYTICS, provider: 'Microsoft Clarity' },
  { pattern: /sentry\.io/, category: TRACKER_CATEGORIES.ANALYTICS, provider: 'Sentry' },

  // Advertising & Trackers
  { pattern: /doubleclick\.net|googleadservices\.com|googlesyndication\.com/, category: TRACKER_CATEGORIES.ADVERTISING, provider: 'Google Ads' },
  { pattern: /facebook\.net|facebook\.com|connect\.facebook\.net/, category: TRACKER_CATEGORIES.ADVERTISING, provider: 'Meta / Facebook Pixel' },
  { pattern: /tiktok\.com|analytics\.tiktok\.com/, category: TRACKER_CATEGORIES.ADVERTISING, provider: 'TikTok Pixel' },
  { pattern: /criteo\.com|criteo\.net/, category: TRACKER_CATEGORIES.ADVERTISING, provider: 'Criteo' },
  { pattern: /taboola\.com/, category: TRACKER_CATEGORIES.ADVERTISING, provider: 'Taboola' },
  { pattern: /outbrain\.com/, category: TRACKER_CATEGORIES.ADVERTISING, provider: 'Outbrain' },

  // Fonts
  { pattern: /fonts\.googleapis\.com|fonts\.gstatic\.com/, category: TRACKER_CATEGORIES.FONTS, provider: 'Google Fonts' },
  { pattern: /use\.typekit\.net|p\.typekit\.net/, category: TRACKER_CATEGORIES.FONTS, provider: 'Adobe Typekit' },
  { pattern: /fontawesome\.com|kit\.fontawesome\.com/, category: TRACKER_CATEGORIES.FONTS, provider: 'Font Awesome' },

  // CDNs
  { pattern: /cdnjs\.cloudflare\.com/, category: TRACKER_CATEGORIES.CDN, provider: 'Cloudflare cdnjs' },
  { pattern: /jsdelivr\.net/, category: TRACKER_CATEGORIES.CDN, provider: 'jsDelivr' },
  { pattern: /unpkg\.com/, category: TRACKER_CATEGORIES.CDN, provider: 'unpkg' },
  { pattern: /ajax\.googleapis\.com/, category: TRACKER_CATEGORIES.CDN, provider: 'Google Hosted Libraries' },

  // Video
  { pattern: /youtube\.com|youtube-nocookie\.com|ytimg\.com/, category: TRACKER_CATEGORIES.VIDEO, provider: 'YouTube' },
  { pattern: /vimeo\.com|vimeocdn\.com/, category: TRACKER_CATEGORIES.VIDEO, provider: 'Vimeo' },

  // Social
  { pattern: /twitter\.com|x\.com|twimg\.com/, category: TRACKER_CATEGORIES.SOCIAL, provider: 'X / Twitter' },
  { pattern: /linkedin\.com|licdn\.com/, category: TRACKER_CATEGORIES.SOCIAL, provider: 'LinkedIn' },

  // Payment
  { pattern: /stripe\.com/, category: TRACKER_CATEGORIES.PAYMENT, provider: 'Stripe' },
  { pattern: /paypal\.com|paypalobjects\.com/, category: TRACKER_CATEGORIES.PAYMENT, provider: 'PayPal' }
];

/**
 * Classifies an external domain into tracker and service categories.
 * @param {string} domain
 * @returns {{category: string, provider: string}}
 */
export function classifyExternalDomain(domain) {
  if (!domain) return { category: TRACKER_CATEGORIES.ESSENTIAL, provider: 'Unknown' };
  const lower = domain.toLowerCase();

  for (const entry of KNOWN_DOMAINS) {
    if (entry.pattern.test(lower)) {
      return { category: entry.category, provider: entry.provider };
    }
  }

  // Generic heuristic
  if (lower.includes('cdn') || lower.includes('static') || lower.includes('assets')) {
    return { category: TRACKER_CATEGORIES.CDN, provider: 'Content Delivery Network' };
  }
  if (lower.includes('track') || lower.includes('pixel') || lower.includes('beacon')) {
    return { category: TRACKER_CATEGORIES.TRACKER, provider: 'Telemetry / Beacon' };
  }

  return { category: TRACKER_CATEGORIES.ESSENTIAL, provider: 'Third-Party Host' };
}

/**
 * Analyzes network traffic to construct third-party dependency data and visual graph.
 * @param {Array<Object>} requests
 * @param {string} activeOrigin
 * @returns {Object}
 */
export function analyzeThirdPartyTrackers(requests = [], activeOrigin = '') {
  const originUrl = safeParseUrl(activeOrigin);
  const primaryHost = originUrl ? originUrl.hostname : '';

  const thirdPartyMap = new Map();
  const categoryCounts = {};
  let totalThirdPartyRequests = 0;

  for (const req of requests) {
    const rawUrl = req.url || req.request?.url || '';
    const urlObj = safeParseUrl(rawUrl);
    if (!urlObj) continue;

    const host = urlObj.hostname;
    const isFirstParty = primaryHost ? (host === primaryHost || host.endsWith('.' + primaryHost)) : true;
    if (isFirstParty) continue;

    totalThirdPartyRequests++;
    const { category, provider } = classifyExternalDomain(host);
    categoryCounts[category] = (categoryCounts[category] || 0) + 1;

    if (!thirdPartyMap.has(host)) {
      thirdPartyMap.set(host, {
        domain: host,
        provider,
        category,
        requestCount: 0,
        resources: new Set(),
        protocols: new Set(),
        totalBytes: 0
      });
    }

    const entry = thirdPartyMap.get(host);
    entry.requestCount++;
    const resourceType = req.mimeType || req._resourceType || 'other';
    entry.resources.add(resourceType);
    if (req.protocol) entry.protocols.add(req.protocol);
    if (req.size || req.transferSize) entry.totalBytes += (req.size || req.transferSize);
  }

  const thirdPartyDomains = Array.from(thirdPartyMap.values()).map(e => ({
    ...e,
    resources: Array.from(e.resources),
    protocols: Array.from(e.protocols)
  })).sort((a, b) => b.requestCount - a.requestCount);

  // Build dependency graph nodes and links for visualization
  const nodes = [{ id: primaryHost || 'First-Party Origin', type: 'first-party', category: 'Origin' }];
  const links = [];

  thirdPartyDomains.forEach(tp => {
    nodes.push({ id: tp.domain, type: 'third-party', category: tp.category, provider: tp.provider, requests: tp.requestCount });
    links.push({ source: primaryHost || 'First-Party Origin', target: tp.domain, value: tp.requestCount });
  });

  return {
    totalThirdPartyRequests,
    distinctThirdPartyDomains: thirdPartyDomains.length,
    categoryCounts,
    thirdPartyDomains,
    graph: { nodes, links }
  };
}
