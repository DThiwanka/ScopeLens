/**
 * Module J - Performance Intelligence
 * Calculates resource distribution, transfer sizes, slow request ranking,
 * cache utilization, and provides real data-driven performance recommendations.
 */

import { safeParseUrl, formatBytes } from '../../core/utils.js';

/**
 * Categorizes a resource by MIME type or URL extension.
 * @param {string} mimeType
 * @param {string} url
 * @returns {string}
 */
export function categorizeResourceType(mimeType = '', url = '') {
  const mime = mimeType.toLowerCase();
  const lowerUrl = url.toLowerCase();

  if (mime.includes('javascript') || lowerUrl.endsWith('.js') || lowerUrl.includes('.js?')) return 'JavaScript';
  if (mime.includes('css') || lowerUrl.endsWith('.css') || lowerUrl.includes('.css?')) return 'CSS';
  if (mime.includes('image') || /\.(png|jpg|jpeg|gif|svg|webp|avif|ico)(\?.*)?$/i.test(lowerUrl)) return 'Image';
  if (mime.includes('font') || /\.(woff2?|ttf|otf|eot)(\?.*)?$/i.test(lowerUrl)) return 'Font';
  if (mime.includes('html') || mime.includes('document')) return 'HTML / Document';
  if (mime.includes('json') || mime.includes('xml')) return 'XHR / Fetch / API';
  if (mime.includes('video') || mime.includes('audio')) return 'Media / Audio / Video';

  return 'Other';
}

/**
 * Analyzes network performance from observed requests.
 * @param {Array<Object>} requests
 * @param {string} activeOrigin
 * @returns {Object}
 */
export function analyzePerformance(requests = [], activeOrigin = '') {
  const primaryHost = activeOrigin ? safeParseUrl(activeOrigin)?.hostname || '' : '';

  let totalTransferBytes = 0;
  let cachedRequestsCount = 0;
  let failedRequestsCount = 0;
  let thirdPartyBytes = 0;

  const typeDistribution = {
    JavaScript: { count: 0, bytes: 0 },
    CSS: { count: 0, bytes: 0 },
    Image: { count: 0, bytes: 0 },
    Font: { count: 0, bytes: 0 },
    'HTML / Document': { count: 0, bytes: 0 },
    'XHR / Fetch / API': { count: 0, bytes: 0 },
    'Media / Audio / Video': { count: 0, bytes: 0 },
    Other: { count: 0, bytes: 0 }
  };

  const slowCandidates = [];
  const largestCandidates = [];

  for (const req of requests) {
    const rawUrl = req.url || req.request?.url || '';
    const urlObj = safeParseUrl(rawUrl);
    const host = urlObj ? urlObj.hostname : '';
    const isFirstParty = primaryHost ? (host === primaryHost || host.endsWith('.' + primaryHost)) : true;

    const mime = req.mimeType || req.response?.content?.mimeType || '';
    const status = req.status || req.response?.status || 0;
    const size = req.size || req.transferSize || req.response?.bodySize || 0;
    const duration = req.durationMs || req.time || 0;
    const isCached = req.fromDiskCache || req.fromMemoryCache || req.fromServiceWorker || status === 304;

    if (isCached) cachedRequestsCount++;
    if (status >= 400 || status === 0) failedRequestsCount++;

    if (size > 0) {
      totalTransferBytes += size;
      if (!isFirstParty) thirdPartyBytes += size;
    }

    const type = categorizeResourceType(mime, rawUrl);
    if (typeDistribution[type]) {
      typeDistribution[type].count++;
      if (size > 0) typeDistribution[type].bytes += size;
    }

    if (duration > 0) {
      slowCandidates.push({
        url: rawUrl,
        durationMs: Math.round(duration),
        status,
        type,
        size
      });
    }

    if (size > 0) {
      largestCandidates.push({
        url: rawUrl,
        sizeBytes: size,
        type,
        status
      });
    }
  }

  // Rank top 10 slowest requests
  const slowRequests = slowCandidates
    .sort((a, b) => b.durationMs - a.durationMs)
    .slice(0, 10);

  // Rank top 10 largest resources
  const largestResources = largestCandidates
    .sort((a, b) => b.sizeBytes - a.sizeBytes)
    .slice(0, 10);

  // Generate actionable performance recommendations
  const recommendations = [];

  const total = requests.length;
  if (total > 0) {
    const cacheRatio = (cachedRequestsCount / total) * 100;
    if (cacheRatio < 15 && total > 20) {
      recommendations.push('Low cache utilization detected. Review Cache-Control and ETag headers for static assets (images, fonts, bundles).');
    }

    if (typeDistribution.JavaScript.bytes > 1.5 * 1024 * 1024) {
      recommendations.push(`Observed JavaScript volume exceeds 1.5 MB (${formatBytes(typeDistribution.JavaScript.bytes)}). Implement code-splitting and defer non-critical scripts.`);
    }

    if (thirdPartyBytes > totalTransferBytes * 0.5 && totalTransferBytes > 500 * 1024) {
      recommendations.push(`Over 50% of transferred bytes originate from third-party hosts (${formatBytes(thirdPartyBytes)}). Evaluate external tag managers and tracking overhead.`);
    }

    if (failedRequestsCount > 0) {
      recommendations.push(`Detected ${failedRequestsCount} failed or errored HTTP request(s). Inspect the Network tab for broken links or 4xx/5xx responses.`);
    }
  }

  return {
    totalRequests: total,
    totalTransferBytes,
    totalTransferFormatted: formatBytes(totalTransferBytes),
    cachedRequestsCount,
    failedRequestsCount,
    cacheUtilizationPercent: total > 0 ? Math.round((cachedRequestsCount / total) * 100) : 0,
    thirdPartyBytes,
    thirdPartyBytesFormatted: formatBytes(thirdPartyBytes),
    typeDistribution,
    slowRequests,
    largestResources,
    recommendations
  };
}
