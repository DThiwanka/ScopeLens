/**
 * Module F - Website Technology Fingerprinting Engine
 * Analyzes DOM cues, window globals, HTTP response headers, meta generators,
 * and script paths with explicit evidence and confidence ratings.
 */

import { CONFIDENCE } from '../../core/constants.js';

export const TECH_CATEGORIES = {
  FRONTEND_FRAMEWORK: 'Frontend Framework',
  WEB_FRAMEWORK: 'Web Framework',
  JS_LIBRARY: 'JavaScript Library',
  CSS_FRAMEWORK: 'CSS Framework',
  CMS: 'Content Management System',
  ECOMMERCE: 'E-commerce Platform',
  SERVER: 'Web Server / Runtime',
  CDN: 'CDN & Edge Infrastructure',
  ANALYTICS: 'Analytics & Tracking',
  TAG_MANAGER: 'Tag Manager',
  MONITORING: 'Error Tracking & Monitoring',
  SECURITY: 'Security & Bot Protection',
  AUTH: 'Authentication Provider',
  PAYMENT: 'Payment Gateway',
  WEB_API: 'Browser Web API'
};

/**
 * Fingerprints technologies from DOM signals, globals, scripts, and HTTP headers.
 * @param {Object} context
 * @param {Object} context.globals - Object indicating detected global window keys
 * @param {Array<string>} context.scripts - Array of script src URLs
 * @param {Array<string>} context.links - Array of link href URLs
 * @param {string} context.metaGenerator - Content of meta[name="generator"]
 * @param {Record<string, string>} context.headers - Response headers
 * @param {Object} context.domSelectors - Map of boolean querySelector matches
 * @returns {Array<Object>}
 */
export function fingerprintTechnologies(context = {}) {
  const findings = [];
  const addTech = (name, category, version, confidence, evidence, source) => {
    if (!findings.some(f => f.name === name)) {
      findings.push({
        name,
        category,
        version: version || null,
        confidence,
        evidence,
        source
      });
    }
  };

  const {
    globals = {},
    scripts = [],
    links = [],
    metaGenerator = '',
    headers = {},
    domSelectors = {}
  } = context;

  const scriptString = scripts.join(' ').toLowerCase();
  const linkString = links.join(' ').toLowerCase();
  const lowerHeaders = {};
  for (const [k, v] of Object.entries(headers || {})) {
    lowerHeaders[k.toLowerCase()] = String(v || '').toLowerCase();
  }

  // --- 1. Frontend & Web Frameworks ---
  if (globals.React || domSelectors['[data-reactroot]'] || globals.__REACT_DEVTOOLS_GLOBAL_HOOK__) {
    addTech('React', TECH_CATEGORIES.FRONTEND_FRAMEWORK, null, CONFIDENCE.HIGH, 'React DOM mount points or DevTools global hook present', 'DOM / Window');
  }

  if (globals.Next || globals.__NEXT_DATA__ || domSelectors['#__next']) {
    const buildId = globals.__NEXT_DATA__?.buildId ? `build: ${globals.__NEXT_DATA__.buildId.slice(0, 8)}` : null;
    addTech('Next.js', TECH_CATEGORIES.WEB_FRAMEWORK, buildId, CONFIDENCE.CONFIRMED, '__NEXT_DATA__ JSON container present', 'Window Globals');
  }

  if (globals.Vue || domSelectors['[data-v-]'] || globals.__VUE__) {
    const ver = globals.VueVersion || (globals.__VUE__ ? '3.x' : null);
    addTech('Vue.js', TECH_CATEGORIES.FRONTEND_FRAMEWORK, ver, CONFIDENCE.HIGH, '__VUE__ runtime flag or data-v scoped styling detected', 'DOM / Window');
  }

  if (globals.Nuxt || globals.__NUXT__ || domSelectors['#__nuxt']) {
    addTech('Nuxt.js', TECH_CATEGORIES.WEB_FRAMEWORK, null, CONFIDENCE.CONFIRMED, '__NUXT__ state hydration container found', 'DOM / Window');
  }

  if (globals.Angular || domSelectors['[ng-version]']) {
    const ver = globals.AngularVersion || null;
    addTech('Angular', TECH_CATEGORIES.FRONTEND_FRAMEWORK, ver, CONFIDENCE.CONFIRMED, 'ng-version attribute detected in root component', 'DOM / Window');
  }

  if (domSelectors['[class*="svelte-"]'] || globals.__svelte) {
    addTech('Svelte', TECH_CATEGORIES.FRONTEND_FRAMEWORK, null, CONFIDENCE.HIGH, 'Svelte class naming pattern observed in rendered elements', 'DOM');
  }

  if (globals.__remixContext) {
    addTech('Remix', TECH_CATEGORIES.WEB_FRAMEWORK, null, CONFIDENCE.CONFIRMED, '__remixContext window state detected', 'Window Globals');
  }

  if (domSelectors['astro-island']) {
    addTech('Astro', TECH_CATEGORIES.WEB_FRAMEWORK, null, CONFIDENCE.CONFIRMED, 'astro-island hydration custom element detected', 'DOM');
  }

  if (globals.jQuery || globals.$?.fn?.jquery) {
    const ver = globals.jQueryVersion || null;
    addTech('jQuery', TECH_CATEGORIES.JS_LIBRARY, ver, CONFIDENCE.CONFIRMED, 'window.jQuery object defined', 'Window Globals');
  }

  if (globals.Alpine) {
    addTech('Alpine.js', TECH_CATEGORIES.FRONTEND_FRAMEWORK, globals.AlpineVersion, CONFIDENCE.CONFIRMED, 'window.Alpine instance initialized', 'Window Globals');
  }

  if (globals.htmx) {
    addTech('htmx', TECH_CATEGORIES.JS_LIBRARY, globals.htmxVersion, CONFIDENCE.CONFIRMED, 'window.htmx library detected', 'Window Globals');
  }

  if (globals.Lodash) {
    addTech('Lodash', TECH_CATEGORIES.JS_LIBRARY, globals.LodashVersion, CONFIDENCE.CONFIRMED, 'window._.VERSION defined', 'Window Globals');
  }

  // --- 2. CSS Frameworks ---
  if (linkString.includes('tailwind') || domSelectors.hasTailwindClasses) {
    addTech('Tailwind CSS', TECH_CATEGORIES.CSS_FRAMEWORK, null, CONFIDENCE.HIGH, 'Tailwind stylesheet or utility class structures detected', 'DOM / CSS');
  }

  if (linkString.includes('bootstrap') || globals.bootstrap) {
    addTech('Bootstrap', TECH_CATEGORIES.CSS_FRAMEWORK, null, CONFIDENCE.HIGH, 'Bootstrap stylesheet or window.bootstrap global defined', 'DOM / CSS');
  }

  // --- 3. Content Management Systems & E-Commerce ---
  if (metaGenerator.includes('WordPress') || scriptString.includes('wp-content') || scriptString.includes('wp-includes')) {
    const match = metaGenerator.match(/WordPress\s*([\d.]+)/i);
    addTech('WordPress', TECH_CATEGORIES.CMS, match ? match[1] : null, CONFIDENCE.CONFIRMED, 'WordPress generator meta tag or wp-content script paths', 'Meta / Script');
  }

  if (globals.Shopify || scriptString.includes('cdn.shopify.com')) {
    addTech('Shopify', TECH_CATEGORIES.ECOMMERCE, null, CONFIDENCE.CONFIRMED, 'window.Shopify instance or cdn.shopify.com assets loaded', 'Window Globals / Assets');
  }

  if (globals.Webflow || metaGenerator.includes('Webflow')) {
    addTech('Webflow', TECH_CATEGORIES.CMS, null, CONFIDENCE.CONFIRMED, 'Webflow meta generator or window.Webflow instance', 'Meta / Window');
  }

  if (metaGenerator.includes('Ghost')) {
    addTech('Ghost', TECH_CATEGORIES.CMS, null, CONFIDENCE.CONFIRMED, 'Ghost meta generator tag observed', 'Meta Tag');
  }

  if (globals.Drupal || scriptString.includes('/sites/default/files/')) {
    addTech('Drupal', TECH_CATEGORIES.CMS, null, CONFIDENCE.HIGH, 'window.Drupal global or standard Drupal file paths', 'Window / Assets');
  }

  // --- 4. Web Servers & Edge CDNs ---
  const serverHeader = lowerHeaders['server'] || '';
  const xPoweredBy = lowerHeaders['x-powered-by'] || '';

  if (serverHeader.includes('cloudflare') || lowerHeaders['cf-ray']) {
    addTech('Cloudflare', TECH_CATEGORIES.CDN, null, CONFIDENCE.CONFIRMED, 'CF-Ray or Server: cloudflare response headers', 'HTTP Header');
  }

  if (lowerHeaders['x-amz-cf-id'] || serverHeader.includes('cloudfront')) {
    addTech('Amazon CloudFront', TECH_CATEGORIES.CDN, null, CONFIDENCE.CONFIRMED, 'X-Amz-Cf-Id response header', 'HTTP Header');
  }

  if (lowerHeaders['x-vercel-id']) {
    addTech('Vercel', TECH_CATEGORIES.CDN, null, CONFIDENCE.CONFIRMED, 'X-Vercel-Id response header', 'HTTP Header');
  }

  if (lowerHeaders['x-nf-request-id']) {
    addTech('Netlify', TECH_CATEGORIES.CDN, null, CONFIDENCE.CONFIRMED, 'X-Nf-Request-Id response header', 'HTTP Header');
  }

  if (serverHeader.includes('nginx')) {
    const match = serverHeader.match(/nginx\/([\d.]+)/i);
    addTech('Nginx', TECH_CATEGORIES.SERVER, match ? match[1] : null, CONFIDENCE.HIGH, `Server header: ${serverHeader}`, 'HTTP Header');
  }

  if (serverHeader.includes('apache')) {
    const match = serverHeader.match(/apache\/([\d.]+)/i);
    addTech('Apache HTTP Server', TECH_CATEGORIES.SERVER, match ? match[1] : null, CONFIDENCE.HIGH, `Server header: ${serverHeader}`, 'HTTP Header');
  }

  if (xPoweredBy.includes('express')) {
    addTech('Express.js', TECH_CATEGORIES.SERVER, null, CONFIDENCE.CONFIRMED, `X-Powered-By: ${xPoweredBy}`, 'HTTP Header');
  }

  if (xPoweredBy.includes('php') || serverHeader.includes('php')) {
    const match = xPoweredBy.match(/php\/([\d.]+)/i);
    addTech('PHP', TECH_CATEGORIES.SERVER, match ? match[1] : null, CONFIDENCE.HIGH, `X-Powered-By header: ${xPoweredBy}`, 'HTTP Header');
  }

  if (xPoweredBy.includes('asp.net')) {
    addTech('ASP.NET', TECH_CATEGORIES.SERVER, null, CONFIDENCE.CONFIRMED, `X-Powered-By: ${xPoweredBy}`, 'HTTP Header');
  }

  // --- 5. Analytics, Monitoring & Security ---
  if (globals.gtag || globals.ga || scriptString.includes('google-analytics.com')) {
    addTech('Google Analytics', TECH_CATEGORIES.ANALYTICS, null, CONFIDENCE.CONFIRMED, 'window.gtag/ga global or google-analytics.com script', 'Window / Assets');
  }

  if (globals.google_tag_manager || globals.dataLayer) {
    addTech('Google Tag Manager', TECH_CATEGORIES.TAG_MANAGER, null, CONFIDENCE.CONFIRMED, 'window.google_tag_manager or dataLayer array initialized', 'Window Globals');
  }

  if (globals.__SENTRY__ || globals.Sentry) {
    addTech('Sentry', TECH_CATEGORIES.MONITORING, null, CONFIDENCE.CONFIRMED, 'window.Sentry client initialized', 'Window Globals');
  }

  if (scriptString.includes('challenges.cloudflare.com/turnstile') || globals.turnstile) {
    addTech('Cloudflare Turnstile', TECH_CATEGORIES.SECURITY, null, CONFIDENCE.CONFIRMED, 'Turnstile bot challenge script loaded', 'Assets / Window');
  }

  if (globals.hj || scriptString.includes('static.hotjar.com')) {
    addTech('Hotjar', TECH_CATEGORIES.ANALYTICS, null, CONFIDENCE.CONFIRMED, 'window.hj tracking snippet loaded', 'Window Globals');
  }

  if (globals.analytics && typeof globals.analytics.track === 'function') {
    addTech('Segment', TECH_CATEGORIES.ANALYTICS, null, CONFIDENCE.HIGH, 'window.analytics customer data client active', 'Window Globals');
  }

  // --- 6. Payments & Auth Providers ---
  if (globals.Stripe || scriptString.includes('js.stripe.com')) {
    addTech('Stripe', TECH_CATEGORIES.PAYMENT, null, CONFIDENCE.CONFIRMED, 'Stripe.js payment integration loaded', 'Window / Assets');
  }

  if (globals.paypal || scriptString.includes('paypal.com/sdk')) {
    addTech('PayPal SDK', TECH_CATEGORIES.PAYMENT, null, CONFIDENCE.CONFIRMED, 'PayPal payment SDK loaded', 'Window / Assets');
  }

  if (globals.firebase || scriptString.includes('firebaseapp.com')) {
    addTech('Firebase', TECH_CATEGORIES.AUTH, null, CONFIDENCE.HIGH, 'Firebase SDK or client domain observed', 'Window / Assets');
  }

  if (globals.auth0) {
    addTech('Auth0', TECH_CATEGORIES.AUTH, null, CONFIDENCE.HIGH, 'Auth0 client instance detected', 'Window Globals');
  }

  return findings;
}
