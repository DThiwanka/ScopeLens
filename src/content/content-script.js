/**
 * ScopeLens Platform - In-Page Content Script Collector
 * Safely inspects DOM cues, window globals, storage items, and security boundaries.
 * Executes purely within the active origin's execution environment.
 */

export function runInPageCollection() {
  const origin = location.origin;
  const isHttps = location.protocol === 'https:';

  // --- 1. DOM Security & Hygiene Cues ---
  const reverseTabnabbingLinks = [];
  document.querySelectorAll('a[target="_blank"]').forEach(a => {
    const rel = (a.getAttribute('rel') || '').toLowerCase();
    const href = a.getAttribute('href') || '';
    if (!rel.includes('noopener') && !rel.includes('noreferrer')) {
      if (href.startsWith('http://') || href.startsWith('https://')) {
        reverseTabnabbingLinks.push(href);
      }
    }
  });

  const externalScriptsWithoutSri = [];
  const mixedContentResources = [];
  document.querySelectorAll('script[src]').forEach(s => {
    const src = s.getAttribute('src') || '';
    try {
      const u = new URL(src, location.href);
      if (u.origin !== origin) {
        if (!s.hasAttribute('integrity')) {
          externalScriptsWithoutSri.push(u.href);
        }
      }
      if (isHttps && u.protocol === 'http:') {
        mixedContentResources.push(u.href);
      }
    } catch {}
  });

  document.querySelectorAll('link[href]').forEach(l => {
    const href = l.getAttribute('href') || '';
    try {
      const u = new URL(href, location.href);
      if (isHttps && u.protocol === 'http:') {
        mixedContentResources.push(u.href);
      }
    } catch {}
  });

  document.querySelectorAll('img[src]').forEach(img => {
    const src = img.getAttribute('src') || '';
    try {
      const u = new URL(src, location.href);
      if (isHttps && u.protocol === 'http:') {
        mixedContentResources.push(u.href);
      }
    } catch {}
  });

  const insecureForms = [];
  const formsMissingCsrf = [];
  const sensitiveHiddenInputs = [];
  const secretKeyPattern = /token|auth|key|secret|password|credential|private|signature/i;
  const csrfKeyPattern = /csrf|xsrf|_token|authenticity_token|RequestVerificationToken/i;

  document.querySelectorAll('form').forEach(f => {
    const action = f.getAttribute('action') || '';
    const method = (f.getAttribute('method') || 'GET').toUpperCase();

    try {
      const u = new URL(action, location.href);
      if (isHttps && u.protocol === 'http:') {
        insecureForms.push(u.href);
      }
    } catch {}

    // Check CSRF token presence on POST forms
    if (method === 'POST') {
      const inputs = Array.from(f.querySelectorAll('input'));
      const hasCsrfToken = inputs.some(i => csrfKeyPattern.test(i.name) || csrfKeyPattern.test(i.id));
      if (!hasCsrfToken) {
        formsMissingCsrf.push(action || location.pathname);
      }
    }

    // Check hidden inputs for static secrets
    f.querySelectorAll('input[type="hidden"]').forEach(h => {
      const name = h.name || h.id || '';
      if (secretKeyPattern.test(name) && !csrfKeyPattern.test(name)) {
        sensitiveHiddenInputs.push(name);
      }
    });
  });

  const javascriptPseudoLinks = [];
  document.querySelectorAll('a[href^="javascript:"]').forEach(a => {
    javascriptPseudoLinks.push(a.getAttribute('href') || '');
  });

  // Count inline event handlers (onclick, onload, onerror, etc.)
  let inlineEventHandlersCount = 0;
  const commonEvents = ['onclick', 'onload', 'onerror', 'onmouseover', 'onchange', 'onsubmit', 'onkeydown'];
  commonEvents.forEach(evt => {
    inlineEventHandlersCount += document.querySelectorAll(`[${evt}]`).length;
  });

  // Insecure or external <base> tags
  const insecureBaseTags = [];
  document.querySelectorAll('base[href]').forEach(b => {
    const href = b.getAttribute('href') || '';
    try {
      const u = new URL(href, location.href);
      if (u.origin !== origin || (isHttps && u.protocol === 'http:')) {
        insecureBaseTags.push(href);
      }
    } catch {}
  });

  // --- 2. Tech Fingerprint Signals ---
  const scripts = Array.from(document.querySelectorAll('script[src]')).map(s => s.src);
  const links = Array.from(document.querySelectorAll('link[href]')).map(l => l.href);
  const metaGen = document.querySelector('meta[name="generator"]')?.content || '';

  const globals = {
    React: Boolean(window.React),
    __REACT_DEVTOOLS_GLOBAL_HOOK__: Boolean(window.__REACT_DEVTOOLS_GLOBAL_HOOK__),
    Next: Boolean(window.next),
    __NEXT_DATA__: window.__NEXT_DATA__ || null,
    Vue: Boolean(window.Vue),
    VueVersion: window.Vue?.version || null,
    __VUE__: Boolean(window.__VUE__),
    Angular: Boolean(window.angular || document.querySelector('[ng-version]')),
    AngularVersion: document.querySelector('[ng-version]')?.getAttribute('ng-version') || window.angular?.version?.full || null,
    __NUXT__: Boolean(window.__NUXT__),
    __remixContext: Boolean(window.__remixContext),
    jQuery: Boolean(window.jQuery),
    jQueryVersion: window.jQuery?.fn?.jquery || window.$?.fn?.jquery || null,
    Alpine: Boolean(window.Alpine),
    AlpineVersion: window.Alpine?.version || null,
    htmx: Boolean(window.htmx),
    htmxVersion: window.htmx?.version || null,
    Lodash: Boolean(window._ && window._.VERSION),
    LodashVersion: window._?.VERSION || null,
    bootstrap: Boolean(window.bootstrap),
    Shopify: Boolean(window.Shopify),
    Webflow: Boolean(window.Webflow),
    Drupal: Boolean(window.Drupal),
    gtag: Boolean(window.gtag),
    ga: Boolean(window.ga || window.GoogleAnalyticsObject),
    google_tag_manager: Boolean(window.google_tag_manager),
    dataLayer: Boolean(Array.isArray(window.dataLayer)),
    Sentry: Boolean(window.Sentry),
    __SENTRY__: Boolean(window.__SENTRY__),
    hj: Boolean(window.hj),
    analytics: Boolean(window.analytics),
    Stripe: Boolean(window.Stripe),
    paypal: Boolean(window.paypal),
    firebase: Boolean(window.firebase),
    auth0: Boolean(window.auth0)
  };

  const domSelectors = {
    '[data-reactroot]': Boolean(document.querySelector('[data-reactroot], #react-root')),
    '#__next': Boolean(document.getElementById('__next')),
    '[data-v-]': Boolean(document.querySelector('[data-v-]')),
    '#__nuxt': Boolean(document.getElementById('__nuxt')),
    '[ng-version]': Boolean(document.querySelector('[ng-version]')),
    '[class*="svelte-"]': Boolean(document.querySelector('[class*="svelte-"]')),
    'astro-island': Boolean(document.querySelector('astro-island')),
    hasTailwindClasses: Boolean(document.querySelector('[class*="flex"], [class*="grid"], [class*="text-"], [class*="bg-"]'))
  };

  // --- 3. Web Storage Inventory ---
  const collectStorage = (storage, name) => {
    const items = [];
    try {
      for (let i = 0; i < storage.length && items.length < 500; i++) {
        const key = storage.key(i);
        const val = storage.getItem(key) || '';
        items.push({ key, value: val, source: name });
      }
    } catch (err) {
      return { items: [], error: err.message };
    }
    return { items, error: null };
  };

  const localStorageData = collectStorage(window.localStorage, 'localStorage');
  const sessionStorageData = collectStorage(window.sessionStorage, 'sessionStorage');

  // Readable cookies in document.cookie
  const cookieNames = document.cookie
    ? document.cookie.split(';').map(c => c.trim().split('=')[0]).filter(Boolean)
    : [];

  // --- 4. CacheStorage, IndexedDB, Service Worker Jobs ---
  const cacheJob = (async () => {
    const results = [];
    if (!('caches' in window)) return results;
    try {
      for (const name of await caches.keys()) {
        const cache = await caches.open(name);
        const keys = await cache.keys();
        const entries = [];
        for (const req of keys.slice(0, 100)) {
          if (new URL(req.url, location.href).origin !== origin) continue;
          const res = await cache.match(req);
          entries.push({
            url: req.url,
            status: res?.status || null,
            contentType: res?.headers.get('content-type') || ''
          });
        }
        results.push({ name, entries });
      }
    } catch (err) {
      results.push({ name: 'Error', error: err.message, entries: [] });
    }
    return results;
  })();

  const idbJob = (async () => {
    const dbs = [];
    if (!indexedDB.databases) return { supported: false, databases: dbs };
    try {
      const list = await indexedDB.databases();
      for (const info of list.slice(0, 50)) {
        if (!info.name) continue;
        const db = await new Promise(resolve => {
          const req = indexedDB.open(info.name);
          req.onsuccess = () => resolve(req.result);
          req.onerror = () => resolve(null);
          req.onblocked = () => resolve(null);
        });
        dbs.push({
          name: info.name,
          version: info.version || null,
          stores: db ? Array.from(db.objectStoreNames) : []
        });
        db?.close();
      }
      return { supported: true, databases: dbs };
    } catch (err) {
      return { supported: true, databases: dbs, error: err.message };
    }
  })();

  const swJob = (async () => {
    if (!navigator.serviceWorker) return [];
    try {
      const regs = await navigator.serviceWorker.getRegistrations();
      return regs.map(r => ({
        scope: r.scope,
        active: Boolean(r.active),
        waiting: Boolean(r.waiting),
        installing: Boolean(r.installing)
      }));
    } catch {
      return [];
    }
  })();

  const quotaJob = (async () => {
    if (navigator.storage && navigator.storage.estimate) {
      try {
        const est = await navigator.storage.estimate();
        const persisted = navigator.storage.persisted ? await navigator.storage.persisted() : false;
        return { usage: est.usage, quota: est.quota, persisted };
      } catch {
        return null;
      }
    }
    return null;
  })();

  const headersJob = (async () => {
    try {
      const resp = await fetch(location.href, { method: 'HEAD', cache: 'no-store' });
      const hdrs = {};
      resp.headers.forEach((v, k) => { hdrs[k.toLowerCase()] = v; });
      return hdrs;
    } catch {
      return {};
    }
  })();

  return Promise.all([cacheJob, idbJob, swJob, quotaJob, headersJob]).then(([cacheStorage, indexedDb, serviceWorkers, storageQuota, headers]) => ({
    origin,
    hostname: location.hostname,
    protocol: location.protocol,
    title: document.title,
    isSecureContext: window.isSecureContext,
    headers,
    domSecurity: {
      reverseTabnabbingLinks,
      externalScriptsWithoutSri,
      mixedContentResources,
      insecureForms,
      javascriptPseudoLinks,
      inlineEventHandlersCount,
      formsMissingCsrf,
      sensitiveHiddenInputs,
      insecureBaseTags
    },
    techContext: {
      globals,
      scripts,
      links,
      metaGenerator: metaGen,
      headers,
      domSelectors
    },
    storage: {
      localStorage: localStorageData,
      sessionStorage: sessionStorageData,
      cookieNames,
      cacheStorage,
      indexedDb,
      serviceWorkers,
      storageQuota
    }
  }));
}
