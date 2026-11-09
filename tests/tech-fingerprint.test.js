/**
 * Tests for Module F: Website Technology Fingerprinting
 */

import { assertEqual, assertTrue } from './test-utils.js';
import { fingerprintTechnologies, TECH_CATEGORIES } from '../src/modules/tech/tech-fingerprint.js';
import { CONFIDENCE } from '../src/core/constants.js';

export function runTechFingerprintTests() {
  const mockContext = {
    globals: {
      React: true,
      Next: true,
      __NEXT_DATA__: { buildId: 'abc1234567' },
      jQuery: true,
      jQueryVersion: '3.7.1',
      gtag: true,
      Sentry: true
    },
    scripts: ['https://example.com/_next/static/chunks/main.js', 'https://challenges.cloudflare.com/turnstile/v0/api.js'],
    links: ['https://cdn.example.com/tailwind.min.css'],
    metaGenerator: 'WordPress 6.4.2',
    headers: {
      'server': 'cloudflare',
      'cf-ray': '840129abc123-IAD',
      'x-powered-by': 'Express'
    },
    domSelectors: {
      '#__next': true,
      '[data-reactroot]': true,
      hasTailwindClasses: true
    }
  };

  const techs = fingerprintTechnologies(mockContext);

  assertTrue(techs.some(t => t.name === 'React'), 'Detects React');
  assertTrue(techs.some(t => t.name === 'Next.js'), 'Detects Next.js');
  assertTrue(techs.some(t => t.name === 'jQuery' && t.version === '3.7.1'), 'Detects jQuery with exact version');
  assertTrue(techs.some(t => t.name === 'WordPress' && t.version === '6.4.2'), 'Detects WordPress with version');
  assertTrue(techs.some(t => t.name === 'Cloudflare'), 'Detects Cloudflare CDN from CF-Ray header');
  assertTrue(techs.some(t => t.name === 'Express.js'), 'Detects Express from X-Powered-By header');
  assertTrue(techs.some(t => t.name === 'Google Analytics'), 'Detects Google Analytics');
  assertTrue(techs.some(t => t.name === 'Cloudflare Turnstile'), 'Detects Cloudflare Turnstile');
  assertTrue(techs.some(t => t.name === 'Tailwind CSS'), 'Detects Tailwind CSS');
}
