/**
 * ScopeLens Platform - Source Map & Dependency Intelligence Analyzer
 * Detects source map declarations, extracts third-party package dependencies from source paths,
 * identifies exposed production source maps, and generates CycloneDX / SPDX SBOMs.
 */

import { safeParseUrl } from '../../core/utils.js';

export class SourceMapAnalyzer {
  constructor() {
    this.dependencies = new Map(); // name -> { version, files: Set }
    this.sourceMaps = [];
  }

  /**
   * Scans script metadata and headers for source map references.
   * @param {Object} scriptInfo
   * @param {string} scriptInfo.url
   * @param {string} [scriptInfo.content]
   * @param {Object} [scriptInfo.headers]
   * @returns {Object|null}
   */
  detectSourceMap(scriptInfo) {
    if (!scriptInfo || !scriptInfo.url) return null;

    let sourceMapUrl = null;

    // 1. Check HTTP headers (SourceMap or X-SourceMap)
    if (scriptInfo.headers) {
      for (const [k, v] of Object.entries(scriptInfo.headers)) {
        if (/^(sourcemap|x-sourcemap)$/i.test(k) && v) {
          sourceMapUrl = v;
          break;
        }
      }
    }

    // 2. Check script content comment if provided
    if (!sourceMapUrl && scriptInfo.content) {
      const match = scriptInfo.content.match(/\/\/[#@]\s*sourceMappingURL=([^\s'"]+)/) ||
                    scriptInfo.content.match(/\/\*[#@]\s*sourceMappingURL=([^\s*'"]+)\s*\*\//);
      if (match && match[1]) {
        sourceMapUrl = match[1];
      }
    }

    // 3. Check conventional .js -> .js.map URL
    if (!sourceMapUrl && scriptInfo.url.endsWith('.js')) {
      sourceMapUrl = scriptInfo.url + '.map';
    }

    if (!sourceMapUrl) return null;

    // Resolve relative source map URLs
    let resolvedUrl = sourceMapUrl;
    try {
      resolvedUrl = new URL(sourceMapUrl, scriptInfo.url).toString();
    } catch {}

    const record = {
      scriptUrl: scriptInfo.url,
      sourceMapUrl: resolvedUrl,
      isInline: resolvedUrl.startsWith('data:'),
      exposedInProduction: !resolvedUrl.startsWith('data:') && !/localhost|127\.0\.0\.1/.test(scriptInfo.url)
    };

    this.sourceMaps.push(record);
    return record;
  }

  /**
   * Parses source paths from a source map to extract third-party npm package dependencies.
   * @param {Array<string>} sources
   * @returns {Array<Object>} List of discovered dependencies
   */
  extractDependenciesFromSources(sources = []) {
    const discovered = [];

    for (const rawSource of sources) {
      // Normalize path separators
      const path = rawSource.replace(/\\/g, '/');

      // Match node_modules dependencies: node_modules/(@scoped/package|package)
      const nmMatch = path.match(/node_modules\/((?:@[^/]+\/)?[^/]+)/);
      if (nmMatch && nmMatch[1]) {
        const pkgName = nmMatch[1];
        if (!this.dependencies.has(pkgName)) {
          this.dependencies.set(pkgName, {
            name: pkgName,
            version: 'unknown',
            files: new Set()
          });
        }
        this.dependencies.get(pkgName).files.add(path);
      }
    }

    for (const [name, entry] of this.dependencies.entries()) {
      discovered.push({
        name,
        version: entry.version,
        fileCount: entry.files.size
      });
    }

    return discovered;
  }

  /**
   * Generates a CycloneDX v1.4 compliant Software Bill of Materials (SBOM) in JSON.
   * @param {string} [targetOrigin='']
   * @returns {Object}
   */
  exportCycloneDxJson(targetOrigin = '') {
    const components = [];

    for (const [name, info] of this.dependencies.entries()) {
      components.push({
        type: 'library',
        name,
        version: info.version === 'unknown' ? '0.0.0' : info.version,
        purl: `pkg:npm/${name}${info.version !== 'unknown' ? '@' + info.version : ''}`,
        properties: [
          { name: 'scopelens:fileCount', value: String(info.files.size) }
        ]
      });
    }

    return {
      bomFormat: 'CycloneDX',
      specVersion: '1.4',
      serialNumber: `urn:uuid:${Math.random().toString(36).substring(2, 15)}`,
      version: 1,
      metadata: {
        timestamp: new Date().toISOString(),
        tools: [
          { vendor: 'ScopeLens', name: 'ScopeLens Dependency Engine', version: '2.0.0' }
        ],
        component: {
          type: 'application',
          name: targetOrigin || 'Inspected Web Application'
        }
      },
      components
    };
  }

  /**
   * Generates an SPDX 2.3 compliant SBOM in JSON.
   * @param {string} [targetOrigin='']
   * @returns {Object}
   */
  exportSpdxJson(targetOrigin = '') {
    const packages = [];

    for (const [name, info] of this.dependencies.entries()) {
      packages.push({
        name,
        SPDXID: `SPDXRef-Package-${name.replace(/[^a-zA-Z0-9.-]/g, '-')}`,
        versionInfo: info.version,
        downloadLocation: 'NOASSERTION',
        filesAnalyzed: false
      });
    }

    return {
      spdxVersion: 'SPDX-2.3',
      dataLicense: 'CC0-1.0',
      SPDXID: 'SPDXRef-DOCUMENT',
      name: `ScopeLens SBOM - ${targetOrigin || 'Web App'}`,
      documentNamespace: `https://scopelens.local/spdx/${Date.now()}`,
      creationInfo: {
        created: new Date().toISOString(),
        creators: ['Tool: ScopeLens-2.0.0']
      },
      packages
    };
  }
}
