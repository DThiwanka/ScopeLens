/**
 * Tests for Phase 5: Source Map & Dependency Intelligence Analyzer
 */

import { assertEqual, assertTrue } from './test-utils.js';
import { SourceMapAnalyzer } from '../src/modules/dependencies/sourcemap-analyzer.js';

export function runSourceMapAnalyzerTests() {
  const analyzer = new SourceMapAnalyzer();

  // Test 1: Detect source map comment
  const mapComment = analyzer.detectSourceMap({
    url: 'https://example.com/assets/app.chunk.js',
    content: 'function hello(){console.log("hello");}\n//# sourceMappingURL=app.chunk.js.map'
  });

  assertTrue(mapComment !== null, 'Detected source map comment');
  assertEqual(mapComment.sourceMapUrl, 'https://example.com/assets/app.chunk.js.map', 'Resolved relative map URL');
  assertTrue(mapComment.exposedInProduction, 'Flagged as exposed in production');

  // Test 2: Extract npm dependencies from source map sources list
  const mockSources = [
    'webpack:///src/index.tsx',
    'webpack:///node_modules/react/index.js',
    'webpack:///node_modules/react-dom/client.js',
    'webpack:///node_modules/@tanstack/react-query/build/lib/index.mjs',
    'webpack:///node_modules/lodash/debounce.js',
    'webpack:///node_modules/lodash/throttle.js'
  ];

  const deps = analyzer.extractDependenciesFromSources(mockSources);
  assertEqual(deps.length, 4, 'Extracted 4 unique packages: react, react-dom, @tanstack/react-query, lodash');
  
  const lodash = deps.find(d => d.name === 'lodash');
  assertTrue(lodash !== undefined, 'Found lodash');
  assertEqual(lodash.fileCount, 2, 'Lodash has 2 files merged');

  const tanstack = deps.find(d => d.name === '@tanstack/react-query');
  assertTrue(tanstack !== undefined, 'Found scoped package @tanstack/react-query');

  // Test 3: CycloneDX Export
  const cdx = analyzer.exportCycloneDxJson('https://example.com');
  assertEqual(cdx.bomFormat, 'CycloneDX', 'BOM format is CycloneDX');
  assertEqual(cdx.components.length, 4, 'CycloneDX components match package count');

  // Test 4: SPDX Export
  const spdx = analyzer.exportSpdxJson('https://example.com');
  assertEqual(spdx.spdxVersion, 'SPDX-2.3', 'SPDX version 2.3');
  assertEqual(spdx.packages.length, 4, 'SPDX packages match');
}
