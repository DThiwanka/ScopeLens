/**
 * ScopeLens Platform - Release Packaging Script
 * Bundles production extension files into scopelens-platform-v2.0.0.zip
 */

import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';

const filesToInclude = [
  'manifest.json',
  'background.js',
  'popup.html',
  'popup.js',
  'styles.css',
  'dashboard.html',
  'dashboard.js',
  'dashboard.css',
  'sidepanel.html',
  'sidepanel.js',
  'sidepanel.css',
  'devtools.html',
  'devtools.js',
  'panel.html',
  'panel.js',
  'package.json',
  'README.md',
  'AGENT.md',
  'icons',
  'src',
  'manifest'
];

const destZip = 'scopelens-platform-v2.0.0.zip';

// Remove old zip if present
if (fs.existsSync(destZip)) {
  fs.unlinkSync(destZip);
}

// PowerShell Compress-Archive command
const items = filesToInclude.filter(f => fs.existsSync(f)).join(', ');
const psCmd = `powershell -NoProfile -Command "$ProgressPreference = 'SilentlyContinue'; Compress-Archive -Path ${items} -DestinationPath '${destZip}' -Force"`;

console.log(`Packaging ScopeLens Platform into ${destZip}...`);
execSync(psCmd, { stdio: 'inherit' });

const stats = fs.statSync(destZip);
console.log(`✓ Release archive generated: ${destZip} (${Math.round(stats.size / 1024)} KB)`);
