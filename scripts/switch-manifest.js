import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '..');

const variant = process.argv[2] || 'standard';
const srcFile = path.join(rootDir, 'manifest', `${variant}.json`);
const destFile = path.join(rootDir, 'manifest.json');

if (!fs.existsSync(srcFile)) {
  console.error(`Error: Manifest variant "${variant}" not found at ${srcFile}`);
  console.error(`Available variants: standard, deep-capture`);
  process.exit(1);
}

fs.copyFileSync(srcFile, destFile);
console.log(`✓ Switched manifest.json to [${variant}] edition.`);
