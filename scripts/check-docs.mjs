import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const siteDir = path.join(rootDir, 'docs', '.vitepress', 'dist');
const base = '/sublink-worker/';
const htmlFiles = [];

walk(siteDir);

const requiredPages = [
    'index.html',
    'protocol-support.html',
    'guide/getting-started.html',
    'guide/deployment.html',
    'guide/configuration.html',
    'guide/api.html',
    'guide/faq.html',
    'en/index.html',
    'en/protocol-support.html',
    'en/guide/getting-started.html',
    'en/guide/deployment.html',
    'en/guide/configuration.html',
    'en/guide/api.html',
    'en/guide/faq.html'
];

for (const page of requiredPages) {
    assert.ok(fs.existsSync(path.join(siteDir, page)), `Missing rendered page: ${page}`);
}
assert.ok(!fs.existsSync(path.join(siteDir, 'research')), 'Internal research notes must not be published');

const brokenLinks = [];
for (const file of htmlFiles) {
    const html = fs.readFileSync(file, 'utf8');
    for (const match of html.matchAll(/href="([^"]+)"/g)) {
        const href = match[1];
        if (!href.startsWith(base)) continue;
        const pathname = href.split(/[?#]/)[0].slice(base.length);
        if (!pathname || /\.[a-z0-9]+$/i.test(pathname)) continue;
        const candidates = [
            path.join(siteDir, `${pathname}.html`),
            path.join(siteDir, pathname, 'index.html')
        ];
        if (!candidates.some(candidate => fs.existsSync(candidate))) {
            brokenLinks.push(`${path.relative(siteDir, file)} -> ${href}`);
        }
    }
}

assert.deepEqual(brokenLinks, [], `Broken internal routes:\n${brokenLinks.join('\n')}`);
console.log(`Verified ${requiredPages.length} required pages and ${htmlFiles.length} rendered HTML files.`);

function walk(directory) {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
        const fullPath = path.join(directory, entry.name);
        if (entry.isDirectory()) walk(fullPath);
        else if (entry.name.endsWith('.html')) htmlFiles.push(fullPath);
    }
}
