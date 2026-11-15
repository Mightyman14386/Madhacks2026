const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const source = path.join(root, 'node_modules/compromise');
fs.mkdirSync(path.join(root, 'vendor'), { recursive: true });
fs.copyFileSync(path.join(source, 'builds/compromise.js'), path.join(root, 'vendor/compromise.js'));
fs.copyFileSync(path.join(source, 'LICENSE'), path.join(root, 'vendor/compromise.LICENSE'));
