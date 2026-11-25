'use strict';

/**
 * Loads every module of the app without starting it: no port is opened, no
 * receiver binds, nothing is collected. The updater runs this inside a
 * downloaded release (after `npm ci`) and swaps the release in only when it
 * prints "self-check ok", so a release with a missing dependency or a
 * module that throws on load never replaces a working install.
 *
 *   node scripts/self-check.js
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
// Scripts that act when loaded (they install or remove the service, or start
// the server), and the build tooling, are not part of the running app.
const SKIP = new Set(['server.js', 'service-install.js', 'service-uninstall.js']);

const modules = [
  ...fs.readdirSync(ROOT).filter((f) => f.endsWith('.js') && !SKIP.has(f)),
  ...fs.readdirSync(path.join(ROOT, 'routes')).filter((f) => f.endsWith('.js')).map((f) => 'routes/' + f)
];
for (const m of modules) {
  try {
    require(path.join(ROOT, m));
  } catch (e) {
    console.error('self-check failed: ' + m + ': ' + e.message);
    process.exit(1);
  }
}
// The client bundle must be the one built from public/src (as npm test checks).
const { build } = require('./build-app');
const built = fs.readFileSync(path.join(ROOT, 'public', 'app.js'), 'utf8').replace(/\r\n/g, '\n');
if (built !== build()) {
  console.error('self-check failed: public/app.js does not match public/src/');
  process.exit(1);
}
console.log('self-check ok (' + modules.length + ' modules)');
process.exit(0);
