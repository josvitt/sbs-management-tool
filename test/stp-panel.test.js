'use strict';
// The Spanning tree panel is keyed (reconciled in place) and repaints only
// when the shape of its layout changes. Checked against the source; the
// headless paint is exercised separately.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const SRC = path.join(__dirname, '..', 'public', 'src');
const read = (f) => fs.readFileSync(path.join(SRC, f), 'utf8');

test('the Spanning tree panel is keyed and builds every table with mountInto', () => {
  assert.match(read('06-panels.js'), /KEYED_PANELS = new Set\(\[[^\]]*'stp'/);
  const body = read('11-panel-bodies.js');
  const stp = body.slice(body.indexOf("case 'stp': {"), body.indexOf("default:\n        body.appendChild(el('div', 'card-sub', 'Unknown panel: '"));
  assert.doesNotMatch(stp, /el\('table'/);
  assert.match(stp, /mountInto\(wrap, s, p, 'stp:' \+ k/);
  assert.match(stp, /if \(s\._ktReconcile && p\._stpSig !== sig\) \{ s\._ktStructural = true; return; \}/);
});
