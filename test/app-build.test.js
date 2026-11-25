'use strict';

// public/app.js is built from public/src/ (scripts/build-app.js). A hand edit
// to app.js, or a src change without a rebuild, fails here.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { build } = require('../scripts/build-app');

test('public/app.js matches what public/src/ builds', () => {
  const current = fs.readFileSync(path.join(__dirname, '..', 'public', 'app.js'), 'utf8');
  assert.ok(current === build(), 'public/app.js is out of date: run npm run build');
});
