'use strict';
// known-hosts.js: trust on first use, refuse a changed key, replace only on
// the explicit trust step. Uses a temp file, never the install's own.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'sbs-kh-')), 'known-hosts.json');
process.env.SBS_KNOWN_HOSTS_FILE = file;
const kh = require('../known-hosts');

const keyA = Buffer.from('host key A');
const keyB = Buffer.from('host key B');

test('fingerprint is OpenSSH SHA256 form', () => {
  // sha256("host key A"), base64 without padding, computed independently.
  assert.equal(kh.fingerprint(keyA), 'SHA256:' + require('crypto').createHash('sha256').update('host key A').digest('base64').replace(/=+$/, ''));
  assert.match(kh.fingerprint(keyA), /^SHA256:[A-Za-z0-9+/]{43}$/);
});

test('first sight is remembered, the same key matches, a different key is refused', () => {
  assert.equal(kh.check('10.0.0.1', 22, keyA).result, 'new');
  assert.ok(JSON.parse(fs.readFileSync(file, 'utf8'))['10.0.0.1:22']);
  assert.equal(kh.check('10.0.0.1', 22, keyA).result, 'match');
  const changed = kh.check('10.0.0.1', 22, keyB);
  assert.equal(changed.result, 'changed');
  assert.equal(changed.expected, kh.fingerprint(keyA));
  assert.equal(changed.fingerprint, kh.fingerprint(keyB));
  assert.equal(kh.check('10.0.0.1', 22, keyB).result, 'changed');   // refusing does not replace
});

test('hosts are keyed by host and port', () => {
  assert.equal(kh.check('10.0.0.1', 2222, keyB).result, 'new');
  assert.equal(kh.check('10.0.0.1', 22, keyA).result, 'match');
});

test('trust replaces the remembered key; a malformed fingerprint is rejected', () => {
  assert.throws(() => kh.trust('10.0.0.1', 22, 'not-a-fingerprint'));
  assert.equal(kh.check('10.0.0.1', 22, keyB).result, 'changed');
  kh.trust('10.0.0.1', 22, kh.fingerprint(keyB));
  assert.equal(kh.check('10.0.0.1', 22, keyB).result, 'match');
  assert.equal(kh.check('10.0.0.1', 22, keyA).result, 'changed');
});
