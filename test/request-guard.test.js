'use strict';
// Offline tests for request-guard.js: every refusal has a matching
// "still allowed" case, because a guard that blocks everything also passes a
// negative-only test.
const test = require('node:test');
const assert = require('node:assert/strict');
const os = require('os');
const { refusal } = require('../request-guard');

test('LAN access by IP address is allowed, with or without a same-origin Origin', () => {
  assert.equal(refusal({ host: '192.168.1.20:3000' }), null);
  assert.equal(refusal({ host: '192.168.1.20:3000', origin: 'http://192.168.1.20:3000' }), null);
  assert.equal(refusal({ host: '[fe80::1]:3000', origin: 'http://[fe80::1]:3000' }), null);
});

test('localhost and this computer\'s own name are allowed', () => {
  assert.equal(refusal({ host: 'localhost:3000' }), null);
  assert.equal(refusal({ host: os.hostname() + ':3000' }), null);
  assert.equal(refusal({ host: os.hostname() + '.corp.example:3000' }), null);
});

test('a cross-site Origin is refused even on an allowed Host', () => {
  assert.match(refusal({ host: '192.168.1.20:3000', origin: 'http://evil.example' }), /Cross-site/);
  assert.match(refusal({ host: 'localhost:3000', origin: 'http://localhost:4000' }), /Cross-site/);
  assert.match(refusal({ host: 'localhost:3000', origin: 'null' }), /Cross-site/);
});

test('a foreign Host name (DNS rebinding) is refused', () => {
  assert.match(refusal({ host: 'rebind.evil.example:3000' }), /not a name for this server/);
  assert.match(refusal({ host: 'rebind.evil.example:3000', origin: 'http://rebind.evil.example:3000' }),
    /not a name for this server/);
  assert.match(refusal({}), /not a name for this server/);
});

test('SBS_ALLOWED_HOSTS admits an alias, and only that alias', () => {
  const before = process.env.SBS_ALLOWED_HOSTS;
  process.env.SBS_ALLOWED_HOSTS = 'sbs.lan, other.lan';
  try {
    assert.equal(refusal({ host: 'sbs.lan:3000', origin: 'http://sbs.lan:3000' }), null);
    assert.equal(refusal({ host: 'other.lan' }), null);
    assert.match(refusal({ host: 'sbs.lan.evil.example:3000' }), /not a name/);
  } finally {
    if (before === undefined) delete process.env.SBS_ALLOWED_HOSTS; else process.env.SBS_ALLOWED_HOSTS = before;
  }
});
