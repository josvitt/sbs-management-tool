'use strict';
// The assembled Express app (web.js), over real HTTP on an ephemeral port:
// pins that the request guard and the security headers are actually wired in,
// not only that the modules behave in isolation.
const test = require('node:test');
const assert = require('node:assert/strict');
const app = require('../web');

let server, base;
test.before(async () => {
  server = app.listen(0, '127.0.0.1');
  await new Promise((r) => server.once('listening', r));
  base = 'http://127.0.0.1:' + server.address().port;
});
test.after(() => server.close());

test('a normal page load is served with the security headers', async () => {
  const res = await fetch(base + '/');
  assert.equal(res.status, 200);
  const csp = res.headers.get('content-security-policy');
  assert.match(csp, /script-src 'self'(;|$)/);
  assert.doesNotMatch(csp, /script-src[^;]*unsafe-inline/);
  assert.match(csp, /frame-ancestors 'none'/);
  assert.equal(res.headers.get('x-frame-options'), 'DENY');
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
});

test('the guard runs before any route: a cross-site API call is refused', async () => {
  const res = await fetch(base + '/api/log', {
    method: 'POST', headers: { 'Content-Type': 'application/json', Origin: 'http://evil.example' },
    body: JSON.stringify({ level: 'info', message: 'x' })
  });
  assert.equal(res.status, 403);
});

test('the same call from the page itself is accepted', async () => {
  const res = await fetch(base + '/api/log', {
    method: 'POST', headers: { 'Content-Type': 'application/json', Origin: base },
    body: JSON.stringify({ level: 'info', message: 'web.test same-origin' })
  });
  assert.equal(res.status, 204);
});
