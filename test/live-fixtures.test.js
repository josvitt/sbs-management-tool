'use strict';

// Real switch output, replayed. Each test/fixtures/live/<switch>-health.json
// holds every SNMP get and walk the health collector made against a real
// switch (scrubbed: communities, addresses, MACs, names and secrets replaced)
// and what collect() produced from them. Feeding the recorded answers back
// through health.collect must give the same result, so a change to parsing,
// decoration or alerting that alters what a real switch shows fails here.
//
// To add a switch, record it the same way (every call as
// { kind: 'get', oids, result } or { kind: 'walk', oid, spec, result },
// Buffers as { "$buf": "<hex>" }), scrub it, and drop the file in.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const health = require('../health');

const DIR = path.join(__dirname, 'fixtures', 'live');

const revive = (v) => JSON.parse(JSON.stringify(v), (k, x) => {
  if (x && typeof x === 'object' && Object.keys(x).length === 1) {
    if (typeof x.$buf === 'string') return Buffer.from(x.$buf, 'hex');
    if (typeof x.$bigint === 'string') return BigInt(x.$bigint);
  }
  return x;
});

async function replay(fx) {
  const queues = new Map();
  const keyOf = (kind, a, b) => JSON.stringify([kind, a, b === undefined ? null : b]);
  for (const c of fx.calls) {
    const k = c.kind === 'get' ? keyOf('get', c.oids) : keyOf('walk', c.oid, c.spec);
    if (!queues.has(k)) queues.set(k, []);
    queues.get(k).push(c);
  }
  const take = (k) => {
    const q = queues.get(k);
    if (!q || !q.length) throw new Error('no recorded answer for ' + k);
    const c = q.shift();
    if (c.error) throw new Error(c.error);
    return revive(c.result);
  };
  const out = await health.collect({
    get: async (oids) => take(keyOf('get', oids)),
    walk: async (oid, spec) => take(keyOf('walk', oid, JSON.parse(JSON.stringify(spec === undefined ? null : spec))))
  });
  const unused = [...queues.values()].reduce((n, q) => n + q.length, 0);
  return { out, unused };
}

const files = fs.readdirSync(DIR).filter((f) => f.endsWith('-health.json'));

test('there is at least one live fixture', () => assert.ok(files.length > 0));

for (const file of files) {
  const fx = JSON.parse(fs.readFileSync(path.join(DIR, file), 'utf8'));
  const want = fx.output;

  test(file + ': replaying the recorded switch gives the recorded result', async () => {
    const { out, unused } = await replay(fx);
    assert.equal(unused, 0, 'every recorded call is asked for again');
    assert.equal(out.model, want.model);
    assert.deepEqual(out.summary, want.summary);
    assert.deepEqual(out.alerts, want.alerts);
    assert.deepEqual(out.failed, want.failed);
    // Table sizes, so a parsing change that drops or invents rows shows.
    for (const k of Object.keys(want)) {
      if (Array.isArray(want[k])) assert.equal(out[k].length, want[k].length, 'rows in ' + k);
    }
  });

  test(file + ': holds nothing that should have been scrubbed', () => {
    const text = fs.readFileSync(path.join(DIR, file), 'utf8') +
      (fs.existsSync(path.join(DIR, file.replace('-health.json', '-running.cfg')))
        ? fs.readFileSync(path.join(DIR, file.replace('-health.json', '-running.cfg')), 'utf8') : '');
    // Private IPv4 (RFC 1918) written out as an address; documentation
    // ranges (192.0.2.0/24, 198.51.100.0/24) are what scrubbing maps to.
    assert.doesNotMatch(text, /(^|[^.\d])(10\.\d{1,3}|172\.(1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}(?![.\d])/);
    assert.doesNotMatch(text, /^\s*(snmp-server community|enable password|username \S+ password)\s+(?!REDACTED)/m);
  });
}

