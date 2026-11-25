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

// The recorded answers, served as a switch would: every varbind the switch
// returned is put back at its OID, so a walk (of one OID or of several columns
// together) and a GET of exact instances are both answered from what the real
// switch said, whatever shape of request the collector now makes. Missing
// instances answer noSuchInstance, as the switch does.
const mib = require('../mibdb');
const { oidCompare, isWithinSubtree } = require('../snmp-core');

function agentFrom(fx) {
  const store = new Map();
  for (const c of fx.calls) {
    if (c.error) continue;
    for (const r of revive(c.result) || []) if (r && r.oid && !r.error) store.set(r.oid, r);
  }
  const sorted = Array.from(store.keys()).sort(oidCompare);
  return { store, sorted };
}

// Requests a walk of these columns costs, the way snmp-core's walk asks
// (GETBULK; several columns share maxVarbinds, one column uses its own
// repetition count).
function walkRequests(rowsPerColumn, spec) {
  if (rowsPerColumn.length === 1) return Math.floor(rowsPerColumn[0] / ((spec && spec.maxRepetitions) || 10)) + 1;
  const left = rowsPerColumn.slice();
  let open = left.map((_, i) => i);
  let n = 0;
  while (open.length) {
    const reps = Math.max(1, Math.floor(40 / open.length));
    n++;
    open = open.filter((i) => { const more = left[i] >= reps; left[i] -= reps; return more; });
  }
  return n;
}

async function replay(fx) {
  const { store, sorted } = agentFrom(fx);
  const counter = { requests: 0 };
  const walkOne = (name, spec) => {
    const base = mib.resolveOid(name);
    const max = (spec && spec.maxRows) || 10000;
    const rows = sorted.filter((o) => isWithinSubtree(base, o)).slice(0, max).map((o) => store.get(o));
    return rows;
  };
  const out = await health.collect({
    get: async (oids) => {
      counter.requests++;
      return oids.map((name) => {
        const oid = mib.resolveOid(name);
        return store.get(oid) || { oid, error: 'NoSuchInstance', column: mib.describeOid(oid) };
      });
    },
    walk: async (oid, spec) => {
      const cols = Array.isArray(oid) ? oid : [oid];
      const per = cols.map((c) => walkOne(c, spec));
      counter.requests += walkRequests(per.map((r) => r.length), spec);
      return [].concat(...per);
    }
  });
  return { out, requests: counter.requests };
}

// What the recorded collection cost: one request per GET, and per walk the
// GETBULKs a single-column walk of that many rows takes.
function recordedRequests(fx) {
  let n = 0;
  for (const c of fx.calls) {
    if (c.kind === 'get') n++;
    else n += Math.floor(((c.result || []).length) / ((c.spec && c.spec.maxRepetitions) || 10)) + 1;
  }
  return n;
}

const files = fs.readdirSync(DIR).filter((f) => f.endsWith('-health.json'));

function digest(out, perPort) {
  const crypto = require('crypto');
  const plain = (v) => JSON.parse(JSON.stringify(v));
  const present = new Set(out.interfaces.map((r) => String(r.index)));
  const d = {};
  for (const k of Object.keys(out).sort()) {
    if (!Array.isArray(out[k])) continue;
    let rows = plain(out[k]);
    if (perPort.includes(k)) rows = rows.filter((r) => present.has(String(r.index)));
    d[k] = crypto.createHash('sha256').update(JSON.stringify(rows)).digest('hex').slice(0, 16);
  }
  return d;
}

const PER_PORT = Object.keys(health.TABLE_WALKS).filter((k) => health.TABLE_WALKS[k].perPort);

test('there is at least one live fixture', () => assert.ok(files.length > 0));

for (const file of files) {
  const fx = JSON.parse(fs.readFileSync(path.join(DIR, file), 'utf8'));
  const want = fx.output;

  test(file + ': replaying the recorded switch gives the recorded result', async () => {
    const { out } = await replay(fx);
    assert.equal(out.model, want.model);
    assert.deepEqual(out.summary, want.summary);
    assert.deepEqual(out.alerts, want.alerts);
    assert.deepEqual(out.failed, want.failed);
    // Table sizes against the recording, except per-port tables, which are
    // now read for the interfaces that exist only.
    for (const k of Object.keys(want)) {
      if (Array.isArray(want[k]) && !PER_PORT.includes(k)) assert.equal(out[k].length, want[k].length, 'rows in ' + k);
    }
    // And every table, row for row, against what v1.4.2 produced from this
    // same fixture (digest file beside it; per-port tables cut to the
    // interfaces that exist in both).
    const basePath = path.join(DIR, file.replace('-health.json', '-baseline.json'));
    if (fs.existsSync(basePath)) {
      const base = JSON.parse(fs.readFileSync(basePath, 'utf8'));
      const now = digest(out, base.perPort);
      for (const k of Object.keys(base.tables)) assert.equal(now[k], base.tables[k], 'table ' + k + ' differs from v1.4.2');
    }
  });

  test(file + ': the same result costs far fewer SNMP requests', async () => {
    const { requests } = await replay(fx);
    const before = recordedRequests(fx);
    // Recorded for the release notes: the reduction on a real switch.
    console.log(`# ${file}: ${before} recorded requests -> ${requests} now`);
    assert.ok(requests * 4 < before, `requests ${requests} vs recorded ${before}`);
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

