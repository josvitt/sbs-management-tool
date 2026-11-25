'use strict';

// The speed changes of v1.5.0, offline: the per-switch request limiter, the
// multi-column walk, per-port tables read for the interfaces that exist, the
// settings tables carried between collections, Refresh joining a poll in
// progress, and the "unchanged" snapshot answer.
const test = require('node:test');
const assert = require('node:assert/strict');
const snmp = require('net-snmp');
const core = require('../snmp-core');
const health = require('../health');
const collector = require('../collector');

const T = snmp.ObjectType;
const cmp = core.oidCompare;

// A tiny agent: sorted varbinds, answering GETBULK the way a switch does
// (repetitions run on past the end of a column into whatever follows).
function agent(rows, opts) {
  const o = opts || {};
  const list = rows.map(([oid, value]) => ({ oid, type: T.Integer, value })).sort((a, b) => cmp(a.oid, b.oid));
  const after = (oid) => list.find((vb) => cmp(vb.oid, oid) > 0) || { oid, type: T.EndOfMibView, value: null };
  const stats = { bulk: 0, maxVarbinds: 0 };
  const session = {
    version: snmp.Version2c,
    getBulk(oids, nonRep, reps, cb) {
      stats.bulk++;
      if (o.failMulti && oids.length > 1) return setImmediate(() => cb(new snmp.RequestFailedError('genErr', 5)));
      if (o.tooBigOver && oids.length * reps > o.tooBigOver) return setImmediate(() => cb(new snmp.RequestFailedError('tooBig', 1)));
      stats.maxVarbinds = Math.max(stats.maxVarbinds, oids.length * reps);
      const out = oids.map((start) => {
        const col = [];
        let cur = start;
        for (let i = 0; i < reps; i++) { const n = after(cur); col.push(n); if (n.type === T.EndOfMibView) break; cur = n.oid; }
        return col;
      });
      setImmediate(() => cb(null, out));
    },
    getNext(oids, cb) { setImmediate(() => cb(null, oids.map(after))); }
  };
  return { session, stats };
}

const walk = (session, base, options) => new Promise((resolve, reject) => {
  core.boundedWalk(session, base, Object.assign({ raw: true, paceMs: 0 }, options || {}),
    (error, rows) => (error && !rows.length ? reject(error) : resolve(rows)));
});

// Two columns of different lengths, and a neighbouring table that must never
// leak in (the over-fetch the boundary rule exists for).
const TABLE = [];
for (let i = 1; i <= 3; i++) TABLE.push(['1.3.6.1.4.1.99.1.1.2.' + i, i]);
for (let i = 1; i <= 25; i++) TABLE.push(['1.3.6.1.4.1.99.1.1.3.' + i, 100 + i]);
TABLE.push(['1.3.6.1.4.1.99.2.1.1.1', 999]);
const COL_A = '1.3.6.1.4.1.99.1.1.2';
const COL_B = '1.3.6.1.4.1.99.1.1.3';

test('columns walked together give exactly the rows of separate walks, in fewer requests', async () => {
  const one = agent(TABLE);
  const separate = [...await walk(one.session, COL_A), ...await walk(one.session, COL_B)];
  const before = one.stats.bulk;
  const two = agent(TABLE);
  const together = await walk(two.session, [COL_A, COL_B]);
  assert.deepEqual(together.map((r) => r.oid), separate.map((r) => r.oid));
  assert.ok(!together.some((r) => r.oid.startsWith('1.3.6.1.4.1.99.2.')), 'nothing from the next table');
  assert.ok(two.stats.bulk < before, `together ${two.stats.bulk} < separate ${before}`);
});

test('a reply the switch calls too big is asked for again, smaller', async () => {
  const a = agent(TABLE, { tooBigOver: 10 });
  const rows = await walk(a.session, [COL_A, COL_B]);
  assert.equal(rows.length, 28);
  assert.ok(a.stats.maxVarbinds <= 10);
});

test('an error status on a combined request falls back to one walk per column', async () => {
  const a = agent(TABLE, { failMulti: true });
  const rows = await walk(a.session, [COL_A, COL_B]);
  assert.equal(rows.length, 28);
});

test('maxRows applies to each column of a combined walk', async () => {
  const a = agent(TABLE);
  const rows = await walk(a.session, [COL_A, COL_B], { maxRows: 5 });
  assert.equal(rows.filter((r) => r.oid.startsWith(COL_A + '.')).length, 3);
  assert.equal(rows.filter((r) => r.oid.startsWith(COL_B + '.')).length, 5);
});

test('requests to one switch are spaced to the budget, across sessions', async () => {
  const sent = [];
  const fake = () => ({ get: (oids, cb) => { sent.push(Date.now()); setImmediate(() => cb(null, [])); } });
  const s1 = core.limitRequests(fake(), '192.0.2.50', 161);
  const s2 = core.limitRequests(fake(), '192.0.2.50', 161);
  await Promise.all([0, 1, 2, 3, 4, 5].map((i) => new Promise((res) => (i % 2 ? s1 : s2).get(['1.3'], res))));
  const gap = 1000 / core.MAX_REQUESTS_PER_SEC;
  // Timers may run late under load, never meaningfully early, so the span of
  // the six sends is at least five gaps (1 ms slack for timer rounding).
  assert.ok(sent[sent.length - 1] - sent[0] >= 5 * gap - 1, 'span ' + (sent[sent.length - 1] - sent[0]));
});

test('a successful write tells the write listeners which switch changed', async () => {
  const told = [];
  core.onSwitchWrite((host) => told.push(host));
  const s = core.limitRequests({ set: (vbs, cb) => setImmediate(() => cb(null, vbs)) }, '192.0.2.51', 161);
  const f = core.limitRequests({ set: (vbs, cb) => setImmediate(() => cb(new Error('noAccess'))) }, '192.0.2.52', 161);
  await new Promise((res) => s.set([], res));
  await new Promise((res) => f.set([], res));
  assert.deepEqual(told, ['192.0.2.51']);
});

// ---- per-port tables ----------------------------------------------------

function fakeSwitch(opts) {
  const o = opts || {};
  const present = ['1', '2', '1000'];
  const calls = { walks: [], gets: [] };
  const row = (column, index, value) => ({ oid: 'x.' + index, column, index, value, display: String(value) });
  const walkFn = async (oid, spec) => {
    const cols = Array.isArray(oid) ? oid : [oid];
    calls.walks.push(cols.join(','));
    const out = [];
    for (const c of cols) {
      if (c === 'rlifPresentName') for (const i of present) out.push(row(c, i, 'p' + i));
      else if (spec && spec.perPort) for (let i = 1; i <= 424; i++) out.push(row(c, String(i), i));
    }
    return out;
  };
  const getFn = async (oids) => {
    calls.gets.push(oids.length);
    return oids.map((name) => {
      const dot = name.indexOf('.');
      const column = name.slice(0, dot);
      const index = name.slice(dot + 1);
      if (o.otherIndexing || index === '1000' && column.startsWith('dot1dStp')) return { oid: name, error: 'NoSuchInstance', column };
      return row(column, index, column === 'dot1dBasePortIfIndex' ? Number(index) : 7);
    });
  };
  return { walk: walkFn, get: getFn, calls };
}

test('per-port tables are read by GET for the interfaces that exist', async () => {
  const sw = fakeSwitch();
  const out = await health.collect({ get: sw.get, walk: sw.walk });
  const perPort = Object.keys(health.TABLE_WALKS).filter((k) => health.TABLE_WALKS[k].perPort);
  for (const k of perPort) {
    const cols = health.TABLE_WALKS[k].columns.join(',');
    assert.ok(!sw.calls.walks.includes(cols), k + ' was not walked');
  }
  assert.deepEqual(out.portModes.map((r) => r.index), ['1', '2', '1000']);
  assert.deepEqual(out.bridgePorts.map((r) => r.index), ['1', '2', '1000']);
});

test('a per-port table that answers no GET is walked the old way', async () => {
  const sw = fakeSwitch({ otherIndexing: true });
  const out = await health.collect({ get: sw.get, walk: sw.walk });
  assert.ok(sw.calls.walks.includes('vlanPortModeState'), 'fell back to the walk');
  assert.equal(out.portModes.length, 424);
});

test('a targeted refresh uses the interfaces of the last full collection', async () => {
  const sw = fakeSwitch();
  const out = await health.collect({ get: sw.get, walk: sw.walk, only: ['dot1xPortCfg'],
    previous: { at: Date.now(), interfaces: [{ index: '1' }, { index: '2' }] } });
  assert.deepEqual(sw.calls.walks, [], 'nothing walked');
  assert.deepEqual(out.dot1xPortCfg.map((r) => r.index), ['1', '2']);
});

test('settings tables passed as reuse are carried, not read', async () => {
  const sw = fakeSwitch();
  const kept = [{ index: '9', entPhysicalName: { value: 'kept' } }];
  const out = await health.collect({ get: sw.get, walk: sw.walk, reuse: { inventory: kept } });
  assert.equal(out.inventory, kept);
  assert.deepEqual(out.carried, ['inventory']);
  assert.ok(!sw.calls.walks.some((w) => w.startsWith('entPhysical')), 'inventory not walked');
});

// ---- collector ----------------------------------------------------------

function startCollector(collect, probe) {
  collector.start({
    probe: probe || (async () => ({ reachable: true, uptime: 100 })),
    collect,
    loadSwitches: () => [],
    settingsTables: ['inventory'],
    events: { record: () => {} },
    history: { append: () => {} }
  }, { schedule: false });
}

test('the collector carries settings until something may have changed them', async () => {
  const seen = [];
  startCollector(async (target, opts) => { seen.push(!!(opts && opts.reuse)); return { collectedAt: String(seen.length), inventory: [], alerts: [], summary: {} }; });
  const realNow = Date.now;
  let skew = 0;
  Date.now = () => realNow() + skew;
  try {
    const entry = { target: { host: '192.0.2.60', port: 161 } };
    const poll = collector._internals.pollOnce;
    await poll(entry, {});                       // first: reads everything
    skew += 10 * 60 * 1000; await poll(entry, {});   // carried
    collector.flagSettingsChange('192.0.2.60');
    skew += 10 * 60 * 1000; await poll(entry, {});   // re-read after a write
    skew += 10 * 60 * 1000; await poll(entry, {});   // carried again
    skew += 61 * 60 * 1000; await poll(entry, {});   // an hour old: re-read
    await collector.nudge(entry.target);             // manual Refresh: re-read
  } finally { Date.now = realNow; collector.stop(); }
  assert.deepEqual(seen, [false, true, false, true, false, false]);
});

test('a Refresh during a poll waits for it rather than returning old data', async () => {
  let calls = 0;
  let release;
  const gate = new Promise((res) => { release = res; });
  startCollector(async () => { calls++; await gate; return { collectedAt: 'c' + calls, alerts: [], summary: {} }; });
  try {
    const target = { host: '192.0.2.61', port: 161 };
    const first = collector.nudge(target);
    const second = collector.nudge(target);
    setTimeout(release, 20);
    const [a, b] = await Promise.all([first, second]);
    assert.equal(calls, 1, 'one poll, not two');
    assert.equal(a.data.collectedAt, 'c1');
    assert.equal(b.data.collectedAt, 'c1', 'the second caller gets the fresh result');
  } finally { collector.stop(); }
});

test('the snapshot route answers "unchanged" when the page already has it', async () => {
  startCollector(async () => ({ collectedAt: '2026-11-25T18:00:00.000Z', alerts: [], summary: {} }));
  const routes = {};
  const app = {};
  for (const m of ['get', 'post', 'put', 'delete', 'patch', 'use']) app[m] = (p, h) => { routes[m.toUpperCase() + ' ' + p] = h; };
  require('../routes/monitoring')(app);
  const call = (query) => new Promise((resolve) => {
    const res = { status() { return this; }, json: (body) => resolve(body) };
    routes['GET /api/collector/snapshot']({ query }, res);
  });
  try {
    await collector.nudge({ host: '192.0.2.62', port: 161 });
    const same = await call({ host: '192.0.2.62', have: '2026-11-25T18:00:00.000Z' });
    assert.equal(same.unchanged, true);
    const other = await call({ host: '192.0.2.62', have: 'older' });
    assert.equal(other.data.collectedAt, '2026-11-25T18:00:00.000Z');
  } finally { collector.stop(); }
});

// ---- server-side panels in the collection (v1.6.0) -----------------------

test('SNMP configuration is read in one pass: each table walked once, same lists', async () => {
  const sc = require('../snmp-config');
  const T2 = snmp.ObjectType;
  // A plausible VACM picture: one community in group 'g' with a write view.
  const enc = (str) => [str.length, ...Buffer.from(str, 'latin1')].join('.');
  const rows = {
    '1.3.6.1.6.3.18.1.1.1': [['2.' + enc('c1'), Buffer.from('public')], ['3.' + enc('c1'), Buffer.from('SNR-public')]],
    '1.3.6.1.6.3.16.1.2.1': [['3.2.' + enc('SNR-public'), Buffer.from('g')]],
    '1.3.6.1.6.3.16.1.4.1': [['6.' + enc('g') + '.0.2.1', Buffer.from('DefaultSuper')]]
  };
  let walks = 0;
  const S = {
    get: async (oids) => oids.map((oid) => ({ oid, value: null, error: 'noSuchInstance' })),
    walk: async (base) => { walks++; return (rows[base] || []).map(([idx, v]) => ({ oid: base + '.' + idx, value: v, type: T2.OctetString })); },
    set: async () => null
  };
  const meta = { version: '2c', community: 'public' };
  const all = await sc.readAll(S, meta);
  assert.ok(walks <= 9, 'walks ' + walks);
  const one = { ok: true, ...(await sc.listGroups(S)) };
  assert.deepEqual(JSON.parse(JSON.stringify(all.groups)), JSON.parse(JSON.stringify(one)));
  assert.ok(all.access.ok);
});

test('the collector reads the capture list every cycle and the settings-like panels on change', async () => {
  const reads = [];
  collector.start({
    probe: async () => ({ reachable: true, uptime: 100 }),
    collect: async () => ({ collectedAt: String(Date.now()), alerts: [], summary: {} }),
    collectModules: async (target, keys) => { reads.push(keys.slice().sort().join(',')); const o = {}; for (const k of keys) o[k] = { ok: true, n: reads.length }; return o; },
    modules: { everyCycle: ['captures'], onSettings: ['snmpConfig', 'flash'] },
    loadSwitches: () => [],
    settingsTables: ['inventory'],
    events: { record: () => {} },
    history: { append: () => {} }
  }, { schedule: false });
  const realNow = Date.now;
  let skew = 0;
  Date.now = () => realNow() + skew;
  try {
    const entry = { target: { host: '192.0.2.70', port: 161 } };
    const poll = collector._internals.pollOnce;
    const a = await poll(entry, {});
    skew += 10 * 60 * 1000; const b = await poll(entry, {});
    collector.flagSettingsChange('192.0.2.70');
    skew += 10 * 60 * 1000; await poll(entry, {});
    assert.deepEqual(reads, ['captures,flash,snmpConfig', 'captures', 'captures,flash,snmpConfig']);
    assert.equal(b.data.snmpConfig.n, a.data.snmpConfig.n, 'carried, not re-read');
    assert.notEqual(b.data.captures.n, a.data.captures.n, 'the capture list is fresh');
  } finally { Date.now = realNow; collector.stop(); }
});
