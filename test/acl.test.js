'use strict';
// Offline tests for the IP Access Lists module (public/src/14-acl.js): the
// table join, the tuple encodings, and the write paths (add, edit, delete a
// rule, delete a list) against a small in-memory stand-in for the switch's
// three QoS ACL tables. The real helpers the module calls (dvc, ipv4ToHex,
// interpretSet, rowStatusDelete) are taken from public/src/01-core.js as-is.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const SRC = path.join(__dirname, '..', 'public', 'src');
const read = (f) => fs.readFileSync(path.join(SRC, f), 'utf8');
// Objects made inside the vm have its prototypes; compare them as plain data.
const plain = (x) => JSON.parse(JSON.stringify(x));

// The source of one top-level function, by name (brace-matched).
function pickFunction(text, name) {
  const start = text.search(new RegExp('(async )?function ' + name + '\\('));
  assert.ok(start >= 0, 'no function ' + name);
  let i = text.indexOf('{', start), depth = 0;
  for (; i < text.length; i++) {
    if (text[i] === '{') depth++;
    else if (text[i] === '}' && --depth === 0) return text.slice(start, i + 1);
  }
  throw new Error('unbalanced ' + name);
}

const BASE = '1.3.6.1.4.1.9.6.1.101.88.';
const COL_NAMES = {
  '7.1.2': 'rlQosAclName', '7.1.3': 'rlQosAclType', '7.1.6': 'rlQosAclIsBoundToInterface', '7.1.8': 'rlQosAclOriginType',
  '31.1.3': 'rlQosAceTidxAction', '31.1.4': 'rlQosAceTidxType',
  '5.1.2': 'rlQosTupleType', '5.1.4': 'rlQosTupleValue2'
};
const TUPLE_COL_NAME = { 5: 1, 6: 2, 7: 3, 8: 4, 9: 5, 10: 6, 11: 7, 12: 8, 17: 9, 18: 10, 19: 11 };

// A stand-in switch: the ACL, ACE and tuple tables, answering createAndGo and
// destroy the way the module uses them. failOn(vbs) may return an error text
// to reject a SET.
function fakeSwitch(seed) {
  const sw = { acls: new Map(), aces: new Map(), tuples: new Map(), sets: [], failOn: () => null };
  for (const [k, v] of Object.entries(seed.acls || {})) sw.acls.set(k, Object.assign({ type: 2, bound: 2, origin: 1 }, v));
  for (const [k, v] of Object.entries(seed.aces || {})) sw.aces.set(k, v);
  for (const [k, v] of Object.entries(seed.tuples || {})) sw.tuples.set(k, v);

  sw.set = (vbs) => {
    vbs = Array.isArray(vbs) ? vbs : [vbs];
    sw.sets.push(vbs);
    const err = sw.failOn(vbs);
    if (err) return { ok: true, status: 200, body: { error: err } };
    const status = vbs.find((v) => /\.(7\.1\.4|31\.1\.14|5\.1\.5)\./.test(v.oid));
    const m = status.oid.match(/^1\.3\.6\.1\.4\.1\.9\.6\.1\.101\.88\.(7\.1\.4|31\.1\.14|5\.1\.5)\.(.+)$/);
    const table = { '7.1.4': sw.acls, '31.1.14': sw.aces, '5.1.5': sw.tuples }[m[1]];
    const idx = m[2];
    if (status.value === 6) {
      if (!table.has(idx)) return { ok: true, status: 200, body: { error: 'NoSuchInstance' } };
      table.delete(idx); return { ok: true, status: 200, body: {} };
    }
    if (status.value === 4) {
      if (table.has(idx)) return { ok: true, status: 200, body: { error: 'InconsistentValue' } };
      const row = {};
      for (const v of vbs) {
        const c = v.oid.slice(BASE.length, v.oid.length - idx.length - 1);
        if (c === '7.1.2') row.name = v.value; else if (c === '7.1.3') row.type = v.value;
        else if (c === '31.1.3') row.action = v.value; else if (c === '31.1.4') row.type = v.value;
        else if (c === '5.1.2') row.type = v.value; else if (c === '5.1.4') row.hex = v.valueHex;
        else if (/^31\.1\.\d+$/.test(c) && TUPLE_COL_NAME[c.split('.')[2]]) { row.tuples = row.tuples || []; row.tuples[TUPLE_COL_NAME[c.split('.')[2]] - 1] = String(v.value); }
      }
      if (table === sw.acls) Object.assign(row, { bound: 2, origin: 1 });
      if (table === sw.aces) row.tuples = (row.tuples || []).filter(Boolean);
      table.set(idx, row); return { ok: true, status: 200, body: {} };
    }
    return { ok: true, status: 200, body: { error: 'unsupported in the fake' } };
  };

  // The raw health rows the panel reads (as the walk returns them).
  sw.health = () => {
    const R = (index, col, value, display) => ({ index, column: COL_NAMES[col] || col, value, display });
    const aclNames = [], aclAces = [], aclTuples = [];
    for (const [i, a] of sw.acls) aclNames.push(R(i, '7.1.2', a.name), R(i, '7.1.3', a.type), R(i, '7.1.6', a.bound), R(i, '7.1.8', a.origin));
    for (const [i, a] of sw.aces) {
      aclAces.push(R(i, '31.1.3', a.action), R(i, '31.1.4', a.type));
      a.tuples.forEach((t, n) => aclAces.push(R(i, 'rlQosAceTidxTuple' + (n + 1), Number(t))));
    }
    for (const [i, t] of sw.tuples) aclTuples.push(R(i, '5.1.2', t.type), R(i, '5.1.4', '', t.hex));
    return { aclNames, aclAces, aclTuples };
  };
  return sw;
}

// Load the module with the real core helpers and a session wired to `sw`.
function load(sw) {
  const core = read('01-core.js');
  const helpers = ['dvc', 'ipv4ToHex', 'interpretSet', 'rowStatusDelete'].map((n) => pickFunction(core, n)).join('\n');
  const ctx = {
    console,
    snmpSetResult: async (s, vbs) => sw.set(vbs),
    snmpSet: async (s, vbs) => { const r = sw.set(vbs); if (r.body && r.body.error) throw new Error(r.body.error); return r.body; },
    refreshTables: async (s) => { s.health = Object.assign({}, s.health, sw.health()); },
    appLog: () => {}
  };
  vm.createContext(ctx);
  const api = vm.runInContext(helpers + '\n' + read('14-acl.js') + `
    ;({ aclModel, aclRuleView, decodeTuple, buildTupleMap, ipTupleHex, protoTupleHex, ACE_TUPLE_COLS,
        createQosAce, editQosAce, deleteQosAce, deleteQosAcl, aclDeleteLock, aclRefresh })`, ctx);
  const s = { target: { host: '10.0.0.2' }, host: '10.0.0.2', health: Object.assign({ scalars: {} }, sw.health()) };
  return { api, s };
}

// ACL 1 "web" with rule 1.1 (permit tcp from 192.168.1.0/24, ACK+SYN set) and
// rule 1.2 (deny ip any any). Tuple 12 is shared with ACL 2's only rule.
const seed = () => ({
  acls: { 1: { name: 'web' }, 2: { name: 'other' } },
  aces: { '1.1': { action: 1, type: 2, tuples: ['10', '11', '12'] }, '1.2': { action: 2, type: 1, tuples: [] }, '2.1': { action: 1, type: 2, tuples: ['12'] } },
  tuples: { 10: { type: 1, hex: '06ff' }, 11: { type: 2, hex: 'c0a80100000000ff' }, 12: { type: 18, hex: '122d' } }
});
const ruleCfg = (o) => Object.assign({ aclName: 'web', aclType: 2, action: 2, aceType: 1, proto: 0, srcAny: true, dstAny: false, dstIp: '10.1.2.0', dstPref: 24, tcpFlags: null }, o);

test('ACE tuple pointer columns match CISCOSB-qosclimib (Tuple1..11)', () => {
  const db = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'public', 'mib', 'oid-db.json'), 'utf8'));
  const cols = [];
  for (let n = 1; n <= 11; n++) {
    const e = db.entries.find((x) => x[0] === 'rlQosAceTidxTuple' + n);
    cols.push(Number(e[1].split('.').pop()));
  }
  const { api } = load(fakeSwitch(seed()));
  assert.deepEqual(plain(api.ACE_TUPLE_COLS), cols);
});

test('the join decodes each rule and flags what the form cannot edit', () => {
  const sw = fakeSwitch(seed());
  sw.aces.set('2.2', { action: 1, type: 3, tuples: ['13'] });
  sw.tuples.set('13', { type: 7, hex: '0035' });   // udp-dst 53: a port match the form does not offer
  const { api, s } = load(sw);
  s.health = Object.assign({}, s.health, sw.health());
  const m = api.aclModel(s.health);
  assert.deepEqual(plain(m.acls.map((a) => a.name)), ['web', 'other']);
  const web = m.byIdx.get('1');
  assert.deepEqual(plain(web.aceList.map((a) => a.idx)), ['1', '2']);
  const v = api.aclRuleView(web.aces.get('1'), m.tupleMap);
  assert.equal(v.action, 'permit');
  assert.equal(v.src, '192.168.1.0/24');
  assert.equal(v.dst, 'any');
  assert.deepEqual(plain(v.extra), ['flags +ack +syn']);
  assert.deepEqual(plain(v.unsupported), []);
  assert.deepEqual(plain(v.init.src), { any: false, ip: '192.168.1.0', pref: 24 });
  const udp = api.aclRuleView(m.byIdx.get('2').aces.get('2'), m.tupleMap);
  assert.deepEqual(plain(udp.unsupported), ['udp-dst 53']);
});

test('ip tuples encode value and wildcard mask, and decode back', () => {
  const { api } = load(fakeSwitch(seed()));
  assert.equal(api.ipTupleHex('192.168.1.0', 24), 'c0a80100000000ff');
  assert.equal(api.ipTupleHex('10.0.0.1', 32), '0a00000100000000');
  assert.equal(api.ipTupleHex('bad', 24), null);
  assert.equal(api.protoTupleHex(17), '11ff');
  assert.deepEqual(plain(api.decodeTuple({ type: 3, v2: api.ipTupleHex('172.16.0.0', 12) })), { field: 'dst', text: '172.16.0.0/12' });
});

test('adding a rule to a new list creates the list, its tuples and the rule', async () => {
  const sw = fakeSwitch(seed());
  const { api, s } = load(sw);
  await api.createQosAce(s, ruleCfg({ aclName: 'new-list', proto: 6, aceType: 2 }));
  assert.equal(sw.acls.get('3').name, 'new-list');
  assert.deepEqual(sw.aces.get('3.1'), { action: 2, type: 2, tuples: ['13', '14'] });
  assert.equal(sw.tuples.get('13').hex, '06ff');
  assert.equal(sw.tuples.get('14').hex, '0a010200000000ff');
});

test('a failed add removes the tuples and the new list it created', async () => {
  const sw = fakeSwitch(seed());
  sw.failOn = (vbs) => (vbs.some((v) => v.oid.indexOf(BASE + '31.1.14.') === 0) ? 'CommitFailed' : null);
  const { api, s } = load(sw);
  await assert.rejects(api.createQosAce(s, ruleCfg({ aclName: 'new-list' })), /creating ACE: CommitFailed/);
  assert.equal(sw.acls.has('3'), false);
  assert.deepEqual(Array.from(sw.tuples.keys()), ['10', '11', '12']);
});

test('deleting a rule removes its tuples but keeps one another rule shares', async () => {
  const sw = fakeSwitch(seed());
  const { api, s } = load(sw);
  const res = await api.deleteQosAce(s, '1', '1');
  assert.equal(res.ok, true);
  assert.equal(sw.aces.has('1.1'), false);
  assert.deepEqual(Array.from(sw.tuples.keys()), ['12']);
});

test('editing a rule keeps its index and replaces its tuples', async () => {
  const sw = fakeSwitch(seed());
  const { api, s } = load(sw);
  await api.editQosAce(s, '1', '1', ruleCfg());
  assert.deepEqual(sw.aces.get('1.1'), { action: 2, type: 1, tuples: ['13'] });
  assert.deepEqual(Array.from(sw.tuples.keys()).sort(), ['12', '13']);
  assert.equal(sw.aces.has('1.3'), false);
});

test('a failed edit puts the original rule back with its original tuples', async () => {
  const sw = fakeSwitch(seed());
  let aceCreates = 0;
  sw.failOn = (vbs) => {
    const create = vbs.find((v) => v.oid.indexOf(BASE + '31.1.14.') === 0 && v.value === 4);
    return create && ++aceCreates === 1 ? 'CommitFailed' : null;   // the replacement fails, the restore works
  };
  const { api, s } = load(sw);
  await assert.rejects(api.editQosAce(s, '1', '1', ruleCfg()), /CommitFailed\. The original rule was put back\./);
  assert.deepEqual(sw.aces.get('1.1'), { action: 1, type: 2, tuples: ['10', '11', '12'] });
  assert.deepEqual(Array.from(sw.tuples.keys()), ['10', '11', '12']);
});

test('deleting a list removes its rules, unshared tuples and the list', async () => {
  const sw = fakeSwitch(seed());
  const { api, s } = load(sw);
  const res = await api.deleteQosAcl(s, '1');
  assert.equal(res.ok, true);
  assert.equal(sw.acls.has('1'), false);
  assert.deepEqual(Array.from(sw.aces.keys()), ['2.1']);
  assert.deepEqual(Array.from(sw.tuples.keys()), ['12']);
});

test('a bound or switch-created list is refused, and nothing is written', async () => {
  const sw = fakeSwitch(seed());
  sw.acls.get('1').bound = 1;
  sw.acls.get('2').origin = 3;
  const { api, s } = load(sw);
  s.health = Object.assign({}, s.health, sw.health());
  assert.match((await api.deleteQosAcl(s, '1')).error, /bound to a port or VLAN/);
  assert.match((await api.deleteQosAcl(s, '2')).error, /created by the switch \(system\)/);
  assert.equal(sw.sets.length, 0);
});

// The ACL tables are "raw" in health.js (rows are not pivoted), which is not
// the shared walk's own raw option (bare varbinds, no index or column). With
// the two mixed up every row lost its index and column, the panel showed no
// lists, and a new list was given an index already in use. Run the real
// collection path against a fake agent and check the rows keep both.
test('ACL tables come back from a health read with index and column', async () => {
  const snmp = require('net-snmp');
  const health = require('../health');
  const { boundedWalkPromise } = require('../collection');
  const T = snmp.ObjectType;
  const agent = [
    ['1.3.6.1.4.1.9.6.1.101.88.7.1.2.1', T.OctetString, Buffer.from('Example')],
    ['1.3.6.1.4.1.9.6.1.101.88.7.1.3.1', T.Integer, 2],
    ['1.3.6.1.4.1.9.6.1.101.88.31.1.3.1.1', T.Integer, 1],
    ['1.3.6.1.4.1.9.6.1.101.88.5.1.4.7', T.OctetString, Buffer.from([0x06, 0xff])]
  ];
  const cmp = (a, b) => { const x = a.split('.').map(Number), y = b.split('.').map(Number);
    for (let i = 0; i < Math.max(x.length, y.length); i++) { if (x[i] === undefined) return -1; if (y[i] === undefined) return 1; if (x[i] !== y[i]) return x[i] - y[i]; } return 0; };
  agent.sort((a, b) => cmp(a[0], b[0]));
  const after = (oid) => agent.find(([o]) => cmp(o, oid) > 0);
  const session = {
    version: snmp.Version2c,
    getBulk: (oids, nr, max, cb) => { const n = after(oids[0]); setImmediate(() => cb(null, n ? [{ oid: n[0], type: n[1], value: n[2] }] : [{ oid: oids[0], type: T.EndOfMibView }])); },
    getNext: (oids, cb) => { const n = after(oids[0]); setImmediate(() => cb(null, n ? [{ oid: n[0], type: n[1], value: n[2] }] : [{ oid: oids[0], type: T.EndOfMibView }])); }
  };
  const out = await health.collect({ only: ['aclNames', 'aclAces', 'aclTuples'], get: async () => [],
    walk: (oid, spec) => boundedWalkPromise(session, oid, undefined, spec) });
  const name = out.aclNames.find((r) => r.column === 'rlQosAclName');
  assert.ok(name, 'the name row is recognised');
  assert.equal(name.index, '1');
  assert.equal(name.value, 'Example');
  assert.equal(out.aclAces[0].column, 'rlQosAceTidxAction');
  assert.equal(out.aclAces[0].index, '1.1');
  assert.equal(out.aclTuples[0].column, 'rlQosTupleValue2');
  // And the panel's join sees the list.
  const { api } = load({ set: () => ({}), health: () => ({}) });
  const model = api.aclModel({ aclNames: plain(out.aclNames), aclAces: plain(out.aclAces), aclTuples: plain(out.aclTuples) });
  assert.deepEqual(plain(model.acls.map((a) => [a.idx, a.name, a.type, a.aceList.length])), [['1', 'Example', 2, 1]]);
});
