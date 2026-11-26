'use strict';
// Offline tests for the Access Lists module (public/src/14-acl.js): the
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
  '5.1.2': 'rlQosTupleType', '5.1.3': 'rlQosTupleValue1', '5.1.4': 'rlQosTupleValue2'
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
        else if (c === '5.1.3') row.n1 = v.value;
        else if (/^31\.1\.\d+$/.test(c) && TUPLE_COL_NAME[c.split('.')[2]]) { row.slots = row.slots || {}; row.slots[TUPLE_COL_NAME[c.split('.')[2]]] = String(v.value); }
      }
      if (table === sw.acls) Object.assign(row, { bound: 2, origin: 1 });
      if (table === sw.aces) { row.slots = row.slots || {}; row.tuples = Object.keys(row.slots).sort((a, b) => a - b).map((k) => row.slots[k]); }
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
      const slots = a.slots || Object.fromEntries(a.tuples.map((t, n) => [n + 1, t]));
      for (const [n, t] of Object.entries(slots)) aclAces.push(R(i, 'rlQosAceTidxTuple' + n, Number(t)));
    }
    for (const [i, t] of sw.tuples) aclTuples.push(R(i, '5.1.2', t.type), R(i, '5.1.3', String(t.n1 || 0), (t.n1 || 0).toLocaleString('en-US')), R(i, '5.1.4', '', t.hex));
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
    ;({ aclModel, aclRuleView, decodeTuple, buildTupleMap, ipTupleHex, ipv6TupleHex, macTupleHex, ipv6ToHex, hexToIpv6, protoTupleHex, ACE_TUPLE_COLS,
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
const ruleCfg = (o) => Object.assign({ aclName: 'web', family: 'ip', action: 2, proto: 'any', src: { any: true }, dst: { any: false, ip: '10.1.2.0', pref: 24 } }, o);
// A rule as the fake switch holds it: action, type, and tuple pointers by slot.
const aceOf = (sw, key) => { const a = sw.aces.get(key); return a && { action: a.action, type: a.type, slots: a.slots }; };

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
  sw.tuples.set('13', { type: 20, n1: 3, hex: '' });   // an ICMP code on a UDP rule: the form cannot make it
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
  assert.deepEqual(plain(udp.unsupported), ['icmp code 3', 'an ICMP code with no type']);
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
  await api.createQosAce(s, ruleCfg({ aclName: 'new-list', proto: 'tcp' }));
  assert.equal(sw.acls.get('3').name, 'new-list');
  assert.equal(sw.acls.get('3').type, 2);
  assert.deepEqual(aceOf(sw, '3.1'), { action: 2, type: 2, slots: { 1: '13', 4: '14' } });
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
  assert.deepEqual(aceOf(sw, '1.1'), { action: 2, type: 1, slots: { 4: '13' } });
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
  sw.aces.get('1.1').slots = { 1: '10', 2: '11', 8: '12' };   // as the switch places protocol, source and flags
  const { api, s } = load(sw);
  await assert.rejects(api.editQosAce(s, '1', '1', ruleCfg()), /CommitFailed\. The original rule was put back\./);
  // Back in the slots it was read from, not packed into 1, 2, 3.
  assert.deepEqual(aceOf(sw, '1.1'), { action: 1, type: 2, slots: { 1: '10', 2: '11', 8: '12' } });
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

// Rules the switch made itself from the CLI on .253 and .254 (sbs-ref-ip,
// sbs-ref-v6 and ISE-PREAUTH), tuple for tuple: { type, slots: { slot: tuple } }
// and each tuple's { type, n1 (Value1), hex (Value2) }.
const switchMade = () => ({
  acls: { 1: { name: 'sbs-ref-ip' }, 2: { name: 'sbs-ref-v6', type: 3 }, 3: { name: 'sbs-ref-mac', type: 1 } },
  aces: {
    '1.20': { action: 1, type: 7, slots: { 1: '12', 4: '13', 5: '14' } },          // permit icmp any any 8 0
    '1.40': { action: 2, type: 1, slots: { 1: '15' } },                            // deny 47 any any
    '1.60': { action: 1, type: 2, slots: { 1: '16', 5: '17', 7: '18' } },          // permit tcp any any any 8000-8080
    '1.80': { action: 1, type: 3, slots: { 1: '19', 3: '20' } },                   // permit udp any 53 any any
    '1.90': { action: 1, type: 7, slots: { 1: '30', 3: '31' } },                   // permit icmp any host 192.168.10.69
    '1.100': { action: 1, type: 1, slots: { 4: '32' } },                           // permit ip any 10.1.2.0 0.0.0.255
    '1.120': { action: 1, type: 2, slots: { 1: '33', 3: '34', 6: '35' } },         // permit tcp any 1000-2000 any any
    '1.140': { action: 1, type: 3, slots: { 1: '36', 3: '37', 6: '38' } },         // permit udp any 5000-5010 any any
    '2.60': { action: 1, type: 9, slots: { 4: '39' } },                            // permit ipv6 any 2001:db8:1::/48
    '2.80': { action: 1, type: 11, slots: { 1: '40', 5: '41' } },                  // permit udp any any any 53
    '2.100': { action: 2, type: 9, slots: { 1: '42' } },                           // deny 47 any any
    '3.20': { action: 1, type: 5, slots: { 1: '43' } },                            // permit 00:11:22:33:44:55 00:00:00:ff:ff:ff any
    '3.40': { action: 2, type: 5, slots: { 2: '44' } },                            // deny any 01:00:5e:00:00:00 00:00:00:ff:ff:ff
    '3.60': { action: 1, type: 5, slots: { 3: '45' } },                            // permit any any vlan 1
    '2.20': { action: 1, type: 10, slots: { 1: '21', 2: '22', 5: '23' } },         // permit tcp 2001:db8::/32 any any 443
    '2.40': { action: 1, type: 13, slots: { 1: '24', 4: '25' } }                   // permit icmp any any 135 any
  },
  tuples: {
    12: { type: 1, n1: 0, hex: '01ff' }, 13: { type: 19, n1: 8, hex: '' }, 14: { type: 20, n1: 0, hex: '' },
    15: { type: 1, n1: 0, hex: '2fff' },
    16: { type: 1, n1: 0, hex: '06ff' }, 17: { type: 31, n1: 8000, hex: '' }, 18: { type: 32, n1: 8080, hex: '' },
    19: { type: 1, n1: 0, hex: '11ff' }, 20: { type: 6, n1: 53, hex: '0000' },
    30: { type: 1, n1: 0, hex: '01ff' }, 31: { type: 3, n1: 0, hex: 'c0a80a4500000000' },
    21: { type: 1, n1: 0, hex: '06ff' }, 22: { type: 23, n1: 0, hex: '20010db800000000000000000000000000000000ffffffffffffffffffffffff' }, 23: { type: 9, n1: 443, hex: '0000' },
    24: { type: 1, n1: 0, hex: '3aff' }, 25: { type: 19, n1: 135, hex: '' },
    32: { type: 3, n1: 0, hex: '0a010200000000ff' },
    33: { type: 1, n1: 0, hex: '06ff' }, 34: { type: 29, n1: 1000, hex: '' }, 35: { type: 30, n1: 2000, hex: '' },
    36: { type: 1, n1: 0, hex: '11ff' }, 37: { type: 25, n1: 5000, hex: '' }, 38: { type: 26, n1: 5010, hex: '' },
    39: { type: 24, n1: 0, hex: '20010db8000100000000000000000000000000000000ffffffffffffffffffff' },
    40: { type: 1, n1: 0, hex: '11ff' }, 41: { type: 7, n1: 53, hex: '0000' },
    42: { type: 1, n1: 0, hex: '2fff' },
    43: { type: 10, n1: 0, hex: '001122334455000000ffffff' }, 44: { type: 11, n1: 0, hex: '01005e000000000000ffffff' },
    45: { type: 12, n1: 1, hex: '' }
  }
});

test('switch-made ICMP, protocol number, port, range and IPv6 rules read back in full', () => {
  const sw = fakeSwitch(switchMade());
  for (const a of sw.aces.values()) a.tuples = Object.values(a.slots);
  const { api, s } = load(sw);
  const m = api.aclModel(s.health);
  const view = (k) => { const [l, r] = k.split('.'); return plain(api.aclRuleView(m.byIdx.get(l).aces.get(r), m.tupleMap)); };
  const pick = (v) => ({ proto: v.proto, src: v.src, dst: v.dst, extra: v.extra, unsupported: v.unsupported });
  assert.deepEqual(pick(view('1.20')), { proto: 'icmp', src: 'any', dst: 'any', extra: ['icmp type 8 code 0'], unsupported: [] });
  assert.deepEqual(pick(view('1.40')), { proto: 'protocol 47', src: 'any', dst: 'any', extra: [], unsupported: [] });
  assert.deepEqual(pick(view('1.60')), { proto: 'tcp', src: 'any', dst: 'any', extra: ['destination ports 8000-8080'], unsupported: [] });
  assert.deepEqual(pick(view('1.80')), { proto: 'udp', src: 'any', dst: 'any', extra: ['source port 53'], unsupported: [] });
  assert.deepEqual(pick(view('1.90')), { proto: 'icmp', src: 'any', dst: '192.168.10.69/32', extra: [], unsupported: [] });
  assert.deepEqual(pick(view('2.20')), { proto: 'tcp', src: '2001:db8::/32', dst: 'any', extra: ['destination port 443'], unsupported: [] });
  assert.deepEqual(pick(view('2.40')), { proto: 'icmp', src: 'any', dst: 'any', extra: ['icmp type 135'], unsupported: [] });
  assert.deepEqual(pick(view('1.100')), { proto: 'ip', src: 'any', dst: '10.1.2.0/24', extra: [], unsupported: [] });
  assert.deepEqual(pick(view('1.120')), { proto: 'tcp', src: 'any', dst: 'any', extra: ['source ports 1000-2000'], unsupported: [] });
  assert.deepEqual(pick(view('2.60')), { proto: 'ipv6', src: 'any', dst: '2001:db8:1::/48', extra: [], unsupported: [] });
  assert.deepEqual(pick(view('2.100')), { proto: 'protocol 47', src: 'any', dst: 'any', extra: [], unsupported: [] });
  assert.deepEqual(pick(view('3.20')), { proto: 'any', src: '00:11:22:33:44:55/24', dst: 'any', extra: [], unsupported: [] });
  assert.deepEqual(pick(view('3.40')), { proto: 'any', src: 'any', dst: '01:00:5e:00:00:00/24', extra: [], unsupported: [] });
  assert.deepEqual(pick(view('3.60')), { proto: 'any', src: 'any', dst: 'any', extra: ['vlan 1'], unsupported: [] });
  assert.equal(m.byIdx.get('2').family, 'ipv6');
  assert.equal(m.byIdx.get('3').family, 'mac');
  assert.deepEqual(view('1.60').init.dstPort, { from: 8000, to: 8080 });
  assert.deepEqual([view('1.40').init.proto, view('1.40').init.protoNum], ['num', 47]);
});

// The strongest check on the writes: each switch-made rule, opened in the
// editor and saved into an empty switch, comes out tuple for tuple and slot
// for slot the way the switch made it.
test('saving a switch-made rule from its editor values writes what the switch wrote', async () => {
  const ref = fakeSwitch(switchMade());
  for (const a of ref.aces.values()) a.tuples = Object.values(a.slots);
  const { api: refApi, s: refS } = load(ref);
  const m = refApi.aclModel(refS.health);
  const shape = (sw, ace) => Object.fromEntries(Object.entries(ace.slots).map(([slot, t]) => {
    const tu = sw.tuples.get(t); return [slot, { type: tu.type, n1: tu.n1 || 0, hex: tu.hex }];
  }));
  for (const [key, want] of ref.aces) {
    const [l, r] = key.split('.');
    const acl = m.byIdx.get(l);
    const init = plain(refApi.aclRuleView(acl.aces.get(r), m.tupleMap).init);
    const sw = fakeSwitch({});
    const { api, s } = load(sw);
    await api.createQosAce(s, Object.assign({ aclName: acl.name }, init));
    const got = sw.aces.get('1.1');
    assert.equal(sw.acls.get('1').type, acl.type, key + ' list type');
    assert.equal(got.type, want.type, key + ' rule type');
    assert.equal(got.action, want.action, key + ' action');
    assert.deepEqual(shape(sw, got), shape(ref, want), key + ' tuples');
  }
});

test('IPv6 addresses encode with a wildcard mask and read back short', () => {
  const { api } = load(fakeSwitch({}));
  assert.equal(api.ipv6TupleHex('2001:db8::', 32), '20010db8' + '0'.repeat(24) + '00000000' + 'f'.repeat(24));
  assert.equal(api.ipv6TupleHex('fe80::', 10), 'fe80' + '0'.repeat(28) + '003f' + 'f'.repeat(28));
  assert.equal(api.ipv6ToHex('::1'), '0'.repeat(31) + '1');
  assert.equal(api.ipv6ToHex('1:2:3:4:5:6:7:8:9'), null);
  assert.equal(api.ipv6ToHex('2001:db8::1::2'), null);
  assert.equal(api.hexToIpv6('0'.repeat(32)), '::');
  assert.equal(api.hexToIpv6('20010db8000000010000000000000001'), '2001:db8:0:1::1');
  assert.equal(api.decodeTuple({ type: 24, v2: '20010db8000100000000000000000001' + '0'.repeat(32) }).text, '2001:db8:1::1/128');
});

test('MAC addresses encode with a wildcard, and an odd wildcard is not edited', () => {
  const { api } = load(fakeSwitch({}));
  assert.equal(api.macTupleHex('00-11-22-33-44-55', 24), '001122334455000000ffffff');
  assert.equal(api.macTupleHex('0011.2233.4455', 48), '001122334455000000000000');
  assert.equal(api.macTupleHex('00:11:22', 48), null);
  const odd = api.decodeTuple({ type: 10, v2: '001122334455ff00ff00ff00' });
  assert.equal(odd.text, '00:11:22:33:44:55 ignoring ff:00:ff:00:ff:00');
  assert.equal(odd.oddMask, true);
});
