'use strict';

// Offline tests for write paths that had none: RADIUS and TACACS+ plans
// (aaa.js), the syslog collector setup (syslog-config.js), VLAN create and
// delete (08-vlans.js) and the static route SET (15-ipv4-addressing.js).
// Each checks the exact varbinds the switch accepted in the live tests.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const snmp = require('net-snmp');
const aaa = require('../aaa');
const syslogConfig = require('../syslog-config');

const SRC = path.join(__dirname, '..', 'public', 'src');
const read = (f) => fs.readFileSync(path.join(SRC, f), 'utf8');
const plain = (x) => JSON.parse(JSON.stringify(x));
const slice = (src, from, to) => src.slice(src.indexOf(from), to ? src.indexOf(to) : undefined);

// ---- AAA ----

test('a new RADIUS server is created in one PDU, RowStatus last', () => {
  const p = aaa.planRadius({ address: '10.1.2.3', key: 'k', priority: 2 });
  assert.equal(p.index, '1.4.10.1.2.3.1812.1813');
  const cols = p.varbinds.map((v) => Number(v.oid.slice(aaa.RADIUS.length + 1).split('.')[0]));
  assert.deepEqual(cols, [aaa.RCOL.addressType, aaa.RCOL.address, aaa.RCOL.priority, aaa.RCOL.useGlobalKey, aaa.RCOL.key, aaa.RCOL.rowStatus]);
  assert.equal(p.varbinds[1].valueHex, '0a010203');
  assert.equal(p.varbinds.at(-1).value, aaa.ROW.createAndGo);
});

test('editing a RADIUS server leaves the index columns and blank fields alone', () => {
  const p = aaa.planRadius({ address: '10.1.2.3', edit: true, timeout: '', retries: null, priority: '' });
  assert.deepEqual(p.varbinds.map((v) => v.value), [aaa.ROW.active]);
});

test('a TACACS+ delete is one destroy on the address index', () => {
  const vbs = aaa.planTacacsDelete('192.168.1.9');
  assert.deepEqual(plain(vbs), [{ oid: aaa.TACACS + '.' + aaa.TCOL.rowStatus + '.1.4.192.168.1.9', type: 'Integer', value: aaa.ROW.destroy }]);
});

test('a RADIUS server address must be IPv4', () => {
  assert.throws(() => aaa.planRadius({ address: 'fe80::1' }), /IPv4/);
});

// ---- syslog collector ----

// A stand-in session: empty tables, refuses what `refuse(varbinds)` says.
function fakeSession(refuse) {
  const sets = [];
  return {
    sets,
    on() {}, close() {},
    subtree(base, n, feed, done) { done(); },
    get(oids, cb) { cb(null, oids.map((oid) => ({ oid, type: snmp.ObjectType.Integer, value: 1 }))); },
    set(vbs, cb) {
      sets.push(vbs.map((v) => ({ oid: v.oid, type: v.type })));
      const why = refuse && refuse(vbs);
      if (why) return cb(new Error(why));
      cb(null, vbs);
    }
  };
}

test('the syslog row goes to the first table, port as Unsigned32, in one PDU', async () => {
  const session = fakeSession();
  const r = await syslogConfig.addCollector(() => session, { host: 'sw', address: '10.0.0.5', port: 514, severity: 6 });
  assert.equal(r.table, 'snmpSyslogCollectorTable');
  assert.equal(r.method, 'single-PDU createAndGo');
  const port = session.sets[0].find((v) => v.oid.startsWith(syslogConfig.TABLES[0].entry + '.5.'));
  assert.equal(port.type, snmp.ObjectType.Unsigned32);
});

test('a WrongType on the port column is retried with INTEGER', async () => {
  const session = fakeSession((vbs) => (vbs.some((v) => v.type === snmp.ObjectType.Unsigned32) ? 'WrongType' : null));
  const r = await syslogConfig.addCollector(() => session, { host: 'sw', address: '10.0.0.5' });
  assert.equal(r.table, 'snmpSyslogCollectorTable');
  assert.ok(session.sets.some((s) => s.some((v) => v.oid.startsWith(syslogConfig.TABLES[0].entry + '.5.') && v.type === snmp.ObjectType.Integer)));
});

test('when every table refuses, the error names each one', async () => {
  const session = fakeSession(() => 'NoCreation');
  await assert.rejects(syslogConfig.addCollector(() => session, { host: 'sw', address: '10.0.0.5' }),
    (e) => /snmpSyslogCollectorTable/.test(e.message) && /rlRegisteredLogsSyslogCollectorTable/.test(e.message) && /logging host 10\.0\.0\.5/.test(e.message));
});

// ---- VLANs ----

function loadVlans(listHex) {
  const sets = [];
  const ctx = {
    console, sets,
    appLog: () => {},
    snmpGet: async () => [{ display: listHex }],
    snmpSet: async (s, vb) => { sets.push(vb); },
    isManagementIf: () => false,
    teardownSvi: async () => {},
    vlanSviIfIndex: async () => null
  };
  vm.createContext(ctx);
  const pc = read('10-port-channels.js');
  const v = read('08-vlans.js');
  const api = vm.runInContext(
    slice(pc, '  function setPortBit', '  // Decode a PortList bitmap') +
    slice(v, '  const VLAN_LIST_OIDS', '  // Refresh the panels that show VLANs') +
    '\n;({ createVlan, deleteVlan })', ctx);
  return { api, sets };
}

test('creating VLAN 10 sets its bit in the full-width static list, then names it', async () => {
  const { api, sets } = loadVlans('80');   // VLAN 1 only, short display
  const r = await api.createVlan({ target: {}, host: 'sw' }, 10, 'staff');
  assert.equal(r.ok, true);
  assert.equal(sets[0].oid, '1.3.6.1.4.1.9.6.1.101.48.69.1.2.0');
  assert.equal(sets[0].valueHex.length, 256);
  assert.equal(sets[0].valueHex.slice(0, 4), '8040');   // VLAN 1 kept, VLAN 10 added
  assert.deepEqual(plain(sets[1]), { oid: 'dot1qVlanStaticName.10', type: 'OctetString', value: 'staff' });
});

test('deleting VLAN 1027 clears its bit in the second block', async () => {
  const { api, sets } = loadVlans('20'.padEnd(256, '0'));   // bit 3 of block 2 = VLAN 1027
  const r = await api.deleteVlan({ target: {}, host: 'sw' }, 1027);
  assert.equal(r.ok, true);
  assert.equal(sets[0].oid, '1.3.6.1.4.1.9.6.1.101.48.69.1.3.0');
  assert.equal(sets[0].valueHex, '0'.repeat(256));
});

test('VLAN 1 cannot be deleted', async () => {
  const { api, sets } = loadVlans('80');
  const r = await api.deleteVlan({ target: {}, host: 'sw' }, 1);
  assert.equal(r.ok, false);
  assert.equal(sets.length, 0);
});

// ---- static route ----

test('a static route is one PDU on dest.mask.0.nextHop', () => {
  const ctx = {};
  vm.createContext(ctx);
  const core = read('01-core.js');
  const ip = read('15-ipv4-addressing.js');
  const fn = vm.runInContext(
    slice(core, '  function ipToOidIndex', '  // Encode a string as a length-prefixed') +
    slice(ip, '  // The SET that adds a static route', '  function openStaticRouteForm') +
    '\n;staticRouteVarbinds', ctx);
  const sfx = '10.20.0.0.255.255.0.0.0.192.168.1.1';
  assert.deepEqual(plain(fn('10.20.0.0', '255.255.0.0', '192.168.1.1', 5)), [
    { oid: '1.3.6.1.4.1.9.6.1.101.26.17.1.1.6.' + sfx, type: 'Integer', value: 4 },
    { oid: '1.3.6.1.4.1.9.6.1.101.26.17.1.1.5.' + sfx, type: 'Integer', value: 5 },
    { oid: '1.3.6.1.4.1.9.6.1.101.26.17.1.1.9.' + sfx, type: 'Integer', value: 4 }
  ]);
});
