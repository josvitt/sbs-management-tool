'use strict';
// The spanning tree settings reader and writes (switch-stp.js) against a fake SNMP session.
const test = require('node:test');
const assert = require('node:assert/strict');
const snmp = require('net-snmp');
const stp = require('../switch-stp');
const { fakeSession } = require('./support/fake-snmp');

const int = (n) => [snmp.ObjectType.Integer, n];

function sample() {
  const v = {};
  const S = stp.SCALARS;
  v[S.enable] = int(1);
  v[S.version] = int(8);
  v[S.priority] = int(32768);
  // ifIndex 5 is a present Ethernet port; the bridge tables also carry a row
  // for port 300, which is not present and is not read.
  v[require('../switch-ports').PRESENT_TYPE + '.5'] = int(6);
  v[require('../switch-ports').PRESENT_TYPE + '.300'] = int(1);
  v[stp.STP_PORT + '.2.300'] = int(128);
  v[stp.BASE_PORT + '.2.300'] = int(300);
  // Bridge port 5 is ifIndex 5: PortFast on, BPDU guard on, cost automatic.
  v[stp.BASE_PORT + '.2.5'] = int(5);
  v[stp.STP_PORT + '.2.5'] = int(128);
  v[stp.STP_PORT + '.4.5'] = int(1);
  v[stp.STP_PORT + '.5.5'] = int(20000);
  v[stp.STP_EXT + '.2.5'] = int(1);
  v[stp.STP_EXT + '.3.5'] = int(1);
  v[stp.STP_EXT + '.4.5'] = int(2);
  v[stp.STP_EXT + '.6.5'] = int(0);
  v[stp.RL_PORT + '.7.5'] = int(5);
  v[stp.RL_PORT + '.10.5'] = int(2);
  v[stp.BPDU_GUARD + '.1.5'] = int(1);
  // VLAN 10 at priority 4096, with port 5 at cost 100.
  v[stp.PVST_VLAN + '.5.10'] = int(4096);
  v[stp.PVST_VLAN + '.6.10'] = int(1);
  v[stp.PVST_PORT + '.3.10.5'] = int(100);
  v[stp.PVST_PORT + '.4.10.5'] = int(128);
  return v;
}

test('readStp reads the mode, priorities and port settings', async () => {
  const r = await stp.readStp(fakeSession(sample()));
  assert.equal(r.enabled, true);
  assert.equal(r.mode, 'rapid-pvst');
  assert.equal(r.priority, 32768);
  assert.deepEqual(r.ports, [{ port: 5, ifIndex: 5, enabled: true, priority: 128, cost: 20000, adminCost: 0, edge: true,
    autoEdge: false, operEdge: true, p2p: 'auto', bpduGuard: true, rootGuard: null, tcnGuard: null, filterBpdu: null, role: 'designated' }]);
  assert.deepEqual(r.vlans.map((x) => [x.vlan, x.priority, x.ports]), [[10, 4096, [{ port: 5, cost: 100, priority: 128, rowStatus: null }]]]);
  assert.deepEqual(r.instances, []);
});

test('the writes send the columns for the switch and the port', async () => {
  const s = fakeSession(sample());
  await stp.setEnabled(s, false);
  await stp.setMode(s, 'mstp');
  await stp.setBridgePriority(s, 8192);
  await stp.setPort(s, 5, { priority: 64, cost: 0, edge: false, autoEdge: true, bpduGuard: false, enabled: false });
  const V = '1.3.6.1.4.1.9.6.1.101';
  assert.deepEqual(s.sets.map((vbs) => vbs.map((v) => v.oid.replace(V, 'V') + '=' + v.value)), [
    ['V.57.2.3.0=2'],
    ['1.3.6.1.2.1.17.2.16.0=3'],
    ['1.3.6.1.2.1.17.2.2.0=8192'],
    ['1.3.6.1.2.1.17.2.15.1.4.5=2'], ['1.3.6.1.2.1.17.2.15.1.2.5=64'], ['1.3.6.1.2.1.17.2.19.1.6.5=0'],
    ['1.3.6.1.2.1.17.2.19.1.2.5=2'], ['V.57.2.13.1.10.5=1'], ['V.57.2.24.1.1.5=2']
  ]);
});

test('the writes refuse values the switch would not take', async () => {
  const s = fakeSession(sample());
  await assert.rejects(stp.setMode(s, 'fast'), /mode must be/);
  await assert.rejects(stp.setBridgePriority(s, 1000), /steps of 4096/);
  await assert.rejects(stp.setPort(s, 5, { priority: 100 }), /steps of 16/);
  await assert.rejects(stp.setPort(s, 5, {}), /Nothing to change/);
  assert.equal(s.sets.length, 0);
});

test('a refused port setting names itself and what was already set', async () => {
  const s = fakeSession(sample(), { refuse: (vbs) => (vbs[0].oid.indexOf(stp.BPDU_GUARD) === 0 ? 'NotWritable' : null) });
  await assert.rejects(stp.setPort(s, 5, { edge: true, bpduGuard: true }), /NotWritable \(1\.3\.6\.1\.4\.1\.9\.6\.1\.101\.57\.2\.24\.1\.1\.5; already set: 1\.3\.6\.1\.2\.1\.17\.2\.19\.1\.2\.5\)/);
});
