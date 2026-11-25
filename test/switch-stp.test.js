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

test('the writes send the columns for the switch, VLAN, instance and port', async () => {
  const s = fakeSession(sample());
  await stp.setEnabled(s, false);
  await stp.setMode(s, 'mstp');
  await stp.setBridgePriority(s, 8192);
  await stp.setBridgePriority(s, 4096, { vlan: 10 });
  await stp.setBridgePriority(s, 0, { instance: 1 });
  await stp.setPort(s, 5, { priority: 64, cost: 0, edge: false, bpduGuard: false });
  await stp.setPortIn(s, { vlan: 10 }, 5, { cost: 200 });
  await stp.setPortIn(s, { instance: 1 }, 5, { priority: 32 });
  const V = '1.3.6.1.4.1.9.6.1.101';
  assert.deepEqual(s.sets.map((vbs) => vbs.map((v) => v.oid.replace(V, 'V') + '=' + v.value)), [
    ['V.57.2.3.0=2'],
    ['1.3.6.1.2.1.17.2.16.0=3'],
    ['1.3.6.1.2.1.17.2.2.0=8192'],
    ['V.57.9.1.1.5.10=4096'],
    ['V.57.6.1.1.12.1=0'],
    ['1.3.6.1.2.1.17.2.15.1.2.5=64'], ['1.3.6.1.2.1.17.2.19.1.6.5=0'], ['1.3.6.1.2.1.17.2.19.1.2.5=2'], ['V.57.2.24.1.1.5=2'],
    ['V.57.9.3.1.3.10.5=200'],
    ['V.57.6.2.1.3.1.5=32']
  ]);
});

test('the writes refuse values the switch would not take', async () => {
  const s = fakeSession(sample());
  await assert.rejects(stp.setMode(s, 'fast'), /mode must be/);
  await assert.rejects(stp.setBridgePriority(s, 1000), /steps of 4096/);
  await assert.rejects(stp.setPort(s, 5, { priority: 100 }), /steps of 16/);
  await assert.rejects(stp.setPort(s, 5, {}), /Nothing to change/);
  await assert.rejects(stp.setPortIn(s, {}, 5, { cost: 1 }), /Name a vlan/);
  assert.equal(s.sets.length, 0);
});
