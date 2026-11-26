'use strict';
// The QoS reader and writes (switch-qos.js) against a fake SNMP session.
const test = require('node:test');
const assert = require('node:assert/strict');
const snmp = require('net-snmp');
const qos = require('../switch-qos');
const { fakeSession } = require('./support/fake-snmp');

const T = snmp.ObjectType;
const int = (n) => [T.Integer, n];
const V = '1.3.6.1.4.1.9.6.1.101';
const STORM = V + '.77.12.1';

// The rows .253 made for the CLI samples on gi1/0/4 (ifIndex 4): rate-limit
// 64000, traffic-shape 64000, traffic-shape queue 3 64000 and qos map
// dscp-queue 10 to 6. Port 3 is left as the switch ships it.
function sample() {
  const v = {};
  for (const c of [2, 3, 4, 7]) v[qos.T.modeCfg + '.' + c + '.1'] = int({ 2: 2, 3: 2, 4: 3, 7: 1 }[c]);
  for (const ifx of [3, 4]) {
    v[V + '.54.43.1.3.' + ifx] = int(6);
    const p = (c, x) => { v[qos.T.ifPolicy + '.' + c + '.' + ifx + '.2'] = x; };
    p(5, int(2)); p(6, int(ifx === 4 ? 2 : 1)); p(7, int(ifx === 4 ? 64000 : 0)); p(8, int(128000));
    p(10, [T.OctetString, Buffer.from('default')]); p(11, int(ifx === 4 ? 1 : 0));
    v[STORM + '.2.' + ifx + '.6'] = [T.Gauge, ifx === 4 ? 64000 : 0];
  }
  for (let q = 1; q <= 8; q++) {
    v[qos.T.shapeProfile + '.' + (2 * q) + '.1'] = int(q === 3 ? 64000 : 0);
    v[qos.T.shapeProfile + '.' + (2 * q + 1) + '.1'] = int(128000);
    v[qos.T.queueProfile + '.' + (2 * q) + '.7.100.101.102.97.117.108.116'] = int(1);
    v[qos.T.queueProfile + '.' + (2 * q + 1) + '.7.100.101.102.97.117.108.116'] = int(q);
  }
  v[qos.T.shapeProfile + '.18.1'] = int(1);
  for (const [c, q] of [[0, 1], [5, 7], [7, 6]]) {
    v[qos.T.cosQueue + '.2.' + c] = int(q);
    v[qos.T.cosDefault + '.1.' + c] = int(c); v[qos.T.cosDefault + '.2.' + c] = int(q);
  }
  for (const [d, q, def] of [[9, 2, 2], [10, 6, 2], [46, 8, 8]]) {
    v[qos.T.dscpQueue + '.2.' + d] = int(q);
    v[qos.T.dscpDefault + '.1.' + d] = int(d); v[qos.T.dscpDefault + '.2.' + d] = int(def);
  }
  return v;
}

const pdus = (s) => s.sets.map((vbs) => vbs.map((x) => x.oid.replace(V, 'V') + '=' + x.value));

test('readQos gives the mode, each port, the queue shapers and the maps with their defaults', async () => {
  const r = await qos.readQos(fakeSession(sample()));
  assert.deepEqual([r.mode, r.basicTrust, r.advancedTrust], ['basic', 'dscp', 'cos-dscp']);
  assert.deepEqual(r.ports, [
    { ifIndex: 3, trust: true, shaper: { on: false, cir: 0, cbs: 128000 }, rateLimit: 0, queueProfile: 'default', queueShaper: null },
    { ifIndex: 4, trust: true, shaper: { on: true, cir: 64000, cbs: 128000 }, rateLimit: 64000, queueProfile: 'default',
      queueShaper: { profile: 1, queues: [{ queue: 3, cir: 64000, cbs: 128000 }] } }
  ]);
  assert.deepEqual(r.scheduling.map((p) => [p.name, p.queues[0].type, p.queues.length]), [['default', 'ef', 8]]);
  assert.deepEqual(r.cosMap, [{ cos: 0, queue: 1, default: 1 }, { cos: 5, queue: 7, default: 7 }, { cos: 7, queue: 6, default: 6 }]);
  assert.deepEqual(r.dscpMap.map((m) => [m.dscp, m.queue, m.default]), [[9, 2, 2], [10, 6, 2], [46, 8, 8]]);
});

test('the writes send the columns the switch filled for the CLI', async () => {
  const s = fakeSession(sample());
  await qos.setMode(s, 'advanced');
  await qos.setTrust(s, 'dscp');
  await qos.setMode(s, 'basic');
  await qos.setTrust(s, 'cos');
  await qos.setPortTrust(s, 3, false);
  await qos.setPortShaper(s, 3, 1000);
  await qos.setPortShaper(s, 3, 0);
  await qos.setRateLimit(s, 3, 500);
  const made = await qos.setQueueShaper(s, 3, 2, 2000, 8192);
  const gone = await qos.setQueueShaper(s, 4, 3, 0);
  await qos.setCosQueue(s, 5, 3);
  await qos.setDscpQueue(s, 10, 4);
  assert.equal(made.profile, 2);
  assert.equal(gone.profileRemoved, true);
  const q2 = [];
  for (let k = 1; k <= 8; k++) q2.push('V.88.23.1.' + (2 * k) + '.2=' + (k === 2 ? 2000 : 0), 'V.88.23.1.' + (2 * k + 1) + '.2=' + (k === 2 ? 8192 : 128000));
  assert.deepEqual(pdus(s), [
    ['V.88.46.1.2.1=3'],
    ['V.88.46.1.4.1=2'],
    ['V.88.46.1.2.1=2'],
    ['V.88.46.1.3.1=1'],
    ['V.88.13.1.5.3.2=1'],
    ['V.88.13.1.6.3.2=2', 'V.88.13.1.7.3.2=1000', 'V.88.13.1.8.3.2=128000'],
    ['V.88.13.1.6.3.2=1'],
    ['V.77.12.1.2.3.6=500'],
    ['V.88.23.1.18.2=4'].concat(q2),
    ['V.88.13.1.11.3.2=2'],
    ['V.88.23.1.6.1=0', 'V.88.23.1.7.1=128000'],
    ['V.88.13.1.11.4.2=0'],
    ['V.88.23.1.18.1=6'],
    ['V.88.17.1.2.5=3'],
    ['V.88.18.1.2.10=4']
  ]);
});

test('restoreMap writes back only the entries that differ from the defaults', async () => {
  const s = fakeSession(sample());
  assert.deepEqual(await qos.restoreMap(s, 'dscp'), { map: 'dscp', changed: 1 });
  assert.deepEqual(await qos.restoreMap(s, 'cos'), { map: 'cos', changed: 0 });
  assert.deepEqual(pdus(s), [['V.88.18.1.2.10=2']]);
});

test('a refused form is undone and the next one tried', async () => {
  const s = fakeSession(sample(), { refuse: (vbs) => (vbs.length === 3 && vbs[0].oid.includes('.88.13.1.6.') ? 'WrongValue' : null) });
  const r = await qos.setPortShaper(s, 3, 1000, 4096);
  assert.equal(r.via, 'rate and burst, then status');
  assert.deepEqual(r.refused, ['status, rate and burst together: WrongValue']);
  assert.deepEqual(pdus(s).slice(-3), [['V.88.13.1.6.3.2=1'], ['V.88.13.1.7.3.2=1000', 'V.88.13.1.8.3.2=4096'], ['V.88.13.1.6.3.2=2']]);
});

test('the writes refuse values the switch would not take', async () => {
  const s = fakeSession(sample());
  await assert.rejects(qos.setMode(s, 'fast'), /mode must be/);
  await assert.rejects(qos.setTrust(s, 'ip'), /trust must be/);
  await assert.rejects(qos.setPortShaper(s, 1000, 64), /front-panel port/);
  await assert.rejects(qos.setPortShaper(s, 3, 10), /64 to 10000000/);
  await assert.rejects(qos.setPortShaper(s, 3, 1000, 100), /burst size/);
  await assert.rejects(qos.setRateLimit(s, 3, -1), /rate limit/);
  await assert.rejects(qos.setQueueShaper(s, 3, 9, 1000), /queue must be 1 to 8/);
  await assert.rejects(qos.setCosQueue(s, 8, 1), /CoS must be 0 to 7/);
  await assert.rejects(qos.setDscpQueue(s, 10, 0), /queue must be 1 to 8/);
  await assert.rejects(qos.restoreMap(s, 'ip'), /map must be/);
  assert.equal(s.sets.length, 0);
});
