'use strict';
// The port features reader (switch-ports.js) against a fake SNMP session.
const test = require('node:test');
const assert = require('node:assert/strict');
const snmp = require('net-snmp');
const ports = require('../switch-ports');
const { fakeSession } = require('./support/fake-snmp');

const T = snmp.ObjectType;
const int = (n) => [T.Integer, n];
const str = (s) => [T.OctetString, Buffer.from(s)];

function sample() {
  const v = {};
  const S = ports.SCALARS;
  v[S.errdisInterval] = int(300);
  v[S.lldp] = int(1);
  v[S.cdp] = int(2);
  v[S.eee] = int(1);
  // PoE on port 1.5: on, delivering, high, 7.5 W of a 30 W limit.
  v[ports.PETH + '.3.1.5'] = int(1);
  v[ports.PETH + '.6.1.5'] = int(3);
  v[ports.PETH + '.7.1.5'] = int(2);
  v[ports.PETH + '.10.1.5'] = int(4);
  v[ports.RL_PETH + '.5.1.5'] = int(7500);
  v[ports.RL_PETH + '.6.1.5'] = int(30000);
  v[ports.RL_PETH + '.9.1.5'] = int(30000);
  v[ports.RL_PETH + '.13.1.5'] = int(3);
  // Port security on ifIndex 5: locked, 3 of 10 addresses, dynamic.
  v[ports.SWIF + '.8.5'] = int(1);
  v[ports.SWIF + '.9.5'] = int(1);
  v[ports.SWIF + '.37.5'] = int(2);
  v[ports.SWIF + '.38.5'] = int(10);
  v[ports.SWIF + '.39.5'] = int(3);
  v[ports.SWIF + '.40.5'] = int(99);   // the next column, past the walk
  // ifIndex 5 is a present Ethernet port; 1000 is a port channel.
  v[ports.PRESENT_TYPE + '.5'] = int(6);
  v[ports.PRESENT_TYPE + '.1000'] = int(161);
  v[ports.SWIF + '.8.1000'] = int(2);
  // Storm control on ifIndex 5: broadcast at 10000.
  v[ports.STORM + '.2.5.1'] = [T.Gauge, 10000];
  v[ports.STORM + '.3.5.1'] = int(2);
  v[ports.STORM + '.4.5.1'] = int(1);
  // Errdisable: port-security recovery on; ifIndex 7 shut by BPDU guard.
  v[ports.ERRDIS + '.2.1.2.2'] = int(1);
  v[ports.ERRDIS + '.2.1.2.5'] = int(2);
  v[ports.ERRDIS + '.3.1.1.7'] = int(5);
  v[ports.ERRDIS + '.3.1.2.7'] = int(1);
  v[ports.ERRDIS + '.3.1.3.7'] = int(120);
  v[ports.LLDP_PORTS + '.2.5'] = int(3);
  v[ports.CDP_IF + '.2.5'] = int(1);
  v[ports.EEE_PORTS + '.1.5'] = int(1);
  v[ports.EEE_PORTS + '.4.5'] = int(2);
  // Mirroring: session 1 to ifIndex 24, both directions of ifIndex 5.
  v[ports.SPAN_DEST + '.2.1'] = int(24);
  v[ports.SPAN_DEST + '.3.1'] = int(1);
  v[ports.SPAN_DEST + '.4.1'] = int(2);
  v[ports.SPAN_DEST + '.6.1'] = int(1);
  v[ports.SPAN_SRC + '.4.1.1.5'] = int(3);
  v[ports.SPAN_SRC + '.5.1.1.5'] = int(1);
  // A cable length test on ifIndex 5 and an SFP reading that is not shown.
  v[ports.PHY_GET + '.2.5.4'] = int(2);
  v[ports.PHY_GET + '.3.5.4'] = int(12);
  v[ports.PHY_GET + '.6.5.4'] = str('25-Nov-2026 10:00:00');
  v[ports.PHY_GET + '.2.25.5'] = int(2);
  return v;
}

test('readPorts reads PoE, security, storm control, errdisable, discovery, EEE, mirroring and cable tests', async () => {
  const r = await ports.readPorts(fakeSession(sample()));
  assert.deepEqual(r.poe, [{ group: 1, port: 5, admin: true, detection: 'deliveringPower', priority: 'high', powerClass: 4,
    powerMw: 7500, limitMw: 30000, operLimitMw: 30000, poeType: 'poeplus' }]);
  assert.deepEqual(r.security, [{ ifIndex: 5, locked: true, operLocked: true, mode: 'dynamic', maxMacs: 10, macCount: 3 }]);
  assert.deepEqual(r.ports, [5]);
  assert.deepEqual(r.storm, [{ ifIndex: 5, traffic: { broadcast: { rate: 10000, unit: 2, action: 1 } } }]);
  assert.equal(r.errdisable.intervalSec, 300);
  assert.deepEqual(r.errdisable.causes.map((c) => [c.cause, c.recover]), [['port-security', true], ['stp-bpdu-guard', false]]);
  assert.deepEqual(r.errdisable.ports, [{ ifIndex: 7, reason: 'stp-bpdu-guard', recover: true, secondsLeft: 120 }]);
  assert.deepEqual(r.lldp, { enabled: true, ports: [{ port: 5, admin: 'txAndRx' }] });
  assert.deepEqual(r.cdp, { enabled: false, ports: [{ ifIndex: 5, on: true }] });
  assert.deepEqual(r.eee.ports, [{ ifIndex: 5, admin: true, remote: null, oper: false }]);
  assert.deepEqual(r.mirror.destinations, [{ session: 1, ifIndex: 24, reflector: 'span', portType: 'network', remoteVlan: null, rowStatus: 1 }]);
  assert.deepEqual(r.mirror.sources, [{ session: 1, type: 'port', index: 5, direction: 'both', rowStatus: 1 }]);
  assert.deepEqual(r.cableTests, [{ ifIndex: 5, test: 'cableLength', status: 'success', result: 12, units: null, at: '25-Nov-2026 10:00:00' }]);
});

test('readPorts returns empty parts when the switch has none of the tables', async () => {
  const r = await ports.readPorts(fakeSession({}));
  assert.deepEqual(r.poe, []);
  assert.deepEqual(r.mirror, { destinations: [], sources: [] });
  assert.equal(r.lldp.enabled, null);
});
