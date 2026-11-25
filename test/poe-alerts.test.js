'use strict';

// PoE fault alerting (health.buildAlerts). A detection fault on a port is
// raised unless the port's link is up: then the device on it has its own power
// and is not a PD, so the fault says nothing about it. The live fixture
// (test/fixtures/live) covers the same case on a real switch: gi1/0/3 is
// linked to a non-PD and reports fault (4), and raises nothing.
const test = require('node:test');
const assert = require('node:assert/strict');
const { buildAlerts, TABLE_WALKS } = require('../health');

// Every walked table empty (as collect() starts them), plus the lists
// buildAlerts reads that are not walks of their own.
const empty = () => {
  const h = { scalars: {} };
  for (const k of Object.keys(TABLE_WALKS)) h[k] = [];
  for (const k of ['dot1xHosts', 'dot1xLocked', 'mgmtSessions', 'sshSessions', 'telnetSessions', 'pvstInconsistencies']) h[k] = h[k] || [];
  return h;
};
const poePort = (port, status) => ({
  index: '1.' + port, portIndex: String(port),
  pethPsePortDetectionStatus: { value: status === 'fault' ? 4 : 2, display: status + ' (' + (status === 'fault' ? 4 : 2) + ')' }
});
const iface = (ix, up) => ({ index: ix, rlifPresentOperStatus: { value: up ? 1 : 2, display: up ? 'up (1)' : 'down (2)' } });
const poeAlerts = (h) => buildAlerts(h).filter((a) => a.area === 'PoE');

test('a PoE fault on a port with no link is raised', () => {
  const h = empty();
  h.poePorts = [poePort(3, 'fault')];
  h.interfaces = [iface(3, false)];
  const a = poeAlerts(h);
  assert.equal(a.length, 1);
  assert.equal(a[0].severity, 'critical');
  assert.match(a[0].message, /Port 1\.3 PoE detection reports fault/);
});

test('a PoE fault on a port linked to a non-PD is not raised', () => {
  const h = empty();
  h.poePorts = [poePort(3, 'fault')];
  h.interfaces = [iface(3, true)];
  assert.deepEqual(poeAlerts(h), []);
});

test('a port that is only searching raises nothing', () => {
  const h = empty();
  h.poePorts = [poePort(4, 'searching')];
  h.interfaces = [iface(4, false)];
  assert.deepEqual(poeAlerts(h), []);
});
