'use strict';

// collectHealthFor gives up at once on a switch that does not answer SNMP,
// instead of timing out table by table and reporting an empty "complete"
// collection; a switch that answers is collected as before.
const test = require('node:test');
const assert = require('node:assert/strict');
const dgram = require('dgram');
const snmp = require('net-snmp');
const { collectHealthFor } = require('../collection');

test('a switch that never answers SNMP fails fast with a clear error', async () => {
  const sink = dgram.createSocket('udp4');   // receives, never replies (like an SNMP host filter)
  await new Promise((r) => sink.bind(0, '127.0.0.1', r));
  const port = sink.address().port;
  const started = Date.now();
  try {
    await assert.rejects(
      collectHealthFor({ host: '127.0.0.1', port, version: '2c', community: 'x', timeout: 300, retries: 0 }),
      /did not answer SNMP/);
    assert.ok(Date.now() - started < 3000, 'gave up within seconds');
  } finally {
    sink.close();
  }
});

test('a switch that answers is collected', async () => {
  const port = 20000 + Math.floor(Math.random() * 20000);
  const agent = snmp.createAgent({ port, address: '127.0.0.1', disableAuthorization: true,
    accessControlModelType: snmp.AccessControlModelType.None }, () => {});
  const mib = agent.getMib();
  mib.registerProvider({ name: 'sysUpTime', type: snmp.MibProviderType.Scalar, oid: '1.3.6.1.2.1.1.3',
    scalarType: snmp.ObjectType.TimeTicks, maxAccess: snmp.MaxAccess['read-only'] });
  mib.setScalarValue('sysUpTime', 4242);
  agent.getAuthorizer().addCommunity('x');
  try {
    const data = await collectHealthFor({ host: '127.0.0.1', port, version: '2c', community: 'x', timeout: 500, retries: 0 },
      { only: ['scalars'] });
    assert.ok(data && !data.error);
  } finally {
    agent.close();
  }
});
