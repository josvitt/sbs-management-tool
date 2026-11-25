'use strict';

/**
 * Run the app's own collection against a recorded switch (fakeSession), and
 * digest what it produced, table by table. Used by scripts/record-switch.js
 * to write the expected digest and by test/live-agent.test.js to check it.
 */

const crypto = require('crypto');
const { setSessionFactory } = require('../../snmp-core');
const { collectHealthFor } = require('../../collection');
const { collectModulesFor } = require('../../module-collection');
const { fakeSession } = require('./snmp-recording');

// label: the fixture's name. It becomes the stand-in address, so each
// recording keeps its own previous-collection state (rates) in one process.
async function replayAgent(varbinds, label) {
  const target = { host: 'recorded-' + (label || 'switch'), port: 161, version: '2c', community: 'recorded' };
  const counter = {};
  setSessionFactory(() => fakeSession(varbinds, counter));
  try {
    const health = await collectHealthFor(target, {});
    const healthRequests = Object.assign({}, counter);
    for (const k of Object.keys(counter)) counter[k] = 0;
    const modules = await collectModulesFor(target, ['snmpConfig', 'flash', 'captures', 'maint', 'system']);
    return { health, modules, requests: { health: healthRequests, modules: Object.assign({}, counter) } };
  } finally {
    setSessionFactory(null);
  }
}

const hash = (v) => crypto.createHash('sha256').update(JSON.stringify(v)).digest('hex').slice(0, 16);
const VOLATILE = new Set(['collectedAt', 'at', 'ms', 'durationMs', 'readAt']);
const stable = (v) => JSON.parse(JSON.stringify(v, (k, x) => (VOLATILE.has(k) ? undefined : x)));

function digestOutputs(o) {
  const d = { health: {}, modules: {}, rows: {} };
  for (const k of Object.keys(o.health).sort()) {
    if (VOLATILE.has(k)) continue;
    d.health[k] = hash(stable(o.health[k]));
    if (Array.isArray(o.health[k])) d.rows[k] = o.health[k].length;
  }
  for (const k of Object.keys(o.modules).sort()) if (!VOLATILE.has(k)) d.modules[k] = hash(stable(o.modules[k]));
  return d;
}

module.exports = { replayAgent, digestOutputs };
