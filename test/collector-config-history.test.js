'use strict';

// The collector offers each running-config it pulls to the config history,
// and a config-change event names the version it stored.
const test = require('node:test');
const assert = require('node:assert/strict');
const collector = require('../collector');

test('collector stores the baseline and each changed config, and links the event', async () => {
  const configs = ['hostname a\n', 'hostname b\n'];
  const recorded = [];
  const events = [];
  let n = 0;
  collector.start({
    probe: async () => ({ reachable: true, uptime: 100 + n }),
    collect: async () => ({ alerts: [], summary: {} }),
    loadSwitches: () => [],
    fetchConfig: async () => configs[Math.min(n, configs.length - 1)],
    configHistory: { record: (host, text) => { recorded.push([host, text]); return { id: 'v' + recorded.length }; } },
    events: { record: (host, e) => events.push(e) },
    history: { append: () => {} }
  }, { schedule: false });
  try {
    const target = { host: '10.9.9.9', port: 161 };
    await collector.nudge(target);          // baseline
    n = 1;
    collector.flagConfigChange('10.9.9.9');
    // The pull is debounced; step past the gap rather than wait it out.
    const realNow = Date.now;
    Date.now = () => realNow() + 10 * 60 * 1000;
    try { await collector.nudge(target); } finally { Date.now = realNow; }
  } finally {
    collector.stop();
  }
  assert.deepEqual(recorded, [['10.9.9.9', 'hostname a\n'], ['10.9.9.9', 'hostname b\n']]);
  const change = events.find((e) => e.type === 'config-change');
  assert.ok(change, 'a config-change event was recorded');
  assert.equal(change.version, 'v2');
});
