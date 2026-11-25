'use strict';

// A write holds the switch's full collection (collector.holdForWrite), so a
// scheduled or manual full read never lands in the middle of a change.
process.env.WRITE_QUIET_MS = '300';
process.env.WRITE_WAIT_MAX_MS = '2000';
const test = require('node:test');
const assert = require('node:assert/strict');
const collector = require('../collector');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function startWith(collect) {
  collector.start({
    probe: async () => ({ reachable: true, uptime: 100 }),
    collect,
    loadSwitches: () => [],
    events: { record: () => {} },
    history: { append: () => {} }
  }, { schedule: false });
}

test('a full collection does not run while a write holds the switch', async () => {
  let fulls = 0;
  startWith(async () => { fulls++; return { alerts: [], summary: {} }; });
  try {
    const target = { host: '10.0.0.1', port: 161 };
    await collector.holdForWrite('10.0.0.1');
    assert.equal(collector._internals.heldForWrite('10.0.0.1'), true);
    // A tick that would be due skips the full collection during the hold.
    await collector._internals.pollOnce({ target }, {});
    assert.equal(fulls, 0, 'no full collection during the hold');
    // A manual Refresh waits for the hold to end, then reads.
    const t0 = Date.now();
    await collector.nudge(target);
    assert.equal(fulls, 1);
    assert.ok(Date.now() - t0 >= 200, 'the Refresh waited for the write to finish');
    assert.equal(collector._internals.heldForWrite('10.0.0.1'), false);
  } finally { collector.stop(); }
});

test('a write waits for a collection already running on that switch', async () => {
  let release;
  const gate = new Promise((r) => { release = r; });
  let collecting = false;
  startWith(async () => { collecting = true; await gate; collecting = false; return { alerts: [], summary: {} }; });
  try {
    const target = { host: '10.0.0.2', port: 161 };
    const poll = collector.nudge(target);
    await sleep(20);
    assert.equal(collecting, true);
    let wrote = false;
    const write = collector.holdForWrite('10.0.0.2').then(() => { wrote = true; });
    await sleep(50);
    assert.equal(wrote, false, 'the write is still waiting');
    release();
    await poll; await write;
    assert.equal(wrote, true);
    assert.equal(collecting, false, 'the collection finished before the write went ahead');
  } finally { collector.stop(); }
});

test('a hold on one switch leaves the others alone', async () => {
  let fulls = 0;
  startWith(async () => { fulls++; return { alerts: [], summary: {} }; });
  try {
    await collector.holdForWrite('10.0.0.3');
    await collector._internals.pollOnce({ target: { host: '10.0.0.4', port: 161 } }, { full: true });
    assert.equal(fulls, 1);
  } finally { collector.stop(); }
});
