'use strict';

// Recorded switches served back as an SNMP agent. Each
// test/fixtures/live/<name>-agent.json holds every varbind a real switch
// answered during one full collection and the server-side panel reads
// (scripts/record-switch.js, read-only, scrubbed). The app's own collection
// runs against it unchanged (snmp-core setSessionFactory), so this covers
// the panels the older replay (live-fixtures.test.js) has no data for: ACL,
// route table, MAC table, SNMP configuration, flash and packet capture.
process.env.SNMP_MAX_RPS = '100000';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { replayAgent, digestOutputs } = require('../scripts/lib/replay');

const DIR = path.join(__dirname, 'fixtures', 'live');
const files = fs.readdirSync(DIR).filter((f) => f.endsWith('-agent.json'));

for (const file of files) {
  const fx = JSON.parse(fs.readFileSync(path.join(DIR, file), 'utf8'));
  const name = file.replace(/-agent\.json$/, '');

  test(file + ': the app makes the same of the recorded switch as when it was recorded', async () => {
    const out = await replayAgent(fx.varbinds, name);
    const now = digestOutputs(out);
    assert.deepEqual(now.rows, fx.digest.rows, 'row counts per table');
    for (const k of Object.keys(fx.digest.health)) assert.equal(now.health[k], fx.digest.health[k], 'health.' + k);
    for (const k of Object.keys(fx.digest.modules)) assert.equal(now.modules[k], fx.digest.modules[k], 'module ' + k);
    console.log(`# ${file}: live ${JSON.stringify(fx.live)}; replay ${JSON.stringify(out.requests)}`);
  });

  test(file + ': holds nothing that should have been scrubbed', () => {
    const text = fs.readFileSync(path.join(DIR, file), 'utf8') +
      fx.varbinds.map(([, , v]) => (v && v.$buf ? Buffer.from(v.$buf, 'hex').toString('latin1') : '')).join('\n');
    assert.doesNotMatch(text, /(^|[^.\d])(10\.\d{1,3}|172\.(1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}(?![.\d])/);
  });
}
