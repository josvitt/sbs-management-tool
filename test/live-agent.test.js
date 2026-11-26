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
const mib = require('../mibdb');

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

  test(file + ': every MAC, and every link-local address made from one, is a documentation MAC', () => {
    const bad = [];
    for (const [oid, , v] of fx.varbinds) {
      const e = mib.entryForOid(oid);
      const b = v && v.$buf ? Buffer.from(v.$buf, 'hex') : null;
      if (e && b && /Mac(Address)?$|PhysAddress|SystemID/i.test(e.entry.name) && b.length === 6 && !b.every((c) => c === 0) &&
          !/^00005e0053/.test(b.toString('hex')) && !b.every((c) => c === 255)) bad.push(e.entry.name);
      const ll = [oid.split('.').map(Number), b ? Array.from(b) : []];
      for (const arcs of ll) {
        for (let i = 0; i + 16 <= arcs.length; i++) {
          if (arcs[i] === 254 && arcs[i + 1] === 128 && arcs.slice(i + 2, i + 8).every((n) => n === 0) && arcs[i + 11] === 255 && arcs[i + 12] === 254 &&
              !(arcs[i + 8] === 2 && arcs[i + 9] === 0 && arcs[i + 10] === 0x5e && arcs[i + 13] === 0 && arcs[i + 14] === 0x53)) bad.push((e && e.entry.name) || oid);
        }
      }
    }
    assert.deepEqual(Array.from(new Set(bad)), []);
  });
}
