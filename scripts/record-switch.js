'use strict';

/**
 * Record a real switch for the offline replay test (test/live-agent.test.js).
 * READ-ONLY: it never sends a SET (the recorder refuses them).
 *
 *   SBS_COMM=<community> node scripts/record-switch.js <switch address> <name>
 *
 * It runs the app's own full collection and server-side panel reads against
 * the switch, keeps every varbind the switch answered with, scrubs addresses,
 * MACs, names and secrets (scripts/lib/scrub-recording.js), replays the
 * scrubbed copy to compute what the app makes of it, and writes
 * test/fixtures/live/<name>-agent.json. The live request counts go in the
 * file too, for the release notes.
 */

process.env.SNMP_MAX_RPS = process.env.SNMP_MAX_RPS || '100';
const fs = require('fs');
const path = require('path');
const { setSessionFactory } = require('../snmp-core');
const { collectHealthFor } = require('../collection');
const { collectModulesFor } = require('../module-collection');
const { recordingSession, serialise } = require('./lib/snmp-recording');
const { scrub } = require('./lib/scrub-recording');
const { replayAgent, digestOutputs } = require('./lib/replay');

async function main() {
  const host = process.argv[2];
  const name = process.argv[3];
  const community = process.env.SBS_COMM;
  if (!host || !name || !community) {
    console.error('Usage: SBS_COMM=<community> node scripts/record-switch.js <address> <name>');
    process.exit(2);
  }
  const target = { host, port: 161, version: '2c', community };
  const rec = {};
  const phases = {};
  setSessionFactory((t, buildReal) => recordingSession(buildReal(), rec));

  let t0 = Date.now();
  await collectHealthFor(target, {});
  phases.health = Object.assign({ ms: Date.now() - t0 }, rec.requests);
  rec.requests = { get: 0, getNext: 0, getBulk: 0 };
  t0 = Date.now();
  await collectModulesFor(target, ['snmpConfig', 'flash', 'captures', 'maint', 'system', 'ports', 'stp', 'security', 'ipv6', 'qos']);
  phases.modules = Object.assign({ ms: Date.now() - t0 }, rec.requests);
  setSessionFactory(null);

  const raw = serialise(rec);
  const { varbinds, counts } = scrub(raw, [community, host]);
  const outputs = await replayAgent(varbinds, name);
  const file = path.join(__dirname, '..', 'test', 'fixtures', 'live', name + '-agent.json');
  fs.writeFileSync(file, JSON.stringify({
    note: 'Every varbind the switch answered during one full collection and the server-side panel reads, scrubbed. Read-only recording.',
    recordedAt: new Date().toISOString().slice(0, 10),
    live: phases,
    replayed: outputs.requests,
    scrubbed: counts,
    digest: digestOutputs(outputs),
    varbinds
  }) + '\n');
  console.log('Wrote ' + path.relative(process.cwd(), file));
  console.log('Live requests: ' + JSON.stringify(phases));
  console.log('Scrubbed: ' + JSON.stringify(counts));
  console.log('RECORDED OK');
}

main().catch((e) => { console.error('Recording failed: ' + e.message); process.exit(1); });
