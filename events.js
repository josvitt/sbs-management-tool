/**
 * The event log: durable, structured records of things that happened to a
 * switch while the app was watching it — an alert raised or cleared, the
 * switch going unreachable and coming back, a reboot, a configuration change.
 *
 * These are distinct from `logs/app.log` (which records what the *app* did)
 * and from the metric history (numbers over time). An event answers "what
 * changed, and when", so it is what a returning operator reads to see what
 * happened while no browser was open.
 *
 * Storage is one rotating JSONL file per switch under `logs/events/`, through
 * the shared `rotate` helper, so a long-running unattended collector cannot
 * grow the log without bound. Each line is one JSON object:
 *   { at, host, type, severity?, ...type-specific fields }
 */

const path = require('path');
const rotate = require('./rotate');

const DIR = path.join(__dirname, 'logs', 'events');
const MAX_BYTES = 5 * 1024 * 1024;
const KEEP = 10;

// A host string may be an IP or a name; keep the on-disk filename safe and
// stable without inventing an opaque id the operator can't recognise.
function fileFor(host) {
  const safe = String(host || 'unknown').replace(/[^A-Za-z0-9._-]/g, '_');
  return path.join(DIR, safe + '.log');
}

/**
 * Append one event for a host. `event` carries at least a `type`; `at` is
 * stamped here (ISO) if absent. Returns the stored record.
 */
function record(host, event) {
  const rec = Object.assign({ at: new Date().toISOString(), host }, event);
  rotate.appendLine(fileFor(host), JSON.stringify(rec), { maxBytes: MAX_BYTES, keep: KEEP });
  return rec;
}

/**
 * Recent events for a host, oldest first. `opts.limit` caps the count
 * (default 200); `opts.type` filters by event type; `opts.since` (epoch ms)
 * drops older records; `opts.generations` reads rotated files too.
 */
function recent(host, opts) {
  const o = opts || {};
  const lines = rotate.readLines(fileFor(host), {
    limit: o.scan || 5000,
    generations: o.generations || 0
  });
  const out = [];
  for (const ln of lines) {
    let rec;
    try { rec = JSON.parse(ln); } catch (e) { continue; }
    if (o.type && rec.type !== o.type) continue;
    if (o.since && new Date(rec.at).getTime() < o.since) continue;
    out.push(rec);
  }
  return out.slice(-(o.limit || 200));
}

module.exports = { record, recent, fileFor, DIR };
