/**
 * Metric history.
 *
 * The dashboard samples a few numbers every thirty seconds -- CPU, PoE
 * draw, packets punted to the CPU. Held only in the browser, that history
 * dies with the tab, which makes it useless for the question it is best
 * at: "was it doing this yesterday too?"
 *
 * So samples are sent here and written to disk. Nothing about them is
 * sensitive -- they are numbers about your own equipment -- so unlike the
 * credentials in vault.js they are stored in plain JSON, where you can
 * read them with any tool you like.
 *
 * "Permanent" has to mean something bounded, or the file grows without
 * limit on a machine nobody is watching. Samples are kept at full 30-second
 * resolution for a WEEK, then thinned: one point per five minutes out to a
 * month, one per hour beyond that. Full-res for a week means the graph can
 * show fine detail for "what was it doing last Tuesday", not just today, at
 * the cost of a slightly larger file: a year of one switch is about 35,000
 * samples and under two megabytes -- still trivial. The lightweight card
 * sparkline downsamples this for display; only the full graph draws every
 * point (see sparkline()/drawGraph() in app.js).
 */

const fs = require('fs');
const path = require('path');
const log = require('./logger');

const FILE = path.join(__dirname, 'history.json');

const DAY = 24 * 60 * 60 * 1000;
const WEEK = 7 * DAY;
const MONTH = 30 * DAY;

/** host -> array of { t, cpu, poeW, cpuPps, temp, fan }
 *  temp = max sensor temperature (°C); fan = worst fan-state code
 *  (0 unknown/none · 1 ok/normal · 2 warning · 3 critical/fault). Any key is
 *  omitted from a sample when its reading was unavailable that cycle. */
const series = new Map();
let dirty = false;
let writeTimer = null;

function load() {
  try {
    if (!fs.existsSync(FILE)) return;
    const parsed = JSON.parse(fs.readFileSync(FILE, 'utf8'));
    for (const [host, samples] of Object.entries(parsed.series || {})) {
      if (Array.isArray(samples)) series.set(host, samples);
    }
    log.info('history', 'Loaded metric history', {
      switches: series.size,
      samples: Array.from(series.values()).reduce((a, b) => a + b.length, 0)
    });
  } catch (e) {
    // A corrupt history is not worth failing to start over. Say so and
    // begin again rather than leaving the app unusable.
    log.error('history', 'Could not read the history file; starting a new one', {
      message: e.message
    });
  }
}

// Write the current series to disk now (synchronous). Used by the batched
// timer and by the shutdown flush so no samples are lost when the app stops.
function writeNow() {
  if (!dirty) return;
  dirty = false;
  try {
    const out = { savedAt: new Date().toISOString(), series: {} };
    for (const [host, samples] of series) out.series[host] = samples;
    fs.writeFileSync(FILE, JSON.stringify(out));
  } catch (e) {
    log.error('history', 'Could not write the history file', { message: e.message });
  }
}

function schedule() {
  dirty = true;
  if (writeTimer) return;
  // Batched: a sample every thirty seconds per switch does not deserve a
  // write every thirty seconds.
  writeTimer = setTimeout(() => {
    writeTimer = null;
    writeNow();
  }, 20000);
}

// Flush any pending samples to disk immediately. Called on process shutdown so
// the last (up to 20s) batch is not lost when the app is stopped.
function flush() {
  if (writeTimer) { clearTimeout(writeTimer); writeTimer = null; }
  writeNow();
}

/**
 * Thin the old end of a series. Each sample carries its own timestamp, so
 * thinning is just dropping points that are closer together than the
 * resolution that age deserves.
 */
function thin(samples, now) {
  const out = [];
  let lastKept = null;
  for (const sample of samples) {
    const age = now - sample.t;
    // Full 30s resolution for a week; 5-minute out to a month; hourly beyond.
    const spacing = age <= WEEK ? 0 : (age <= MONTH ? 5 * 60 * 1000 : 60 * 60 * 1000);
    if (lastKept === null || sample.t - lastKept >= spacing) {
      out.push(sample);
      lastKept = sample.t;
    }
  }
  return out;
}

function append(host, samples) {
  if (!host || !Array.isArray(samples) || !samples.length) return 0;
  const list = series.get(host) || [];
  const known = list.length ? list[list.length - 1].t : 0;

  let added = 0;
  for (const raw of samples) {
    const t = Number(raw.t);
    if (!Number.isFinite(t) || t <= known) continue;   // never rewrite the past
    const sample = { t };
    for (const key of ['cpu', 'poeW', 'cpuPps', 'temp', 'fan']) {
      const v = raw[key];
      if (v !== null && v !== undefined && Number.isFinite(Number(v))) sample[key] = Number(v);
    }
    if (Object.keys(sample).length > 1) { list.push(sample); added++; }
  }
  if (!added) return 0;

  list.sort((a, b) => a.t - b.t);
  series.set(host, thin(list, Date.now()));
  schedule();
  return added;
}

function get(host, sinceMs) {
  const list = series.get(host) || [];
  if (!sinceMs) return list;
  const cutoff = Date.now() - sinceMs;
  return list.filter((s) => s.t >= cutoff);
}

const hosts = () => Array.from(series.keys()).map((host) => ({
  host,
  samples: series.get(host).length,
  from: series.get(host).length ? series.get(host)[0].t : null
}));

function forget(host) {
  if (host) series.delete(host); else series.clear();
  schedule();
}

load();

module.exports = { append, get, hosts, forget, flush };
