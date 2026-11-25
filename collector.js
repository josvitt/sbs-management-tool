/**
 * The server-side collector: the app's own heartbeat, independent of any
 * browser.
 *
 * Before this existed, a browser tab drove collection on a setInterval, so
 * closing the tab (or the OS throttling a background tab's timers) stopped or
 * stretched the polling. The authoritative poll loop now lives here, on the
 * server: on a wall-clock cadence it loads every saved switch and runs the
 * same full health collection the UI used to trigger, then persists what
 * changed. A browser is a viewer of this data, never the thing that makes it
 * happen.
 *
 * This module owns the LOOP and the CHANGE DETECTION; it owns no SNMP wiring.
 * Everything that touches the switch or the vault is injected (`collect`,
 * `loadSwitches`, `fetchConfig`), exactly as config-fetch.js takes a session
 * builder — so the scheduler is testable without a switch and there is no
 * circular require back into server.js.
 *
 * Budget (MODULE-STANDARD §B5a): each switch still sees only its own full
 * walk once per interval — the same traffic the periodic walk always was, so
 * the per-switch ~100 pps budget is unchanged. Switches are polled
 * sequentially with a small gap so N switches do not burst from the server at
 * once; that paces the SERVER's fan-out, not any one switch's load. onDemand
 * modules (snmpcfg/flash/capture) are never collected here — they stay lazy
 * and browser-only, by the same budget rule.
 */

const crypto = require('crypto');

// Each switch is polled on ITS OWN interval (the per-switch control drives the
// server's poll rate for that switch). DEFAULT_INTERVAL_MS applies to a switch
// with no interval set; MIN/MAX clamp it to the same bounds the UI enforces.
// Two cadences, exactly as the app had before the server took over collection:
//  - METRIC_PROBE_MS: a cheap single-PDU probe (CPU, PoE, cpu-pps, uptime,
//    config-saved) every ~30s. It feeds the fine-grained metric graph and
//    decides reachability/reboot. This is the fast pulse the graph needs.
//  - the per-switch interval (DEFAULT_INTERVAL_MS default): the FULL collection
//    (every table, alerts, temperature, fan state, the config gate). Heavier,
//    so it runs far less often. Each tick is a probe; every interval the tick
//    also does the full collection.
const METRIC_PROBE_MS = Number(process.env.METRIC_PROBE_MS) || 30000;            // fast metric/reachability pulse
const DEFAULT_INTERVAL_MS = Number(process.env.COLLECT_INTERVAL_MS) || 300000;   // full-collection cadence (5 min)
const MIN_INTERVAL_MS = 5000;
const MAX_INTERVAL_MS = 3600000;
const SWITCH_PACE_MS = Number(process.env.COLLECT_PACE_MS) || 1500;              // stagger between switches so N don't fire at once
const CONFIG_PULL_MIN_GAP_MS = Number(process.env.CONFIG_PULL_MIN_GAP_MS) || 60000;
const INITIAL_DELAY_MS = Number(process.env.COLLECT_INITIAL_DELAY_MS) || 3000;
// Settings tables (deps.settingsTables) are carried from the last full read
// between collections, and re-read after a config change, a reboot, an app
// write, a manual Refresh, or at the latest this often.
const SETTINGS_MAX_AGE_MS = Number(process.env.SETTINGS_MAX_AGE_MS) || 3600000;

let deps = null;         // { probe, collect, loadSwitches, fetchConfig, history, events, log }
let running = false;
const timers = new Map();       // key -> timeout id for the next scheduled tick
const inflight = new Map();     // key -> promise of the poll in progress (never poll one switch twice at once)

// key -> { at, host, target, data? , error? }   latest snapshot per switch
const snapshots = new Map();
// key -> per-switch change-detection state (see freshState)
const state = new Map();
// hosts for which an external signal (config trap, app-driven write) asks the
// next poll to re-check the running config even if the saved flag didn't move
const pendingConfigHosts = new Set();

const keyOf = (target) => `${target.host}:${target.port || 161}`;
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

function freshState() {
  return {
    reachable: null,
    sysUpTime: null,
    lastConfigEqual: null,     // last saved/unsaved flag seen by the fast probe
    configHash: null,
    lastConfigPullAt: 0,
    configTripPending: false,
    alertSigs: new Map(),      // sig -> alert, the alerts standing as of last full poll
    lastFullAt: 0,             // when the full collection last ran
    lastData: null,            // last full-collection data, kept for the snapshot between full polls
    settingsGen: 1,            // bumped by anything that may have changed the switch's settings
    settingsReadGen: 0,        // the settingsGen the settings tables were last read at
    lastSettingsAt: 0          // when the settings tables were last read
  };
}

// A cell as the pivoted health tables carry it: { value, display }.
function colDisp(row, name) {
  const c = row && row[name];
  if (!c) return '';
  return String(c.display != null ? c.display : (c.value != null ? c.value : ''));
}

// worst fan-state code across present fans: 0 unknown · 1 ok · 2 warn · 3 crit
function fanStateCode(data) {
  let worst = null;
  for (const f of (data.fans || [])) {
    const st = colDisp(f, 'rlEnvMonFanState');
    if (/notPresent|notAvailable/i.test(st)) continue;
    let code;
    if (!st) code = 0;
    else if (/normal|ok/i.test(st)) code = 1;
    else if (/critical|shutdown|notFunctioning|fault/i.test(st)) code = 3;
    else code = 2;
    if (worst === null || code > worst) worst = code;
  }
  return worst;
}

// Stable identity for an alert across cycles: its area + its message with the
// numbers blanked, so "CPU at 85%" and "CPU at 86%" are the SAME ongoing alert
// and don't churn raised/cleared every poll. (buildAlerts emits {severity,
// area, message}.)
function alertSig(a) {
  return (a.area || '') + '|' + String(a.message || '').replace(/\d+(?:\.\d+)?/g, '#');
}

function diffAlerts(host, st, data) {
  const now = new Map();
  for (const a of (data.alerts || [])) now.set(alertSig(a), a);
  for (const [sig, a] of now) {
    if (!st.alertSigs.has(sig)) {
      deps.events.record(host, { type: 'alert', state: 'raised', severity: a.severity, area: a.area, message: a.message });
    }
  }
  for (const [sig, a] of st.alertSigs) {
    if (!now.has(sig)) {
      deps.events.record(host, { type: 'alert', state: 'cleared', severity: a.severity, area: a.area, message: a.message });
    }
  }
  st.alertSigs = now;
}

// Gated running-config content diff, run only on a full collection. The fast
// probe owns the cheap trip signals (it sets configTripPending on a saved-flag
// flip or a reboot); here we consume that, plus the one-time baseline, and only
// then spend the expensive config pull; the pull + hash decide whether the
// content actually changed.
async function maybeConfigDiff(host, target, st, rebooted) {
  let trip = false;
  if (rebooted) trip = true;
  if (st.configTripPending) trip = true;
  if (st.configHash === null) trip = true;   // establish a baseline once

  if (!trip || !deps.fetchConfig) return;
  const nowMs = Date.now();
  if (!rebooted && (nowMs - st.lastConfigPullAt) < CONFIG_PULL_MIN_GAP_MS) return;   // debounce a flapping flag
  st.lastConfigPullAt = nowMs;
  st.configTripPending = false;

  let text;
  try {
    text = await deps.fetchConfig(target);
  } catch (e) {
    deps.log && deps.log.warn('collector', 'Config pull for change-detection failed', { host, message: e.message });
    return;
  }
  if (text == null) return;
  // Every pull is offered to the config history, the baseline included; it
  // stores a version only when the text differs from its newest one.
  let stored = null;
  if (deps.configHistory) {
    try { stored = deps.configHistory.record(host, text); }
    catch (e) { deps.log && deps.log.warn('collector', 'Could not store the config version', { host, message: e.message }); }
  }
  const hash = sha256(String(text));
  if (st.configHash && hash !== st.configHash) {
    deps.events.record(host, Object.assign(
      { type: 'config-change', hash, previousHash: st.configHash, bytes: String(text).length },
      stored ? { version: stored.id } : {}));
    deps.log && deps.log.info('collector', 'Running-config change detected', { host });
  }
  st.configHash = hash;
}

// The settings tables of a full collection, to carry into the next one.
function settingsFrom(data) {
  const keys = (deps && deps.settingsTables) || [];
  if (!data || !keys.length) return null;
  const out = {};
  for (const k of keys) if (Array.isArray(data[k])) out[k] = data[k];
  return Object.keys(out).length ? out : null;
}

// One tick for a switch. ALWAYS does the cheap probe (reachability, reboot,
// config-flag, and a CPU/PoE/pps metric sample - the fast pulse the graph
// needs). ADDITIONALLY does the full collection (alerts, temp, fan, config
// gate, snapshot) when its per-switch interval has elapsed, or when forced
// (opts.full - a manual nudge / first open).
async function pollOnce(entry, opts) {
  const target = entry && entry.target;
  if (!target || !target.host) return null;
  const key = keyOf(target);
  const host = target.host;

  let st = state.get(key);
  if (!st) { st = freshState(); state.set(key, st); }
  if (pendingConfigHosts.has(host)) { st.configTripPending = true; pendingConfigHosts.delete(host); }

  // --- cheap probe (every tick) ---
  let p;
  try { p = await deps.probe(target); } catch (e) { p = { reachable: false, error: e.message }; }

  if (!p || !p.reachable) {
    if (st.reachable !== false) {
      deps.events.record(host, { type: 'reachability', state: 'down', error: p && p.error });
      deps.log && deps.log.warn('collector', 'Switch unreachable', { host, message: p && p.error });
    }
    st.reachable = false;
    // Keep the last good data on the snapshot so the viewer shows the last
    // known state, flagged with the error, rather than going blank.
    snapshots.set(key, { at: Date.now(), host, target, error: (p && p.error) || 'unreachable', data: st.lastData || undefined });
    return snapshots.get(key);
  }

  if (st.reachable === false) {
    deps.events.record(host, { type: 'reachability', state: 'up' });
    deps.log && deps.log.info('collector', 'Switch reachable again', { host });
  }
  st.reachable = true;

  // reboot (sysUpTime went backwards) - also trips the config gate
  const upNow = Number.isFinite(p.uptime) ? p.uptime : null;
  let rebooted = false;
  if (upNow != null && st.sysUpTime != null && upNow < st.sysUpTime) {
    rebooted = true;
    st.configTripPending = true;
    st.settingsGen++;
    deps.events.record(host, { type: 'reboot', fromTicks: st.sysUpTime, toTicks: upNow });
    deps.log && deps.log.info('collector', 'Reboot detected (sysUpTime reset)', { host });
  }
  if (upNow != null) st.sysUpTime = upNow;

  // config saved/unsaved flag flip (either direction) trips the config gate
  const configEqual = (p.configSaved === true || p.configSaved === false) ? p.configSaved : null;
  if (st.lastConfigEqual !== null && configEqual !== null && configEqual !== st.lastConfigEqual) {
    st.configTripPending = true;
    st.settingsGen++;
  }
  if (configEqual !== null) st.lastConfigEqual = configEqual;

  // the fast metric point (cpu/poe/pps), built from the probe every tick
  const sample = { t: Date.now() };
  if (Number.isFinite(p.cpu)) sample.cpu = p.cpu;
  if (Number.isFinite(p.poeW)) sample.poeW = p.poeW;
  if (Number.isFinite(p.cpuPps)) sample.cpuPps = p.cpuPps;

  // --- full collection (only when due or forced) ---
  const now = Date.now();
  const due = !!(opts && opts.full) || (now - (st.lastFullAt || 0)) >= intervalMsFor(entry);
  if (due) {
    let data = null;
    // Carry the settings tables forward unless something may have changed
    // them (or they are an hour old, or this is a manual Refresh).
    const gen = st.settingsGen;
    const settingsDue = !!(opts && opts.full) || !st.lastData || st.settingsReadGen !== gen ||
      (now - st.lastSettingsAt) >= SETTINGS_MAX_AGE_MS;
    const reuse = settingsDue ? null : settingsFrom(st.lastData);
    try { data = await deps.collect(target, reuse ? { reuse } : {}); }
    catch (e) { deps.log && deps.log.warn('collector', 'Collection failed after reachable probe', { host, message: e.message }); }
    if (data) {
      st.lastData = data;
      st.lastFullAt = now;
      if (!reuse) { st.settingsReadGen = gen; st.lastSettingsAt = now; }
      snapshots.set(key, { at: Date.now(), host, target, data, probe: p });
      diffAlerts(host, st, data);
      // add the slow-moving environment readings to this tick's point
      const sum = data.summary || {};
      if (Number.isFinite(sum.maxTempC)) sample.temp = sum.maxTempC;
      const fan = fanStateCode(data);
      if (fan != null) sample.fan = fan;
      try { await maybeConfigDiff(host, target, st, rebooted); } catch (e) { /* logged */ }
    } else {
      // reachable but the full walk failed: keep the fast pulse going
      snapshots.set(key, { at: Date.now(), host, target, probe: p, data: st.lastData || undefined });
    }
  } else {
    // fast tick only: refresh the snapshot's freshness, keep last full data
    snapshots.set(key, { at: Date.now(), host, target, data: st.lastData || undefined, probe: p });
  }

  if (Object.keys(sample).length > 1) deps.history.append(host, [sample]);
  return snapshots.get(key);
}

// Drop snapshot/state for switches no longer saved, so a removed switch stops
// consuming memory and its stale snapshot can't be served.
function pruneTo(entries) {
  const live = new Set(entries.filter((e) => e && e.target && e.target.host).map((e) => keyOf(e.target)));
  for (const key of Array.from(snapshots.keys())) if (!live.has(key)) snapshots.delete(key);
  for (const key of Array.from(state.keys())) if (!live.has(key)) state.delete(key);
}

// The saved switches as a key->entry map, each with its SNMP target.
function entriesByKey() {
  let entries = [];
  try { entries = deps.loadSwitches() || []; } catch (e) { entries = []; }
  const map = new Map();
  for (const e of entries) if (e && e.target && e.target.host) map.set(keyOf(e.target), e);
  return map;
}

// A switch's poll interval in ms: its own `interval` (seconds), clamped to the
// UI's bounds, else the default.
function intervalMsFor(entry) {
  const sec = Number(entry && entry.interval);
  if (!Number.isFinite(sec) || sec <= 0) return DEFAULT_INTERVAL_MS;
  return Math.max(MIN_INTERVAL_MS, Math.min(MAX_INTERVAL_MS, Math.round(sec * 1000)));
}

// Tick one switch (cheap probe + a full collection when due), then schedule the
// next tick at the fast metric cadence. The per-switch interval is read live
// inside pollOnce to decide whether this tick also does the full collection, so
// an interval change takes effect on the next tick with no rescheduling.
async function tickAndReschedule(key) {
  if (!running) return;
  const entry = entriesByKey().get(key);
  if (!entry) { timers.delete(key); return; }   // removed meanwhile
  if (!inflight.has(key)) {
    const run = pollOnce(entry, {});
    inflight.set(key, run);
    try { await run; }
    catch (e) { deps.log && deps.log.error('collector', 'Tick failed', { message: e.message }); }
    inflight.delete(key);
  }
  if (!running) return;
  timers.set(key, setTimeout(() => tickAndReschedule(key), METRIC_PROBE_MS));
}

// Reconcile the scheduled set against the saved switches: drop removed ones and
// add new ones (first tick soon, staggered so several don't fire at once). The
// first tick does a full collection immediately (lastFullAt is 0). `initial`
// only lengthens the first stagger so startup doesn't thundering-herd.
function ensureScheduled(initial) {
  const map = entriesByKey();
  for (const key of Array.from(timers.keys())) {
    if (!map.has(key)) { clearTimeout(timers.get(key)); timers.delete(key); }
  }
  pruneTo(Array.from(map.values()));
  let i = 0;
  const base = initial ? INITIAL_DELAY_MS : 800;
  for (const key of map.keys()) {
    if (!timers.has(key)) {
      timers.set(key, setTimeout(() => tickAndReschedule(key), base + i * SWITCH_PACE_MS));
      i++;
    }
  }
}

// ---- public API ----------------------------------------------------------

function start(d, opts) {
  deps = d;
  if (running) return;
  running = true;
  // A test harness drives pollOnce directly via nudge and suppresses the timers.
  if (!opts || opts.schedule !== false) ensureScheduled(true);
  deps.log && deps.log.info('collector', 'Server-side collector started',
    { metricProbeMs: METRIC_PROBE_MS, defaultIntervalMs: DEFAULT_INTERVAL_MS, paceMs: SWITCH_PACE_MS });
}

function stop() {
  running = false;
  for (const t of timers.values()) clearTimeout(t);
  timers.clear();
}

// A saved-switch change (add/remove/interval edit): reconcile the schedule now
// rather than at the next poll boundary, so a new switch starts collecting
// promptly and an interval change takes effect quickly.
function reload() {
  if (!running || !deps) return;
  ensureScheduled(false);
}

// Manual "Refresh" (MODULE-STANDARD manual-refresh = nudge server to poll now):
// force a FULL poll of one switch out of cycle and return its fresh snapshot.
// Respects the in-flight guard so it never double-polls a switch mid-tick: if
// a poll is already running it waits for that one, and returns it when it was
// a full collection; after a probe-only tick it then runs the full poll. (It
// used to return the previous snapshot at once, so a click could show old data.)
async function nudge(target) {
  if (!running || !deps || !target || !target.host) return null;
  const key = keyOf(target);
  const fullBefore = st0(key);
  while (inflight.has(key)) {
    try { await inflight.get(key); } catch (e) { /* that poll's failure is logged by its owner */ }
    if (!running) return snapshots.get(key) || null;
    if (st0(key) !== fullBefore) return snapshots.get(key) || null;   // a full collection just landed
  }
  const run = pollOnce({ target }, { full: true });
  inflight.set(key, run);
  try { return await run; }
  finally { inflight.delete(key); }
}
const st0 = (key) => { const st = state.get(key); return st ? st.lastFullAt : 0; };

// An external signal (a config-related trap, or an app-driven config write)
// asks the next poll of this host to re-check the running config.
function flagConfigChange(host) {
  if (!host) return;
  for (const [key, st] of state) {
    // keyOf is host:port; split at the LAST colon so an IPv6 host survives.
    if (key.slice(0, key.lastIndexOf(':')) === host) { st.configTripPending = true; st.settingsGen++; return; }
  }
  pendingConfigHosts.add(host);
}

// The app wrote to this switch (snmp-core's write listener): read the settings
// tables afresh on the next full collection. Does not pull the config; the
// saved/unsaved flag the probe reads already covers that.
function flagSettingsChange(host) {
  if (!host) return;
  for (const [key, st] of state) {
    if (key.slice(0, key.lastIndexOf(':')) === host) st.settingsGen++;
  }
}

function snapshotByKey(key) { return snapshots.get(key) || null; }
function snapshotFor(target) { return target ? (snapshots.get(keyOf(target)) || null) : null; }
function snapshotByHost(host) {
  for (const snap of snapshots.values()) if (snap.host === host) return snap;
  return null;
}
function status() {
  return Array.from(snapshots.values()).map((s) => ({
    host: s.host,
    at: s.at,
    reachable: !s.error,
    error: s.error || null,
    worst: s.data && s.data.summary ? s.data.summary.worstSeverity : null,
    alerts: s.data && s.data.alerts ? s.data.alerts.length : null
  }));
}

module.exports = {
  start, stop, reload, nudge, flagConfigChange, flagSettingsChange,
  snapshotFor, snapshotByKey, snapshotByHost, status,
  _internals: { alertSig, fanStateCode, colDisp, keyOf, intervalMsFor, pollOnce }   // for offline tests
};
