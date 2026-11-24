'use strict';

/**
 * The ONE collection path (SERVER-STANDARD §1-2): the reachability probe and
 * collectHealthFor, shared by the HTTP routes and the server-side collector.
 * Moved verbatim out of server.js.
 */

const snmp = require('net-snmp');
const log = require('./logger');
const mib = require('./mibdb');
const health = require('./health');
const { buildSnmpSession, resolveOids, boundedWalk, describeVarbind, redactTarget } = require('./snmp-core');

/**
 * Reachability probe: one GET of sysUpTime, nothing else.
 *
 * The full health collection is dozens of walks; asking whether the switch
 * is still answering does not need any of that. A single varbind is about
 * as small as SNMP gets, and the uptime it returns doubles as a reboot
 * detector -- an uptime lower than the last one means the switch restarted
 * between polls, which is worth knowing and free to notice.
 */
/**
 * The probe carries a few numbers as well as the uptime, so the dashboard
 * can show how they are *moving* rather than only where they are now.
 * Still one PDU, four varbinds: cheap enough to run every 30 seconds
 * whether or not auto-refresh is on.
 */
const PROBE_OIDS = [
  '1.3.6.1.2.1.1.3.0',                       // sysUpTime
  '1.3.6.1.4.1.9.6.1.101.1.9.0',             // CPU, 5 minute average
  '1.3.6.1.2.1.105.1.3.1.1.4.1',             // PoE watts drawn
  '1.3.6.1.4.1.9.6.1.101.1.13.0',            // running == startup
  '1.3.6.1.4.1.9.6.1.101.203.2.0'            // packets per second to the CPU
];

// A fast, single-PDU reachability + quick-metrics probe (sysUpTime, CPU, PoE,
// config-saved flag, cpu pps). Shared by the HTTP ping and the collector: the
// collector probes BEFORE a full collection, so reachability is decided in one
// PDU and a dead host never incurs a dozens-of-walks collection (budget,
// MODULE-STANDARD §B5a). `collect` returns a resilient partial even when a host
// is unreachable, so this probe - not a collect failure - is the reachability
// signal. Never rejects; resolves { reachable, ... }.
function probeSwitch(target) {
  return new Promise((resolve) => {
    const started = Date.now();
    let session;
    try {
      session = buildSnmpSession(Object.assign({}, target, { timeout: 2500, retries: 1 }));
    } catch (e) {
      return resolve({ reachable: false, error: e.message, ms: 0 });
    }
    session.get(PROBE_OIDS, (error, varbinds) => {
      try { session.close(); } catch (e) {}
      if (error) return resolve({ reachable: false, error: error.message, ms: Date.now() - started });
      const num = (i) => {
        const vb = varbinds && varbinds[i];
        if (!vb || snmp.isVarbindError(vb)) return null;
        const n = Number(vb.value);
        return Number.isFinite(n) ? n : null;
      };
      const uptime = num(0);
      if (uptime === null) {
        return resolve({ reachable: false, error: 'no answer', ms: Date.now() - started });
      }
      resolve({
        reachable: true, ms: Date.now() - started,
        uptime, cpu: num(1), poeW: num(2), configSaved: num(3) === 1, cpuPps: num(4)
      });
    });
  });
}


// -----------------------------------------------------------------
// Health page
// -----------------------------------------------------------------
// One request collects the whole health picture so the UI doesn't have to
// orchestrate a dozen round trips. Everything runs over a single SNMP
// session, which is closed when the last walk finishes.

function snmpGetPromise(session, oids) {
  return new Promise((resolve, reject) => {
    session.get(oids, (error, varbinds) => {
      if (error) return reject(error);
      resolve(varbinds.map((vb) =>
        snmp.isVarbindError(vb)
          ? { oid: vb.oid, error: snmp.varbindError(vb), column: mib.describeOid(vb.oid) }
          : describeVarbind(vb)));
    });
  });
}

function boundedWalkPromise(session, oid, mode, opts) {
  return new Promise((resolve, reject) => {
    boundedWalk(session, oid, Object.assign({ mode }, opts || {}), (error, results) => {
      // A table the model doesn't implement is not fatal; return what we
      // have so the rest of the page still renders.
      if (error && !results.length) return reject(error);
      resolve(results);
    });
  });
}

// One previous collection per switch, kept only to turn counters into
// rates. Nothing is persisted: a restart simply means the first collection
// after it has no rate to report, which is honest.
const lastCollection = new Map();

// The ONE collection path. Both the HTTP handler below and the server-side
// collector (collector.js) run collection through here, so there is a single
// place that builds a session, walks the switch, and keeps the per-switch rate
// baseline (governing rule 4 - never a parallel poller). Throws on failure;
// the session is always closed. `previous` turns error counters into a rate:
// "4,812 since boot" says nothing on a switch up 160 days, but "up 43 in the
// last two minutes" is a fault.
async function collectHealthFor(target, opts) {
  const { mode, only } = opts || {};
  const session = buildSnmpSession(target);
  session.on('error', (err) => {
    log.error('health', 'SNMP session error', { message: err.message });
  });
  const key = redactTarget(target).host + ':' + (target.port || 161);
  try {
    const data = await health.collect({
      only,
      previous: lastCollection.get(key),
      get: (oids) => snmpGetPromise(session, resolveOids(oids)),
      walk: (oid, spec) => boundedWalkPromise(session, mib.resolveOid(oid), mode, spec)
    });
    if (!data.partial) {
      lastCollection.set(key, {
        at: Date.now(),
        interfaces: data.interfaces.map((r) => ({
          index: r.index,
          inErrors: r.rlifPresentInErrors ? Number(r.rlifPresentInErrors.value) : null,
          outErrors: r.rlifPresentOutErrors ? Number(r.rlifPresentOutErrors.value) : null
        }))
      });
    }
    return data;
  } finally {
    try { session.close(); } catch (e) { /* already closed */ }
  }
}


module.exports = {
  PROBE_OIDS,
  probeSwitch,
  snmpGetPromise,
  boundedWalkPromise,
  collectHealthFor
};
