'use strict';

/**
 * Port features over SNMP: PoE settings, port security, storm control,
 * errdisable recovery, LLDP, CDP, Energy Efficient Ethernet, port
 * mirroring (SPAN) and cable test results.
 *
 * Objects (vendor root V = 1.3.6.1.4.1.9.6.1.101 unless noted):
 *   pethPsePortTable 1.3.6.1.2.1.105.1.1.1 (index group.port):
 *     .3 AdminEnable (1/2), .6 DetectionStatus, .7 PowerPriority (critical 1,
 *     high 2, low 3), .10 PowerClassifications
 *   rlPethPsePortTable V.108.1.1 (same index): .5 OutputPower (mW),
 *     .6 PowerLimit (mW, rw), .9 OperPowerLimit (mW), .13 SupportPoeType
 *   swIfTable V.43.1.1 (ifIndex): .8 LockAdminStatus (locked 1, unlocked 2),
 *     .9 LockOperStatus, .37 LockLimitationMode (disabled 1, dynamic 2,
 *     secure-permanent 3, secure-delete-on-reset 4), .38 LockMaxMacAddresses,
 *     .39 LockMacAddressesCount
 *   rlStormCtrlRateLimCfgTable V.77.12.1 (ifIndex, traffic: broadcast 1,
 *     multicastRegistered 2, multicastUnregistered 3, multicastAll 4,
 *     unknownUnicast 5, all 6): .2 Rate, .3 Unit, .4 Action. (The older
 *     rlStormCtrlTable, V.77.8, is empty on a C1300 on 4.1.9.92.)
 *   rlifPresentType V.54.43.1.3 (ifIndex): which interfaces exist. Most
 *     per-port tables carry a row for every possible ifIndex (416 on a
 *     24-port C1300), so the present Ethernet ports are read with a GET each.
 *   rlErrdisableRecovery V.128: .1 Interval (s), .2.1 cause table
 *     (.2 Enable), .3.1 per-port table (.1 Reason, .2 Enable, .3 TimeToRecover)
 *   lldpPortConfigTable 1.0.8802.1.1.2.1.1.6.1 (port number): .2 AdminStatus
 *     (txOnly 1, rxOnly 2, txAndRx 3, disabled 4); rlLldpEnabled V.110.1.1.1
 *   cdpGlobalRun 1.3.6.1.4.1.9.9.23.1.3.1; cdpInterfaceEnable
 *     1.3.6.1.4.1.9.9.23.1.1.1.1.2 (ifIndex)
 *   rlEee V.149: .1 Enable; .2.1 per-port (.1 Admin, .3 Remote, .4 Oper)
 *   rlSpan V.219: .2.1 destinations (session; .2 ifIndex, .3 reflector,
 *     .4 port type, .5 RSPAN VLAN, .6 row status); .3.1 sources (session,
 *     type, index; .4 direction rx 1, tx 2, both 3, .5 row status)
 *   rlPhyTestGetTable V.90.1.2.1 (ifIndex, test type): .2 Status, .3 Result,
 *     .4 Units, .6 TimeStamp
 */

const snmp = require('net-snmp');

const V = '1.3.6.1.4.1.9.6.1.101';
const PETH = '1.3.6.1.2.1.105.1.1.1';
const RL_PETH = V + '.108.1.1';
const SWIF = V + '.43.1.1';
const STORM = V + '.77.12.1';
const PRESENT_TYPE = V + '.54.43.1.3';
const ERRDIS = V + '.128';
const LLDP_PORTS = '1.0.8802.1.1.2.1.1.6.1';
const CDP_IF = '1.3.6.1.4.1.9.9.23.1.1.1.1';
const EEE_PORTS = V + '.149.2.1';
const SPAN_DEST = V + '.219.2.1';
const SPAN_SRC = V + '.219.3.1';
const PHY_GET = V + '.90.1.2.1';

const SCALARS = {
  errdisInterval: ERRDIS + '.1.0',
  lldp: V + '.110.1.1.1.0',
  cdp: '1.3.6.1.4.1.9.9.23.1.3.1.0',
  eee: V + '.149.1.0'
};

const POE_PRIORITY = { 1: 'critical', 2: 'high', 3: 'low' };
const POE_DETECT = { 1: 'disabled', 2: 'searching', 3: 'deliveringPower', 4: 'fault', 5: 'test', 6: 'otherFault' };
const POE_TYPE = { 1: 'none', 2: 'poe', 3: 'poeplus', 4: 'poe60w', 5: 'poeBTtype3', 6: 'poeBTtype4', 7: 'poeBTtype32pair' };
const LOCK_MODE = { 1: 'disabled', 2: 'dynamic', 3: 'secure-permanent', 4: 'secure-delete-on-reset' };
const LLDP_ADMIN = { 1: 'txOnly', 2: 'rxOnly', 3: 'txAndRx', 4: 'disabled' };
const CAUSES = { 1: 'loopback-detection', 2: 'port-security', 3: 'dot1x-src-address', 4: 'acl-deny',
  5: 'stp-bpdu-guard', 6: 'stp-loopback-guard', 7: 'pcb-overheat', 8: 'udld', 9: 'storm-control',
  10: 'link-flapping', 11: 'link-state-group' };
const REFLECTOR = { 1: 'span', 2: 'rspan-start', 3: 'rspan-final' };
const SPAN_PORT_TYPE = { 1: 'monitor-only', 2: 'network' };
const SRC_TYPE = { 1: 'port', 2: 'vlan', 3: 'flow', 4: 'remote-vlan' };
const DIRECTION = { 1: 'rx', 2: 'tx', 3: 'both' };
const PHY_TYPE = { 2: 'cableStatus', 3: 'cableFault', 4: 'cableLength',
  13: 'pair1', 14: 'pair2', 15: 'pair3', 16: 'pair4',
  17: 'polarity1', 18: 'polarity2', 19: 'polarity3', 20: 'polarity4',
  21: 'skew1', 22: 'skew2', 23: 'skew3', 24: 'skew4' };
const PHY_SET = V + '.90.1.1.1.1';   // rlPhyTestSetType, index ifIndex
const TRAFFIC = { 1: 'broadcast', 2: 'multicastRegistered', 3: 'multicastUnregistered', 4: 'multicastAll', 5: 'unknownUnicast', 6: 'all' };
const PHY_STATUS = { 1: 'none', 2: 'success', 3: 'inProgress', 4: 'notSupported', 5: 'unableToRun', 6: 'aborted', 7: 'failed' };

const num = (v) => (v == null ? null : Number(v));
const truth = (v) => (v == null ? null : Number(v) === 1);
const text = (v) => (Buffer.isBuffer(v) ? v.toString('utf8') : (v == null ? '' : String(v))).replace(/\0+$/, '').trim();
const named = (map, v) => (v == null ? null : (map[Number(v)] || String(v)));

function getChunk(session, oids) {
  return new Promise((resolve, reject) => {
    session.get(oids, (error, varbinds) => (error ? reject(error) : resolve(varbinds)));
  });
}

async function getScalars(session) {
  const names = Object.keys(SCALARS);
  const vbs = await getChunk(session, names.map((n) => SCALARS[n]));
  const out = {};
  names.forEach((n, k) => { const vb = vbs[k]; out[n] = (!vb || snmp.isVarbindError(vb)) ? undefined : vb.value; });
  return out;
}

async function walk(session, base) {
  const { boundedWalkPromise } = require('./collection');
  const rows = await boundedWalkPromise(session, base, 'getbulk', { maxRows: 600 });
  return rows.filter((vb) => !snmp.isVarbindError(vb) && String(vb.oid).indexOf(base + '.') === 0);
}

/**
 * Some columns of a table, one walk per column (a whole-table walk of a
 * wide table like swIfTable would run to thousands of rows). Resolves
 * [{ index: [arcs], key: 'a.b', cols: { n: value } }] in index order.
 */
async function walkColumns(session, table, cols) {
  const rows = new Map();
  for (const c of cols) {
    const base = table + '.' + c;
    let vbs = [];
    try { vbs = await walk(session, base); } catch (e) { continue; }
    for (const vb of vbs) {
      const key = vb.oid.slice(base.length + 1);
      if (!rows.has(key)) rows.set(key, { index: key.split('.').map(Number), key, cols: {} });
      rows.get(key).cols[c] = vb.value;
    }
  }
  return Array.from(rows.values());
}

/**
 * The present front-panel Ethernet ports' ifIndexes, from rlifPresentType.
 * Port channels start at 1000; above that, an Ethernet row is the
 * out-of-band management port (1800 on a C1300), which has none of these
 * features.
 */
async function presentPorts(session) {
  return (await walk(session, PRESENT_TYPE))
    .map((vb) => ({ ifIndex: Number(vb.oid.slice(PRESENT_TYPE.length + 1)), type: Number(vb.value) }))
    .filter((p) => p.type === 6 && p.ifIndex < 1000)
    .map((p) => p.ifIndex)
    .sort((a, b) => a - b);
}

/**
 * Some columns of the rows at the given indexes, by GET, 30 varbinds a
 * request. Resolves [{ index, key, cols }] for the rows that answered.
 */
async function getRows(session, table, cols, keys) {
  const oids = [];
  for (const k of keys) for (const c of cols) oids.push(table + '.' + c + '.' + k);
  const got = new Map();
  for (let i = 0; i < oids.length; i += 30) {
    const vbs = await getChunk(session, oids.slice(i, i + 30));
    for (const vb of vbs) {
      if (!vb || snmp.isVarbindError(vb) || vb.value == null) continue;
      const rest = vb.oid.slice(table.length + 1);
      const dot = rest.indexOf('.');
      const c = Number(rest.slice(0, dot)), key = rest.slice(dot + 1);
      if (!got.has(key)) got.set(key, {});
      got.get(key)[c] = vb.value;
    }
  }
  return keys.map(String).filter((k) => got.has(k))
    .map((k) => ({ index: k.split('.').map(Number), key: k, cols: got.get(k) }));
}

async function readPoe(session) {
  const std = await walkColumns(session, PETH, [3, 6, 7, 10]);
  const rl = new Map((await walkColumns(session, RL_PETH, [5, 6, 9, 13])).map((r) => [r.key, r.cols]));
  return std.map((r) => {
    const x = rl.get(r.key) || {};
    return {
      group: r.index[0], port: r.index[1],
      admin: truth(r.cols[3]),
      detection: named(POE_DETECT, r.cols[6]),
      priority: named(POE_PRIORITY, r.cols[7]),
      powerClass: num(r.cols[10]),
      powerMw: num(x[5]), limitMw: num(x[6]), operLimitMw: num(x[9]),
      poeType: named(POE_TYPE, x[13])
    };
  });
}

async function readSecurity(session, ifs) {
  return (await getRows(session, SWIF, [8, 9, 37, 38, 39], ifs)).map((r) => ({
    ifIndex: r.index[0],
    locked: r.cols[8] == null ? null : Number(r.cols[8]) === 1,
    operLocked: r.cols[9] == null ? null : Number(r.cols[9]) === 1,
    mode: named(LOCK_MODE, r.cols[37]),
    maxMacs: num(r.cols[38]),
    macCount: num(r.cols[39])
  }));
}

async function readStorm(session, ifs) {
  const keys = [];
  for (const i of ifs) for (const t of [1, 2, 3, 4, 5, 6]) keys.push(i + '.' + t);
  const rows = await getRows(session, STORM, [2, 3, 4], keys);
  const out = new Map();
  for (const r of rows) {
    const [ifIndex, t] = r.index;
    if (!out.has(ifIndex)) out.set(ifIndex, { ifIndex, traffic: {} });
    out.get(ifIndex).traffic[TRAFFIC[t] || String(t)] = { rate: num(r.cols[2]), unit: num(r.cols[3]), action: num(r.cols[4]) };
  }
  return Array.from(out.values());
}

async function readErrdisable(session, interval) {
  const causes = (await walkColumns(session, ERRDIS + '.2.1', [2])).map((r) => ({
    cause: named(CAUSES, r.index[0]), id: r.index[0], recover: truth(r.cols[2])
  }));
  const ports = (await walkColumns(session, ERRDIS + '.3.1', [1, 2, 3])).map((r) => ({
    ifIndex: r.index[0],
    reason: named(CAUSES, r.cols[1]),
    recover: truth(r.cols[2]),
    secondsLeft: num(r.cols[3])
  }));
  return { intervalSec: num(interval), causes, ports };
}

async function readMirror(session) {
  const destinations = (await walkColumns(session, SPAN_DEST, [2, 3, 4, 5, 6])).map((r) => ({
    session: r.index[0],
    ifIndex: num(r.cols[2]),
    reflector: named(REFLECTOR, r.cols[3]),
    portType: named(SPAN_PORT_TYPE, r.cols[4]),
    remoteVlan: num(r.cols[5]),
    rowStatus: num(r.cols[6])
  }));
  const sources = (await walkColumns(session, SPAN_SRC, [4, 5])).map((r) => ({
    session: r.index[0],
    type: named(SRC_TYPE, r.index[1]),
    index: r.index[2],
    direction: named(DIRECTION, r.cols[4]),
    rowStatus: num(r.cols[5])
  }));
  return { destinations, sources };
}

async function readCableTests(session) {
  return (await walkColumns(session, PHY_GET, [2, 3, 4, 6]))
    .filter((r) => PHY_TYPE[r.index[1]])
    .map((r) => ({
      ifIndex: r.index[0],
      test: PHY_TYPE[r.index[1]],
      status: named(PHY_STATUS, r.cols[2]),
      result: num(r.cols[3]),
      units: num(r.cols[4]),
      at: r.cols[6] == null ? '' : text(r.cols[6])
    }));
}

// ---- writes ----------------------------------------------------------------
// Each is encoded from the row the switch made (docs/SWITCH-NOTES.md, "Port
// features"). Nothing here saves the configuration.

function setVarbinds(session, varbinds) {
  return new Promise((resolve, reject) => {
    session.set(varbinds, (error, result) => {
      if (error) return reject(error);
      const bad = (result || []).find((vb) => snmp.isVarbindError(vb));
      if (bad) return reject(new Error(snmp.varbindError(bad)));
      resolve(result);
    });
  });
}

const I = (oid, value) => ({ oid, type: snmp.ObjectType.Integer, value });
const TV = (on) => (on ? 1 : 2);
const ROW = { active: 1, createAndGo: 4, createAndWait: 5, destroy: 6 };

function checkIf(ifIndex) {
  const n = Number(ifIndex);
  if (!Number.isInteger(n) || n < 1 || n >= 1000) throw new Error('ifIndex must be a front-panel port.');
  return n;
}

/**
 * PoE on one port. `p` has any of admin (bool), priority ('critical',
 * 'high', 'low') and limitMw (milliwatts, the user's power limit).
 */
async function setPoe(session, group, port, p) {
  const g = Number(group) || 1, n = Number(port);
  if (!Number.isInteger(n) || n < 1) throw new Error('port is required.');
  const idx = g + '.' + n;
  const vbs = [];
  if (p.admin != null) vbs.push(I(PETH + '.3.' + idx, TV(p.admin)));
  if (p.priority != null) {
    const v = Number(Object.keys(POE_PRIORITY).find((k) => POE_PRIORITY[k] === p.priority));
    if (!v) throw new Error('priority must be critical, high or low.');
    vbs.push(I(PETH + '.7.' + idx, v));
  }
  if (p.limitMw != null) {
    const mw = Number(p.limitMw);
    if (!Number.isInteger(mw) || mw < 0 || mw > 100000) throw new Error('The power limit is in milliwatts, 0 to 100000.');
    vbs.push(I(RL_PETH + '.6.' + idx, mw));
  }
  if (!vbs.length) throw new Error('Nothing to change.');
  await setVarbinds(session, vbs);
  return { group: g, port: n, set: p };
}

/**
 * Port security on one port: locked (bool), mode ('disabled' classic lock,
 * 'dynamic' learn up to maxMacs, 'secure-permanent', 'secure-delete-on-reset')
 * and maxMacs.
 */
async function setPortSecurity(session, ifIndex, p) {
  const ifx = checkIf(ifIndex);
  const vbs = [];
  if (p.mode != null) {
    const v = Number(Object.keys(LOCK_MODE).find((k) => LOCK_MODE[k] === p.mode));
    if (!v) throw new Error('mode must be disabled, dynamic, secure-permanent or secure-delete-on-reset.');
    vbs.push(I(SWIF + '.37.' + ifx, v));
  }
  if (p.maxMacs != null) {
    const m = Number(p.maxMacs);
    if (!Number.isInteger(m) || m < 0 || m > 256) throw new Error('The address limit is 0 to 256.');
    vbs.push(I(SWIF + '.38.' + ifx, m));
  }
  if (p.locked != null) vbs.push(I(SWIF + '.8.' + ifx, p.locked ? 1 : 2));
  if (!vbs.length) throw new Error('Nothing to change.');
  await setVarbinds(session, vbs);
  return { ifIndex: ifx, set: p };
}

/**
 * Storm control on one port: the rate for one kind of traffic ('broadcast',
 * 'multicastAll' or 'unknownUnicast'); 0 turns it off. 'all' is the port's
 * ingress rate limit: the CLI's "rate-limit" lands in this row on a C1300
 * (QoS recording, v1.16.0), not in rlQosIfPolicyTable. Only the rate column
 * is written, in kb/s. The unit (.3) and action (.4) stay as the switch has
 * them: on a C1300 on 4.1.9.92 every row reads unit 1, action 1, and the
 * switch's web page shows a rate of 10000 there as "10000 kbits/sec".
 */
async function setStorm(session, ifIndex, traffic, rate) {
  const ifx = checkIf(ifIndex);
  const t = Number(Object.keys(TRAFFIC).find((k) => TRAFFIC[k] === traffic));
  if (!t || [1, 4, 5, 6].indexOf(t) < 0) throw new Error('traffic must be broadcast, multicastAll, unknownUnicast or all.');
  const n = Number(rate);
  if (!Number.isInteger(n) || n < 0 || n > 10000000) throw new Error('The rate must be 0 to 10000000.');
  await setVarbinds(session, [{ oid: STORM + '.2.' + ifx + '.' + t, type: snmp.ObjectType.Gauge, value: n }]);
  return { ifIndex: ifx, traffic, rate: n };
}

async function setErrdisableInterval(session, seconds) {
  const n = Number(seconds);
  if (!Number.isInteger(n) || n < 30 || n > 86400) throw new Error('The recovery interval is 30 to 86400 seconds.');
  await setVarbinds(session, [I(SCALARS.errdisInterval, n)]);
  return { intervalSec: n };
}

async function setErrdisableCause(session, cause, on) {
  const id = Number(Object.keys(CAUSES).find((k) => CAUSES[k] === cause || k === String(cause)));
  if (!id) throw new Error('Unknown errdisable cause.');
  await setVarbinds(session, [I(ERRDIS + '.2.1.2.' + id, TV(on))]);
  return { cause: CAUSES[id], recover: !!on };
}

/** LLDP, CDP or EEE for the whole switch. */
async function setGlobal(session, feature, on) {
  const oid = { lldp: SCALARS.lldp, cdp: SCALARS.cdp, eee: SCALARS.eee }[feature];
  if (!oid) throw new Error('feature must be lldp, cdp or eee.');
  await setVarbinds(session, [I(oid, TV(on))]);
  return { feature, on: !!on };
}

/** LLDP on one port: 'txAndRx', 'txOnly', 'rxOnly' or 'disabled'. */
async function setLldpPort(session, ifIndex, admin) {
  const ifx = checkIf(ifIndex);
  const v = Number(Object.keys(LLDP_ADMIN).find((k) => LLDP_ADMIN[k] === admin));
  if (!v) throw new Error('LLDP must be txAndRx, txOnly, rxOnly or disabled.');
  await setVarbinds(session, [I(LLDP_PORTS + '.2.' + ifx, v)]);
  return { ifIndex: ifx, lldp: admin };
}

async function setCdpPort(session, ifIndex, on) {
  const ifx = checkIf(ifIndex);
  await setVarbinds(session, [I(CDP_IF + '.2.' + ifx, TV(on))]);
  return { ifIndex: ifx, cdp: !!on };
}

async function setEeePort(session, ifIndex, on) {
  const ifx = checkIf(ifIndex);
  await setVarbinds(session, [I(EEE_PORTS + '.1.' + ifx, TV(on))]);
  return { ifIndex: ifx, eee: !!on };
}

// ---- port mirroring ----

const MAX_SESSIONS = 4;

/**
 * A local mirroring session: copy `sources` ([{ ifIndex, direction: 'rx' |
 * 'tx' | 'both' }]) to the `dest` port. The destination row is made as the
 * switch makes it (span, monitor-only), then each source. If a source is
 * refused, the rows made so far are removed again.
 */
async function addMirror(session, sessionId, dest, sources) {
  const id = Number(sessionId);
  if (!Number.isInteger(id) || id < 1 || id > MAX_SESSIONS) throw new Error('The session is 1 to ' + MAX_SESSIONS + '.');
  const d = checkIf(dest);
  if (!Array.isArray(sources) || !sources.length) throw new Error('Choose at least one port to copy.');
  const src = sources.map((x) => {
    const ifx = checkIf(x.ifIndex);
    if (ifx === d) throw new Error('A port cannot be copied to itself.');
    const dir = Number(Object.keys(DIRECTION).find((k) => DIRECTION[k] === (x.direction || 'both')));
    if (!dir) throw new Error('direction must be rx, tx or both.');
    return { ifx, dir };
  });
  const now = await readMirror(session);
  if (now.destinations.some((x) => x.session === id)) throw new Error('Session ' + id + ' is in use.');
  if (now.destinations.some((x) => x.ifIndex === d)) throw new Error('That port is already a mirroring destination.');
  // The destination as the switch makes it: span(1), monitor-only(1),
  // RSPAN VLAN 1. The forms are tried in turn, and every one tried is kept
  // in the error (MODULE-STANDARD rule 6).
  const at = (c) => SPAN_DEST + '.' + c + '.' + id;
  const cols = [I(at(2), d), I(at(3), 1), I(at(4), 1)];
  const forms = [
    ['createAndGo with ifIndex, reflector, port type', [[I(at(6), ROW.createAndGo)].concat(cols)]],
    ['createAndGo with every column, as the switch-made row', [[I(at(6), ROW.createAndGo)].concat(cols, [I(at(5), 1)])]],
    ['createAndGo with the ifIndex alone', [[I(at(6), ROW.createAndGo), I(at(2), d)]]],
    ['createAndWait, columns, then active', [[I(at(6), ROW.createAndWait)], cols, [I(at(6), ROW.active)]]],
    ['the ifIndex alone, with no row status', [[I(at(2), d)]]]
  ];
  const tried = [];
  let ok = false;
  let via = '';
  for (const [name, steps] of forms) {
    try {
      for (const step of steps) await setVarbinds(session, step);
      const back = (await readMirror(session)).destinations.find((x) => x.session === id);
      if (!back || back.ifIndex !== d) throw new Error('the row does not read back');
      ok = true;
      via = name;
      break;
    } catch (e) {
      tried.push(name + ': ' + e.message);
      await setVarbinds(session, [I(at(6), ROW.destroy)]).catch(() => {});
    }
  }
  if (!ok) throw new Error('The switch refused every form of the destination (' + tried.join('; ') + ').');
  const made = [];
  try {
    for (const x of src) {
      const idx = id + '.1.' + x.ifx;
      await setVarbinds(session, [I(SPAN_SRC + '.5.' + idx, ROW.createAndGo), I(SPAN_SRC + '.4.' + idx, x.dir)]);
      made.push(idx);
    }
  } catch (e) {
    for (const idx of made) await setVarbinds(session, [I(SPAN_SRC + '.5.' + idx, ROW.destroy)]).catch(() => {});
    await setVarbinds(session, [I(SPAN_DEST + '.6.' + id, ROW.destroy)]).catch(() => {});
    throw new Error('The switch refused a mirrored port, so the session was removed again (' + e.message + ').');
  }
  return { session: id, dest: d, via, refused: tried, sources: src.map((x) => ({ ifIndex: x.ifx, direction: DIRECTION[x.dir] })) };
}

/** Add one port to an existing session's sources. */
async function addMirrorSource(session, sessionId, ifIndex, direction) {
  const id = Number(sessionId), ifx = checkIf(ifIndex);
  const dir = Number(Object.keys(DIRECTION).find((k) => DIRECTION[k] === (direction || 'both')));
  if (!dir) throw new Error('direction must be rx, tx or both.');
  const now = await readMirror(session);
  const dst = now.destinations.find((x) => x.session === id);
  if (!dst) throw new Error('There is no mirroring session ' + id + '.');
  if (dst.ifIndex === ifx) throw new Error('A port cannot be copied to itself.');
  if (now.sources.some((x) => x.session === id && x.type === 'port' && x.index === ifx)) throw new Error('That port is already in the session.');
  const idx = id + '.1.' + ifx;
  await setVarbinds(session, [I(SPAN_SRC + '.5.' + idx, ROW.createAndGo), I(SPAN_SRC + '.4.' + idx, dir)]);
  return { session: id, ifIndex: ifx, direction: DIRECTION[dir] };
}

/** Take one port out of a session's sources. */
async function removeMirrorSource(session, sessionId, ifIndex) {
  const id = Number(sessionId), ifx = checkIf(ifIndex);
  const now = await readMirror(session);
  if (!now.sources.some((x) => x.session === id && x.type === 'port' && x.index === ifx)) throw new Error('That port is not in session ' + id + '.');
  if (now.sources.filter((x) => x.session === id).length === 1) throw new Error('It is the only port in the session; remove the session instead.');
  await setVarbinds(session, [I(SPAN_SRC + '.5.' + id + '.1.' + ifx, ROW.destroy)]);
  return { session: id, removed: ifx };
}

/** Remove a mirroring session: its sources first, then its destination. */
async function removeMirror(session, sessionId) {
  const id = Number(sessionId);
  const now = await readMirror(session);
  if (!now.destinations.some((x) => x.session === id) && !now.sources.some((x) => x.session === id)) {
    throw new Error('There is no mirroring session ' + id + '.');
  }
  for (const x of now.sources.filter((y) => y.session === id)) {
    const t = Number(Object.keys(SRC_TYPE).find((k) => SRC_TYPE[k] === x.type)) || 1;
    await setVarbinds(session, [I(SPAN_SRC + '.5.' + id + '.' + t + '.' + x.index, ROW.destroy)]);
  }
  if (now.destinations.some((x) => x.session === id)) await setVarbinds(session, [I(SPAN_DEST + '.6.' + id, ROW.destroy)]);
  return { removed: id };
}

// ---- cable test ----

/**
 * Start a cable test on one port and wait for its results. 'length' (VCT
 * length, rlPhyTestTableCableLength) runs on a port whose link is up at
 * 1 Gb/s and keeps the link; 'full' (rlPhyTestTableCableStatus, TDR)
 * takes the link down for a few seconds while it measures each pair.
 */
async function cableTest(session, ifIndex, kind, opts) {
  const ifx = checkIf(ifIndex);
  const type = { full: 2, length: 4 }[kind || 'full'];
  if (!type) throw new Error('The test is full or length.');
  const waitMs = (opts && opts.waitMs) || 20000;
  const stepMs = (opts && opts.stepMs) || 1000;
  // Results from an earlier test stay in the table, so a result counts only
  // once its time stamp has changed.
  const stamp = (rs) => rs.map((r) => r.test + '@' + r.at).join('|');
  const before = stamp((await readCableTests(session)).filter((r) => r.ifIndex === ifx));
  await setVarbinds(session, [I(PHY_SET + '.' + ifx, type)]);
  const until = Date.now() + waitMs;
  let results = [];
  let fresh = false;
  for (;;) {
    await new Promise((r) => setTimeout(r, stepMs));
    results = (await readCableTests(session)).filter((r) => r.ifIndex === ifx);
    fresh = results.length > 0 && stamp(results) !== before && !results.some((r) => r.status === 'inProgress');
    if (fresh || Date.now() > until) break;
  }
  if (!fresh) throw new Error('The switch took the test but gave no new results within ' + Math.round(waitMs / 1000) + ' s.');
  return { ifIndex: ifx, kind: kind || 'full', results };
}

/**
 * Everything the port popout's feature tabs and the Port mirroring panel
 * show. A part the switch does not answer is null or empty, never an error
 * for the whole read.
 */
async function readPorts(session) {
  const s = await getScalars(session).catch(() => ({}));
  const safe = (p, empty) => p.catch(() => empty);
  const ifs = await safe(presentPorts(session), []);
  const poe = await safe(readPoe(session), []);
  const security = await safe(readSecurity(session, ifs), []);
  const storm = await safe(readStorm(session, ifs), []);
  const errdisable = await safe(readErrdisable(session, s.errdisInterval), { intervalSec: num(s.errdisInterval), causes: [], ports: [] });
  const lldpPorts = await safe(getRows(session, LLDP_PORTS, [2], ifs), []);
  const cdpPorts = await safe(getRows(session, CDP_IF, [2], ifs), []);
  const eeePorts = await safe(getRows(session, EEE_PORTS, [1, 3, 4], ifs), []);
  const mirror = await safe(readMirror(session), { destinations: [], sources: [] });
  const cableTests = await safe(readCableTests(session), []);
  return {
    ports: ifs, poe, security, storm, errdisable,
    lldp: { enabled: truth(s.lldp), ports: lldpPorts.map((r) => ({ port: r.index[0], admin: named(LLDP_ADMIN, r.cols[2]) })) },
    cdp: { enabled: truth(s.cdp), ports: cdpPorts.map((r) => ({ ifIndex: r.index[0], on: truth(r.cols[2]) })) },
    eee: {
      enabled: truth(s.eee),
      ports: eeePorts.map((r) => ({ ifIndex: r.index[0], admin: truth(r.cols[1]), remote: truth(r.cols[3]), oper: truth(r.cols[4]) }))
    },
    mirror, cableTests
  };
}

module.exports = {
  readPorts, presentPorts, setPoe, setPortSecurity, setStorm, setErrdisableInterval, setErrdisableCause, setGlobal,
  setLldpPort, setCdpPort, setEeePort, addMirror, removeMirror, addMirrorSource, removeMirrorSource, cableTest, walkColumns, getRows, SCALARS, PRESENT_TYPE, TRAFFIC,
  PETH, RL_PETH, SWIF, STORM, ERRDIS, LLDP_PORTS, CDP_IF, EEE_PORTS, SPAN_DEST, SPAN_SRC, PHY_GET,
  CAUSES, LOCK_MODE, LLDP_ADMIN, POE_PRIORITY
};
