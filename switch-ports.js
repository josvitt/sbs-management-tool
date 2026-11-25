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
const PHY_TYPE = { 2: 'cableStatus', 3: 'cableFault', 4: 'cableLength', 13: 'pair1', 14: 'pair2', 15: 'pair3', 16: 'pair4' };
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
  readPorts, walkColumns, getRows, SCALARS, PRESENT_TYPE, TRAFFIC,
  PETH, RL_PETH, SWIF, STORM, ERRDIS, LLDP_PORTS, CDP_IF, EEE_PORTS, SPAN_DEST, SPAN_SRC, PHY_GET,
  CAUSES, LOCK_MODE, LLDP_ADMIN, POE_PRIORITY
};
