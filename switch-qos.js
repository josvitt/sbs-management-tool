'use strict';

/**
 * QoS over SNMP (CISCOSB-QOS-CLI-MIB, V.88): the QoS mode and trust, trust
 * per port, the port shaper, the port rate limit, shapers per queue, and the
 * CoS and DSCP queue maps. Policy maps and ACL bindings are out of scope.
 *
 * Encoded from the rows .253 made for the CLI samples on gi1/0/4
 * (rate-limit 64000, traffic-shape 64000, traffic-shape queue 3 64000,
 * wrr-queue cos-map 7 5, qos map dscp-queue 10 to 6), docs/SWITCH-NOTES.md
 * "QoS". Nothing here saves the configuration.
 *
 * Objects (vendor root V = 1.3.6.1.4.1.9.6.1.101):
 *   rlQosModeGlobalCfgTable V.88.46.1, one row (index 1): .2 GlobalQoSMode
 *     (disable 1 / basic 2 / advance 3), .3 BasicGlobalTrustMode and
 *     .4 AdvcGlobalTrustMode (cos 1 / dscp 2 / cos-dscp 3), .7 RowStatus.
 *     The older scalars V.88.1 and V.88.2 do not answer on .253.
 *   rlQosIfPolicyTable V.88.13.1, index ifIndex.2: .5 TrustActive and
 *     .6 PortShaperStatus (disable 1 / enable 2), .7 CirPortShaper (kb/s),
 *     .8 CbsPortShaper (bytes), .10 QueueProfilePointer (name),
 *     .11 QueueShapeProfilePointer (0 = none). Its .17-.19 rate limit
 *     columns stay disabled on .253 when "rate-limit" is set: the CLI puts
 *     the rate in rlStormCtrlRateLimCfgTable traffic 'all' instead
 *     (switch-ports.js setStorm).
 *   rlQosQueueShapeProfileTable V.88.23.1 (index): CIR .2,.4,..,.16 and CBS
 *     .3,.5,..,.17 for queues 1 to 8 (CIR 0 = not shaped), .18 RowStatus.
 *   rlQosQueueProfileTable V.88.22.1 (name): queue type .2,.4,.. (ef 1 /
 *     wrr 2) and weight .3,.5,.. for queues 1 to 8.
 *   rlQosCosQueueTable V.88.17.1 (CoS 0-7): .2 queue; rlQosDscpQueueTable
 *     V.88.18.1 (DSCP 0-63): .2 queue. The defaults: V.88.29.1 and V.88.33.1
 *     (.1 the CoS or DSCP, .2 the queue).
 */

const { walkColumns, getRows, presentPorts, setStorm, STORM } = require('./switch-ports');
const { setVarbinds, tryForms, getInt, I, ROW } = require('./snmp-write');

const V = '1.3.6.1.4.1.9.6.1.101';
const T = {
  modeCfg: V + '.88.46.1',
  ifPolicy: V + '.88.13.1',
  queueProfile: V + '.88.22.1',
  shapeProfile: V + '.88.23.1',
  cosQueue: V + '.88.17.1',
  dscpQueue: V + '.88.18.1',
  cosDefault: V + '.88.29.1',
  dscpDefault: V + '.88.33.1'
};
const MODE = { 1: 'disable', 2: 'basic', 3: 'advanced' };
const TRUST = { 1: 'cos', 2: 'dscp', 3: 'cos-dscp' };
const ON = 2, OFF = 1; // BinaryStatus
const QUEUES = 8;
const DEFAULT_CBS = 128000; // what the switch writes for "traffic-shape <cir>"

// A walked value comes as display text ("down (2)", "1,500"); a GET as a number.
const num = (v) => {
  if (v == null || v === '') return null;
  if (Buffer.isBuffer(v)) return null;
  const m = /\((-?\d+)\)\s*$/.exec(String(v));
  const n = Number(m ? m[1] : String(v).replace(/,/g, ''));
  return Number.isFinite(n) ? n : null;
};
const text = (v) => (v == null ? '' : Buffer.isBuffer(v) ? v.toString('utf8') : String(v));
const keyOf = (name, enumMap) => {
  const k = Object.keys(enumMap).find((n) => enumMap[n] === name);
  return k == null ? null : Number(k);
};
// A name index (length, then the bytes) back to text: "7.100.101..." -> "default".
const nameOfIndex = (index) => String.fromCharCode.apply(null, index.slice(1));

const shapeQueues = (cols) => Array.from({ length: QUEUES }, (_, k) => ({
  queue: k + 1, cir: num(cols[2 + 2 * k]) || 0, cbs: num(cols[3 + 2 * k]) || 0
}));

/** Everything the QoS panel shows; a part the switch does not answer is null or empty. */
async function readQos(session) {
  const safe = (p, empty) => p.catch(() => empty);
  const cfg = (await safe(walkColumns(session, T.modeCfg, [2, 3, 4, 7]), []))[0];
  const ifs = await safe(presentPorts(session), []);
  const policy = await safe(getRows(session, T.ifPolicy, [5, 6, 7, 8, 10, 11], ifs.map((i) => i + '.2')), []);
  const rates = await safe(getRows(session, STORM, [2], ifs.map((i) => i + '.6')), []);
  const shapes = await safe(walkColumns(session, T.shapeProfile, Array.from({ length: 17 }, (_, k) => k + 2)), []);
  const profiles = await safe(walkColumns(session, T.queueProfile, Array.from({ length: 16 }, (_, k) => k + 2)), []);
  const cos = await safe(walkColumns(session, T.cosQueue, [2]), []);
  const dscp = await safe(walkColumns(session, T.dscpQueue, [2]), []);
  const cosDef = await safe(walkColumns(session, T.cosDefault, [1, 2]), []);
  const dscpDef = await safe(walkColumns(session, T.dscpDefault, [1, 2]), []);

  const shapeBy = new Map(shapes.map((r) => [r.index[0], shapeQueues(r.cols)]));
  const rateBy = new Map(rates.map((r) => [r.index[0], num(r.cols[2])]));
  const ports = policy.map((r) => {
    const c = r.cols, ifIndex = r.index[0], ptr = num(c[11]) || 0;
    return {
      ifIndex,
      trust: num(c[5]) === ON,
      shaper: { on: num(c[6]) === ON, cir: num(c[7]) || 0, cbs: num(c[8]) || 0 },
      rateLimit: rateBy.has(ifIndex) ? rateBy.get(ifIndex) : null,
      queueProfile: text(c[10]) || null,
      queueShaper: ptr ? { profile: ptr, queues: (shapeBy.get(ptr) || []).filter((q) => q.cir > 0) } : null
    };
  });
  const map = (rows, defs, field) => {
    const d = new Map(defs.map((r) => [num(r.cols[1]), num(r.cols[2])]));
    return rows.map((r) => ({ [field]: r.index[0], queue: num(r.cols[2]), default: d.has(r.index[0]) ? d.get(r.index[0]) : null }));
  };
  const sched = profiles.map((r) => ({
    name: nameOfIndex(r.index),
    queues: Array.from({ length: QUEUES }, (_, k) => ({ queue: k + 1, type: num(r.cols[2 + 2 * k]) === 2 ? 'wrr' : 'ef', weight: num(r.cols[3 + 2 * k]) }))
  }));
  return {
    mode: cfg ? (MODE[num(cfg.cols[2])] || null) : null,
    basicTrust: cfg ? (TRUST[num(cfg.cols[3])] || null) : null,
    advancedTrust: cfg ? (TRUST[num(cfg.cols[4])] || null) : null,
    ports,
    shapeProfiles: shapes.map((r) => ({ index: r.index[0], queues: shapeBy.get(r.index[0]) })),
    scheduling: sched,
    cosMap: map(cos, cosDef, 'cos'),
    dscpMap: map(dscp, dscpDef, 'dscp')
  };
}

// ---- writes ----------------------------------------------------------------

function checkIf(ifIndex) {
  const n = Number(ifIndex);
  if (!Number.isInteger(n) || n < 1 || n >= 1000) throw new Error('ifIndex must be a front-panel port.');
  return n;
}
function checkInt(v, lo, hi, what) {
  const n = Number(v);
  if (!Number.isInteger(n) || n < lo || n > hi) throw new Error(what + ' must be ' + lo + ' to ' + hi + '.');
  return n;
}
const checkRate = (v, what) => {
  const n = Number(v);
  if (n === 0) return 0;
  return checkInt(v, 64, 10000000, what + ' (kb/s, 0 = off)');
};
const checkCbs = (v) => (v == null || v === '' ? DEFAULT_CBS : checkInt(v, 4096, 16769020, 'The burst size (bytes)'));
const checkQueue = (v) => checkInt(v, 1, QUEUES, 'The queue');
const pol = (col, ifx) => T.ifPolicy + '.' + col + '.' + ifx + '.2';
const cfg = (col) => T.modeCfg + '.' + col + '.1';

/** The QoS mode: 'disable', 'basic' or 'advanced'. */
async function setMode(session, mode) {
  const n = keyOf(mode, MODE);
  if (!n) throw new Error('mode must be disable, basic or advanced.');
  const before = await getInt(session, cfg(2));
  const r = await tryForms(session, [
    ['GlobalQoSMode', [[I(cfg(2), n)]]],
    ['GlobalQoSMode with the row active', [[I(cfg(2), n), I(cfg(7), ROW.active)]]]
  ], async () => (await getInt(session, cfg(2))) === n, before ? [I(cfg(2), before)] : null);
  return Object.assign({ mode }, r);
}

/** What the switch trusts for the mode it is in: 'cos', 'dscp' or 'cos-dscp'. */
async function setTrust(session, trust) {
  const n = keyOf(trust, TRUST);
  if (!n) throw new Error('trust must be cos, dscp or cos-dscp.');
  const col = (await getInt(session, cfg(2))) === 3 ? 4 : 3;
  const r = await tryForms(session, [
    ['trust mode', [[I(cfg(col), n)]]],
    ['trust mode with the row active', [[I(cfg(col), n), I(cfg(7), ROW.active)]]]
  ], async () => (await getInt(session, cfg(col))) === n, null);
  return Object.assign({ trust, mode: col === 4 ? 'advanced' : 'basic' }, r);
}

/** Trust on or off for one port (basic mode). */
async function setPortTrust(session, ifIndex, on) {
  const ifx = checkIf(ifIndex), want = on ? ON : OFF;
  await setVarbinds(session, [I(pol(5, ifx), want)]);
  if ((await getInt(session, pol(5, ifx))) !== want) throw new Error('The port trust did not change.');
  return { ifIndex: ifx, trust: !!on };
}

/** The egress shaper of one port: CIR in kb/s (0 turns it off), burst in bytes. */
async function setPortShaper(session, ifIndex, cir, cbs) {
  const ifx = checkIf(ifIndex), rate = checkRate(cir, 'The shaper rate');
  if (rate === 0) {
    await setVarbinds(session, [I(pol(6, ifx), OFF)]);
    if ((await getInt(session, pol(6, ifx))) !== OFF) throw new Error('The shaper did not turn off.');
    return { ifIndex: ifx, cir: 0, via: 'PortShaperStatus disable', refused: [] };
  }
  const burst = checkCbs(cbs);
  const wasOn = (await getInt(session, pol(6, ifx))) === ON;
  const cols = [I(pol(7, ifx), rate), I(pol(8, ifx), burst)];
  const r = await tryForms(session, [
    ['status, rate and burst together', [[I(pol(6, ifx), ON)].concat(cols)]],
    ['rate and burst, then status', [cols, [I(pol(6, ifx), ON)]]]
  ], async () => (await getInt(session, pol(6, ifx))) === ON && (await getInt(session, pol(7, ifx))) === rate,
  wasOn ? null : [I(pol(6, ifx), OFF)]);
  return Object.assign({ ifIndex: ifx, cir: rate, cbs: burst }, r);
}

/** The ingress rate limit of one port in kb/s; 0 turns it off. */
async function setRateLimit(session, ifIndex, rate) {
  const ifx = checkIf(ifIndex), n = checkRate(rate, 'The rate limit');
  await setStorm(session, ifx, 'all', n);
  if ((await getInt(session, STORM + '.2.' + ifx + '.6')) !== n) throw new Error('The rate limit did not change.');
  return { ifIndex: ifx, rate: n };
}

/**
 * The shaper of one egress queue on one port: CIR in kb/s (0 turns it off),
 * burst in bytes. A port points at a shape profile row (.11); a port with no
 * profile gets a new row, made as the switch made one for the CLI: every
 * queue's CBS set, CIR 0 for the queues not shaped. When the last shaped
 * queue is turned off, the port's pointer goes back to 0 and the row is
 * removed.
 */
async function setQueueShaper(session, ifIndex, queue, cir, cbs) {
  const ifx = checkIf(ifIndex), q = checkQueue(queue), rate = checkRate(cir, 'The queue shaper rate');
  const burst = checkCbs(cbs);
  const sp = (col, idx) => T.shapeProfile + '.' + col + '.' + idx;
  const cirCol = 2 * q, cbsCol = 2 * q + 1;
  const ptr = await getInt(session, pol(11, ifx)) || 0;

  if (ptr) {
    const before = { cir: await getInt(session, sp(cirCol, ptr)), cbs: await getInt(session, sp(cbsCol, ptr)) };
    const r = await tryForms(session, [
      ['the queue columns', [[I(sp(cirCol, ptr), rate), I(sp(cbsCol, ptr), burst)]]],
      ['the queue rate only', [[I(sp(cirCol, ptr), rate)]]]
    ], async () => (await getInt(session, sp(cirCol, ptr))) === rate,
    before.cir == null ? null : [I(sp(cirCol, ptr), before.cir), I(sp(cbsCol, ptr), before.cbs == null ? DEFAULT_CBS : before.cbs)]);
    let removed = false;
    if (rate === 0) {
      const left = (await getRows(session, T.shapeProfile, [2, 4, 6, 8, 10, 12, 14, 16], [String(ptr)]))[0];
      if (!left || Object.values(left.cols).every((v) => !num(v))) {
        await setVarbinds(session, [I(pol(11, ifx), 0)]).catch(() => {});
        removed = (await getInt(session, pol(11, ifx))) === 0;
        if (removed) await setVarbinds(session, [I(sp(18, ptr), ROW.destroy)]).catch(() => {});
      }
    }
    return Object.assign({ ifIndex: ifx, queue: q, cir: rate, cbs: burst, profile: ptr, profileRemoved: removed }, r);
  }
  if (rate === 0) return { ifIndex: ifx, queue: q, cir: 0, profile: 0, via: 'nothing to turn off', refused: [] };

  const used = (await walkColumns(session, T.shapeProfile, [18])).map((r) => r.index[0]);
  const idx = used.length ? Math.max.apply(null, used) + 1 : 1;
  const all = [];
  for (let k = 1; k <= QUEUES; k++) {
    all.push(I(sp(2 * k, idx), k === q ? rate : 0), I(sp(2 * k + 1, idx), k === q ? burst : DEFAULT_CBS));
  }
  const point = [I(pol(11, ifx), idx)];
  const r = await tryForms(session, [
    ['createAndGo with every queue, then the port pointer', [[I(sp(18, idx), ROW.createAndGo)].concat(all), point]],
    ['createAndGo with the shaped queue, then the port pointer', [[I(sp(18, idx), ROW.createAndGo), all[2 * q - 2], all[2 * q - 1]], point]],
    ['createAndWait, columns, active, then the port pointer', [[I(sp(18, idx), ROW.createAndWait)], all, [I(sp(18, idx), ROW.active)], point]]
  ], async () => (await getInt(session, pol(11, ifx))) === idx && (await getInt(session, sp(cirCol, idx))) === rate,
  async () => {
    await setVarbinds(session, [I(pol(11, ifx), 0)]).catch(() => {});
    await setVarbinds(session, [I(sp(18, idx), ROW.destroy)]).catch(() => {});
  });
  return Object.assign({ ifIndex: ifx, queue: q, cir: rate, cbs: burst, profile: idx, profileRemoved: false }, r);
}

/** Which egress queue a CoS value (0-7) goes to. */
async function setCosQueue(session, cos, queue) {
  const c = checkInt(cos, 0, 7, 'The CoS'), q = checkQueue(queue);
  const oid = T.cosQueue + '.2.' + c;
  await setVarbinds(session, [I(oid, q)]);
  if ((await getInt(session, oid)) !== q) throw new Error('The CoS map did not change.');
  return { cos: c, queue: q };
}

/** Which egress queue a DSCP value (0-63) goes to. */
async function setDscpQueue(session, dscp, queue) {
  const d = checkInt(dscp, 0, 63, 'The DSCP'), q = checkQueue(queue);
  const oid = T.dscpQueue + '.2.' + d;
  await setVarbinds(session, [I(oid, q)]);
  if ((await getInt(session, oid)) !== q) throw new Error('The DSCP map did not change.');
  return { dscp: d, queue: q };
}

/** Put the CoS or DSCP map back to the switch's defaults; only the entries that differ are written. */
async function restoreMap(session, which) {
  if (which !== 'cos' && which !== 'dscp') throw new Error('map must be cos or dscp.');
  const table = which === 'cos' ? T.cosQueue : T.dscpQueue;
  const defs = await walkColumns(session, which === 'cos' ? T.cosDefault : T.dscpDefault, [1, 2]);
  const now = new Map((await walkColumns(session, table, [2])).map((r) => [r.index[0], num(r.cols[2])]));
  const vbs = defs.map((r) => [num(r.cols[1]), num(r.cols[2])])
    .filter(([k, q]) => k != null && q && now.get(k) !== q)
    .map(([k, q]) => I(table + '.2.' + k, q));
  for (let i = 0; i < vbs.length; i += 16) await setVarbinds(session, vbs.slice(i, i + 16));
  return { map: which, changed: vbs.length };
}

module.exports = {
  readQos, setMode, setTrust, setPortTrust, setPortShaper, setRateLimit, setQueueShaper,
  setCosQueue, setDscpQueue, restoreMap, T, MODE, TRUST
};
