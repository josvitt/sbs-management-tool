'use strict';

/**
 * Spanning tree settings over SNMP: the mode, the bridge priority (for the
 * whole switch, per VLAN under PVST, per instance under MSTP) and, per port,
 * the cost, priority, edge (PortFast) and BPDU guard.
 *
 * The health reader (health.js) already shows the running tree; this module
 * reads the settings behind it and writes them.
 *
 * Objects (vendor root V = 1.3.6.1.4.1.9.6.1.101 unless noted):
 *   dot1dStp 1.3.6.1.2.1.17.2: .2 Priority (rw), .16 Version (rw:
 *     stpCompatible 0, rstp 2, mstp 3, pvst 6, rpvst 8), .12-.14 the bridge
 *     max age, hello and forward delay (centiseconds)
 *   dot1dStpPortTable 17.2.15.1 (bridge port): .2 Priority, .4 Enable,
 *     .5 PathCost
 *   dot1dStpExtPortTable 17.2.19.1 (bridge port): .2 AdminEdgePort,
 *     .3 OperEdgePort, .4 AdminPointToPoint, .6 AdminPathCost (0 = auto)
 *   dot1dBasePortTable 17.1.4.1 (bridge port): .2 IfIndex
 *   rldot1dStp V.57.2: .3 Enable, .2 Type, .19 SupportedType, .21 FilterBpdu,
 *     .25 LoopbackGuardEnable; rldot1dStpPortTable .13.1 (bridge port):
 *     .4 FilterBpdu, .7 Role, .9 RestrictedRole, .10 AutoEdgePort,
 *     .12 BpduOperStatus, .13 TcnGuardEnable; rldot1dStpPortBpduGuardTable
 *     .24.1: .1 Enable
 *   rlBrgPvst V.57.9: .1.1 VLAN settings (VLAN; .2 hello, .3 forward delay,
 *     .4 max age, .5 Priority, .6 row status), .3.1 port settings per VLAN
 *     (VLAN, port; .3 PathCost, .4 Priority, .5 row status)
 *   rldot1sMstp V.57.6: .1.1 instances (.12 Priority), .2.1 instance ports
 *     (instance, port; .3 Priority, .12 AdminPathCost)
 */

const snmp = require('net-snmp');
const { walkColumns, getRows } = require('./switch-ports');

const V = '1.3.6.1.4.1.9.6.1.101';
const DOT1D = '1.3.6.1.2.1.17.2';
const STP_PORT = DOT1D + '.15.1';
const STP_EXT = DOT1D + '.19.1';
const BASE_PORT = '1.3.6.1.2.1.17.1.4.1';
const RL_STP = V + '.57.2';
const RL_PORT = RL_STP + '.13.1';
const BPDU_GUARD = RL_STP + '.24.1';
const PVST_VLAN = V + '.57.9.1.1';
const PVST_PORT = V + '.57.9.3.1';
const MSTP_INST = V + '.57.6.1.1';
const MSTP_PORT = V + '.57.6.2.1';

const SCALARS = {
  enable: RL_STP + '.3.0',
  version: DOT1D + '.16.0',
  priority: DOT1D + '.2.0',
  type: RL_STP + '.2.0',
  supportedType: RL_STP + '.19.0',
  filterBpdu: RL_STP + '.21.0',
  loopbackGuard: RL_STP + '.25.0',
  maxAge: DOT1D + '.12.0',
  helloTime: DOT1D + '.13.0',
  forwardDelay: DOT1D + '.14.0',
  pathCostDefault: DOT1D + '.18.0'
};

const MODE = { 0: 'stp', 2: 'rstp', 3: 'mstp', 6: 'pvst', 8: 'rapid-pvst' };
const ROLE = { 1: 'disabled', 2: 'alternate', 3: 'backup', 4: 'root', 5: 'designated', 6: 'master' };
const P2P = { 0: 'on', 1: 'off', 2: 'auto' };

const num = (v) => (v == null ? null : Number(v));
const truth = (v) => (v == null ? null : Number(v) === 1);
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

const byKey = (rows) => new Map(rows.map((r) => [r.key, r.cols]));

/**
 * The settings. Resolves { enabled, mode, priority, timers, ports, vlans,
 * instances }: ports by bridge port with the ifIndex each maps to; vlans and
 * instances carry their own bridge priority and the per-port rows the
 * switch keeps for them.
 */
async function readStp(session) {
  const s = await getScalars(session);
  const ifOf = byKey(await walkColumns(session, BASE_PORT, [2]));
  const std = await walkColumns(session, STP_PORT, [2, 4, 5]);
  // The extended, vendor and BPDU guard tables carry a row for every
  // possible port (424 on a 24-port C1300); only the bridge's own ports are
  // read, with a GET each.
  const keys = std.map((r) => r.key);
  const ext = byKey(await getRows(session, STP_EXT, [2, 3, 4, 6], keys));
  const rl = byKey(await getRows(session, RL_PORT, [4, 7, 9, 10, 12, 13], keys));
  const guard = byKey(await getRows(session, BPDU_GUARD, [1], keys));
  const ports = std.map((r) => {
    const x = ext.get(r.key) || {}, y = rl.get(r.key) || {}, g = guard.get(r.key) || {};
    const ifx = (ifOf.get(r.key) || {})[2];
    return {
      port: r.index[0],
      ifIndex: ifx == null ? null : Number(ifx),
      enabled: truth(r.cols[4]),
      priority: num(r.cols[2]),
      cost: num(r.cols[5]),
      adminCost: num(x[6]),
      edge: truth(x[2]),
      autoEdge: truth(y[10]),
      operEdge: truth(x[3]),
      p2p: named(P2P, x[4]),
      bpduGuard: truth(g[1]),
      rootGuard: truth(y[9]),
      tcnGuard: truth(y[13]),
      filterBpdu: num(y[4]),
      role: named(ROLE, y[7])
    };
  });
  const pvstPorts = await walkColumns(session, PVST_PORT, [3, 4, 5]);
  const vlans = (await walkColumns(session, PVST_VLAN, [2, 3, 4, 5, 6])).map((r) => ({
    vlan: r.index[0],
    priority: num(r.cols[5]),
    helloTime: num(r.cols[2]), forwardDelay: num(r.cols[3]), maxAge: num(r.cols[4]),
    rowStatus: num(r.cols[6]),
    ports: pvstPorts.filter((p) => p.index[0] === r.index[0])
      .map((p) => ({ port: p.index[1], cost: num(p.cols[3]), priority: num(p.cols[4]), rowStatus: num(p.cols[5]) }))
  }));
  const mstpPorts = await walkColumns(session, MSTP_PORT, [3, 12]);
  const instances = (await walkColumns(session, MSTP_INST, [12])).map((r) => ({
    instance: r.index[0],
    priority: num(r.cols[12]),
    ports: mstpPorts.filter((p) => p.index[0] === r.index[0])
      .map((p) => ({ port: p.index[1], priority: num(p.cols[3]), adminCost: num(p.cols[12]) }))
  }));
  return {
    enabled: truth(s.enable),
    mode: named(MODE, s.version),
    priority: num(s.priority),
    type: num(s.type),
    supportedType: num(s.supportedType),
    filterBpdu: truth(s.filterBpdu),
    loopbackGuard: truth(s.loopbackGuard),
    pathCostDefault: num(s.pathCostDefault),
    timers: { maxAge: num(s.maxAge), helloTime: num(s.helloTime), forwardDelay: num(s.forwardDelay) },
    ports, vlans, instances
  };
}

// ---- writes ----------------------------------------------------------------
// Each is encoded from the rows the switch made (docs/SWITCH-NOTES.md,
// "Spanning tree"). Nothing here saves the configuration.

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

function checkPort(port) {
  const n = Number(port);
  if (!Number.isInteger(n) || n < 1 || n > 4096) throw new Error('port must be a bridge port number.');
  return n;
}

function checkBridgePriority(priority) {
  const n = Number(priority);
  if (!Number.isInteger(n) || n < 0 || n > 61440 || n % 4096) throw new Error('The bridge priority is 0 to 61440, in steps of 4096.');
  return n;
}

function checkPortPriority(priority) {
  const n = Number(priority);
  if (!Number.isInteger(n) || n < 0 || n > 240 || n % 16) throw new Error('The port priority is 0 to 240, in steps of 16.');
  return n;
}

function checkCost(cost) {
  const n = Number(cost);
  if (!Number.isInteger(n) || n < 0 || n > 200000000) throw new Error('The cost is 0 (automatic) to 200000000.');
  return n;
}

/** Spanning tree on or off for the whole switch. */
async function setEnabled(session, on) {
  await setVarbinds(session, [I(SCALARS.enable, TV(on))]);
  return { enabled: !!on };
}

/** The mode: 'stp', 'rstp', 'mstp', 'pvst' or 'rapid-pvst'. */
async function setMode(session, mode) {
  const v = Object.keys(MODE).find((k) => MODE[k] === mode);
  if (v == null) throw new Error('mode must be stp, rstp, mstp, pvst or rapid-pvst.');
  await setVarbinds(session, [I(SCALARS.version, Number(v))]);
  return { mode };
}

/**
 * The bridge priority: for the whole switch (STP, RSTP and the MSTP
 * common instance), for one VLAN (`where.vlan`, PVST) or for one MSTP
 * instance (`where.instance`).
 */
async function setBridgePriority(session, priority, where) {
  const n = checkBridgePriority(priority);
  const w = where || {};
  if (w.vlan != null) {
    const vlan = checkVlan(w.vlan);
    const via = await setRowForms(session, PVST_VLAN, 6, String(vlan), [I(PVST_VLAN + '.5.' + vlan, n)]);
    return { priority: n, vlan, via };
  }
  let oid;
  if (w.instance != null) {
    const inst = Number(w.instance);
    if (!Number.isInteger(inst) || inst < 0 || inst > 4094) throw new Error('instance is 0 to 4094.');
    oid = MSTP_INST + '.12.' + inst;
  } else oid = SCALARS.priority;
  await setVarbinds(session, [I(oid, n)]);
  return Object.assign({ priority: n }, w);
}

function checkVlan(v) {
  const vlan = Number(v);
  if (!Number.isInteger(vlan) || vlan < 1 || vlan > 4094) throw new Error('vlan is 1 to 4094.');
  return vlan;
}

/**
 * Columns of a PVST row (rlBrgPvstVlanTable, rlBrgPvstPortTable). A C1300
 * keeps a row only for a VLAN or port given its own settings, so the row
 * may need making. The forms are tried in turn and every one tried is kept
 * in the error (MODULE-STANDARD rule 6). Resolves the form that worked.
 */
async function setRowForms(session, table, statusCol, idx, cols) {
  const st = (v) => I(table + '.' + statusCol + '.' + idx, v);
  const forms = [
    ['the columns, on the row as it is', [cols]],
    ['createAndGo with the columns', [[st(ROW.createAndGo)].concat(cols)]],
    ['createAndWait, the columns, then active', [[st(ROW.createAndWait)], cols, [st(ROW.active)]]]
  ];
  const tried = [];
  for (const [name, steps] of forms) {
    try {
      for (const vbs of steps) await setVarbinds(session, vbs);
      return name;
    } catch (e) {
      tried.push(name + ': ' + e.message);
      if (name.indexOf('createAndWait') === 0) { try { await setVarbinds(session, [st(ROW.destroy)]); } catch (x) { /* nothing made */ } }
    }
  }
  throw new Error('The switch refused every form (' + tried.join('; ') + ').');
}

/** Remove a VLAN's own spanning tree settings (its PVST row), back to the defaults. */
async function resetVlan(session, vlan) {
  const v = checkVlan(vlan);
  await setVarbinds(session, [I(PVST_VLAN + '.6.' + v, ROW.destroy)]);
  return { vlan: v, reset: true };
}

/** Remove a port's own settings in one VLAN (its PVST port row). */
async function resetPortInVlan(session, vlan, port) {
  const v = checkVlan(vlan), n = checkPort(port);
  await setVarbinds(session, [I(PVST_PORT + '.5.' + v + '.' + n, ROW.destroy)]);
  return { vlan: v, port: n, reset: true };
}

/**
 * One port's settings, by bridge port: any of enabled, priority, cost
 * (0 = automatic), edge (PortFast), autoEdge and bpduGuard.
 */
async function setPort(session, port, p) {
  const n = checkPort(port);
  const vbs = [];
  if (p.enabled != null) vbs.push(I(STP_PORT + '.4.' + n, p.enabled ? 1 : 2));
  if (p.priority != null) vbs.push(I(STP_PORT + '.2.' + n, checkPortPriority(p.priority)));
  if (p.cost != null) vbs.push(I(STP_EXT + '.6.' + n, checkCost(p.cost)));
  if (p.edge != null) vbs.push(I(STP_EXT + '.2.' + n, TV(p.edge)));
  if (p.autoEdge != null) vbs.push(I(RL_PORT + '.10.' + n, TV(p.autoEdge)));
  if (p.bpduGuard != null) vbs.push(I(BPDU_GUARD + '.1.' + n, TV(p.bpduGuard)));
  if (!vbs.length) throw new Error('Nothing to change.');
  // One SET each: a refused column then names itself and leaves the others.
  const done = [];
  for (const vb of vbs) {
    try { await setVarbinds(session, [vb]); done.push(vb.oid); }
    catch (e) { e.message = e.message + ' (' + vb.oid + (done.length ? '; already set: ' + done.join(', ') : '') + ')'; throw e; }
  }
  return { port: n, set: p };
}

/** One port's priority or cost in one VLAN (PVST) or MSTP instance. */
async function setPortIn(session, where, port, p) {
  const n = checkPort(port);
  const w = where || {};
  const vbs = [];
  if (w.vlan != null) {
    const idx = checkVlan(w.vlan) + '.' + n;
    if (p.cost != null) vbs.push(I(PVST_PORT + '.3.' + idx, checkCost(p.cost)));
    if (p.priority != null) vbs.push(I(PVST_PORT + '.4.' + idx, checkPortPriority(p.priority)));
    if (!vbs.length) throw new Error('Nothing to change.');
    const via = await setRowForms(session, PVST_PORT, 5, idx, vbs);
    return Object.assign({ port: n, set: p, via }, w);
  } else if (w.instance != null) {
    const idx = Number(w.instance) + '.' + n;
    if (p.priority != null) vbs.push(I(MSTP_PORT + '.3.' + idx, checkPortPriority(p.priority)));
    if (p.cost != null) vbs.push(I(MSTP_PORT + '.12.' + idx, checkCost(p.cost)));
  } else throw new Error('Name a vlan or an instance.');
  if (!vbs.length) throw new Error('Nothing to change.');
  await setVarbinds(session, vbs);
  return Object.assign({ port: n, set: p }, w);
}

module.exports = {
  readStp, setEnabled, setMode, setBridgePriority, setPort, setPortIn, resetVlan, resetPortInVlan, SCALARS, MODE, DOT1D, STP_PORT, STP_EXT, BASE_PORT, RL_STP, RL_PORT, BPDU_GUARD,
  PVST_VLAN, PVST_PORT, MSTP_INST, MSTP_PORT
};
