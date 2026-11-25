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
const { walkColumns } = require('./switch-ports');

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
  const ext = byKey(await walkColumns(session, STP_EXT, [2, 3, 4, 6]));
  const rl = byKey(await walkColumns(session, RL_PORT, [4, 7, 9, 10, 12, 13]));
  const guard = byKey(await walkColumns(session, BPDU_GUARD, [1]));
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

module.exports = {
  readStp, SCALARS, MODE, DOT1D, STP_PORT, STP_EXT, BASE_PORT, RL_STP, RL_PORT, BPDU_GUARD,
  PVST_VLAN, PVST_PORT, MSTP_INST, MSTP_PORT
};
