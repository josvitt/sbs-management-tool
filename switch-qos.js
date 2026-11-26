'use strict';

/**
 * QoS over SNMP (CISCOSB-QOS-CLI-MIB, V.88). This first part reads; the
 * writes follow once a recording shows which of these tables a C1300 fills
 * for the QoS mode, trust, the CoS and DSCP queue maps, port shapers and
 * rate limits, and the queue scheduling (docs/MODULE-STANDARD rule 5).
 *
 * Objects (vendor root V = 1.3.6.1.4.1.9.6.1.101):
 *   rlQosCliQosMode V.88.1 (disable 1 / basic 2 / advance 3; deprecated for
 *     rlQosModeGlobalCfgTable), rlQosCliBasicModeCfg V.88.2 (cos 1 / dscp 2 /
 *     cos-dscp 3)
 *   rlQosModeGlobalCfgTable V.88.46.1 (.2 GlobalQoSMode, .3 BasicGlobalTrustMode,
 *     .4 AdvcGlobalTrustMode, .7 RowStatus)
 *   rlQosIfPolicyTable V.88.13.1 (.5 TrustActive, .6 PortShaperStatus,
 *     .7 CirPortShaper, .8 CbsPortShaper, .9 IfProfilePointer,
 *     .10 QueueProfilePointer, .11 QueueShapeProfilePointer, .16 IfPolicerIn,
 *     .17 PortRateLimitStatus, .18 CirPortRateLimit, .19 CbsPortRateLimit)
 *   rlQosQueueProfileTable V.88.22.1 (queue type and weight per queue)
 *   rlQosQueueShapeProfileTable V.88.23.1 (CIR and CBS per queue)
 *   rlQosCosQueueTable V.88.17.1, rlQosDscpQueueTable V.88.18.1 (the maps),
 *   rlQosCosQueueDefaultMapTable V.88.29.1, rlQosDscpQueueDefaultMapTable
 *     V.88.33.1 (the defaults), rlQosEfTable V.88.21.1
 *   dot1dTrafficClassesEnabled 1.3.6.1.2.1.17.6.1.1.2
 */

const snmp = require('net-snmp');
const { walkColumns } = require('./switch-ports');

const V = '1.3.6.1.4.1.9.6.1.101';
const T = {
  modeCfg: V + '.88.46.1',
  ifPolicy: V + '.88.13.1',
  queueProfile: V + '.88.22.1',
  shapeProfile: V + '.88.23.1',
  cosQueue: V + '.88.17.1',
  dscpQueue: V + '.88.18.1',
  cosDefault: V + '.88.29.1',
  dscpDefault: V + '.88.33.1',
  ef: V + '.88.21.1'
};
const SCALARS = { qosMode: V + '.88.1.0', basicTrust: V + '.88.2.0', trafficClasses: '1.3.6.1.2.1.17.6.1.1.2.0' };
const MODE = { 1: 'disable', 2: 'basic', 3: 'advanced' };
const TRUST = { 1: 'cos', 2: 'dscp', 3: 'cos-dscp' };

// A walked value comes as display text ("down (2)", "1,500"); a GET as a number.
const num = (v) => {
  if (v == null || v === '') return null;
  const m = /\((-?\d+)\)\s*$/.exec(String(v));
  return Number(m ? m[1] : String(v).replace(/,/g, ''));
};

async function getScalars(session) {
  const names = Object.keys(SCALARS);
  const vbs = await new Promise((resolve, reject) => session.get(names.map((n) => SCALARS[n]), (e, v) => (e ? reject(e) : resolve(v))));
  const out = {};
  names.forEach((n, k) => { const vb = vbs[k]; out[n] = (!vb || snmp.isVarbindError(vb)) ? undefined : vb.value; });
  return out;
}

const range = (a, b) => Array.from({ length: b - a + 1 }, (_, k) => a + k);

/** Everything the QoS panel will show; a table the switch does not answer comes back empty. */
async function readQos(session) {
  const s = await getScalars(session).catch(() => ({}));
  const safe = async (table, cols) => { try { return await walkColumns(session, table, cols); } catch (e) { return []; } };
  const raw = (rows) => rows.map((r) => ({ index: r.key, cols: r.cols }));
  return {
    qosMode: s.qosMode == null ? null : (MODE[num(s.qosMode)] || String(s.qosMode)),
    basicTrust: s.basicTrust == null ? null : (TRUST[num(s.basicTrust)] || String(s.basicTrust)),
    trafficClasses: s.trafficClasses == null ? null : num(s.trafficClasses) === 1,
    modeCfg: raw(await safe(T.modeCfg, [2, 3, 4, 7])),
    ifPolicy: raw(await safe(T.ifPolicy, [5, 6, 7, 8, 9, 10, 11, 16, 17, 18, 19])),
    queueProfile: raw(await safe(T.queueProfile, range(2, 19))),
    shapeProfile: raw(await safe(T.shapeProfile, range(2, 18))),
    cosQueue: raw(await safe(T.cosQueue, [2])),
    dscpQueue: raw(await safe(T.dscpQueue, [2])),
    cosDefault: raw(await safe(T.cosDefault, [1, 2])),
    dscpDefault: raw(await safe(T.dscpDefault, [1, 2])),
    ef: raw(await safe(T.ef, [2, 3]))
  };
}

module.exports = { readQos, T, SCALARS };
