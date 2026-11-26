'use strict';

/**
 * Write helpers shared by the switch modules that encode SNMP row writes
 * (switch-ipv6.js, switch-qos.js): a SET that rejects on any varbind error,
 * single-value GETs, and tryForms, which tries the ways of making a change
 * in turn (docs/MODULE-STANDARD.md rule 6). Nothing here saves the
 * configuration.
 */

const snmp = require('net-snmp');

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
const OT = snmp.ObjectType;
const I = (oid, value) => ({ oid, type: OT.Integer, value });
const G = (oid, value) => ({ oid, type: OT.Gauge, value });
const OCT = (oid, value) => ({ oid, type: OT.OctetString, value });
const ROW = { active: 1, createAndGo: 4, createAndWait: 5, destroy: 6 };

/**
 * Try the ways of making a change in turn until one reads back: forms is
 * [[name, [pdu, ...]], ...]. A form that fails is undone before the next:
 * undo is one PDU, or a function for an undo that takes more than one.
 * Resolves { via, refused }; when every form fails, the error names each one
 * and what the switch said.
 */
async function tryForms(session, forms, readsBack, undo) {
  const refused = [];
  for (const [name, steps] of forms) {
    try {
      for (const step of steps) await setVarbinds(session, step);
      if (!(await readsBack())) throw new Error('the change does not read back');
      return { via: name, refused };
    } catch (e) {
      refused.push(name + ': ' + e.message);
      if (typeof undo === 'function') await Promise.resolve().then(undo).catch(() => {});
      else if (undo && undo.length) await setVarbinds(session, undo).catch(() => {});
    }
  }
  throw new Error('The switch refused every form (' + refused.join('; ') + ').');
}

async function getOne(session, oid) {
  const vbs = await new Promise((resolve, reject) => session.get([oid], (e, v) => (e ? reject(e) : resolve(v)))).catch(() => null);
  const vb = vbs && vbs[0];
  return vb && !snmp.isVarbindError(vb) ? vb : null;
}
async function getInt(session, oid) {
  const vb = await getOne(session, oid);
  return vb ? Number(vb.value) : null;
}
async function getBytes(session, oid) {
  const vb = await getOne(session, oid);
  return vb && Buffer.isBuffer(vb.value) ? vb.value : null;
}
async function rowStatusIs(session, oid, want) {
  return (await getInt(session, oid)) === want;
}

module.exports = { setVarbinds, tryForms, getInt, getBytes, rowStatusIs, I, G, OCT, ROW, OT };
