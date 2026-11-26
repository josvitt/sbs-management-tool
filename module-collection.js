'use strict';

/**
 * The panels whose data is a server-side view rather than health tables --
 * SNMP configuration, Flash files, Packet capture, Reboot and firmware -- read for the server
 * collector (SERVER-STANDARD §3c), so they ride the snapshot like every other
 * panel instead of loading when opened.
 *
 * One session, the reads one after another (a C1300 agent handles concurrent
 * sessions badly, especially right after a VACM or community change), closed at
 * the end. Each module's reader is the same function its route uses, so the
 * snapshot and a live read can never disagree in shape. A module that fails
 * comes back as { ok: false, error } and does not stop the others.
 */

const { buildSnmpSession, snmpConfigBundle } = require('./snmp-core');
const snmpConfig = require('./snmp-config');
const { listFlash } = require('./routes/flash');
const { listCaptures } = require('./routes/opc');
const { readMaint } = require('./switch-maint');
const { readSystem } = require('./switch-system');
const { readPorts } = require('./switch-ports');
const { readStp } = require('./switch-stp');
const { readSecurity } = require('./switch-security');
const { readIpv6 } = require('./switch-ipv6');
const { readQos } = require('./switch-qos');

const READERS = {
  snmpConfig: (session, target) => snmpConfig.readAll(snmpConfigBundle(session), {
    version: target.version, community: target.community, user: target.v3 && target.v3.username
  }),
  flash: (session) => listFlash(session),
  captures: (session) => listCaptures(session),
  maint: (session) => readMaint(session),
  system: (session) => readSystem(session),
  ports: (session) => readPorts(session),
  stp: (session) => readStp(session),
  security: (session) => readSecurity(session),
  ipv6: (session) => readIpv6(session),
  qos: (session) => readQos(session)
};

const MODULE_KEYS = Object.keys(READERS);

async function collectModulesFor(target, keys) {
  const out = {};
  const want = (keys || MODULE_KEYS).filter((k) => READERS[k]);
  if (!want.length) return out;
  const session = buildSnmpSession(target);
  session.on('error', () => { /* a reply that fails to parse; the read reports it */ });
  try {
    for (const key of want) {
      try { out[key] = await READERS[key](session, target); }
      catch (e) { out[key] = { ok: false, error: e.message }; }
    }
  } finally {
    try { session.close(); } catch (e) { /* already closed */ }
  }
  return out;
}

module.exports = { collectModulesFor, MODULE_KEYS };
