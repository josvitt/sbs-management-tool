'use strict';

/**
 * Port features (switch-ports.js): PoE settings, port security, storm
 * control, errdisable recovery, LLDP, CDP, EEE, port mirroring and the
 * cable test. Every route that changes the switch passes writeHold(), so
 * the collector is not reading while it writes.
 */

const { writeHold } = require('../write-hold');
const log = require('../logger');
const { buildSnmpSession, redactTarget } = require('../snmp-core');
const ports = require('../switch-ports');

function needTarget(req, res) {
  const t = req.body && req.body.target;
  if (!t || !t.host) { res.status(400).json({ error: 'target.host is required.' }); return null; }
  return t;
}

async function withSession(target, fn) {
  const session = buildSnmpSession(target);
  try { return await fn(session); }
  finally { try { session.close(); } catch (e) {} }
}

const USER_ERROR = /must|cannot|already|is required|is in use|Nothing to change|Unknown|Choose|is not in session|only port in the session|already in the session|is 0 to|is 1 to|is 30 to|There is no|in milliwatts|The test is/;

function writeRoute(app, path, what, fn) {
  app.post(path, writeHold(), async (req, res) => {
    const target = needTarget(req, res); if (!target) return;
    try {
      const r = await withSession(target, (s) => fn(s, req.body || {}));
      log.info('ports', what, Object.assign({ host: target.host }, r));
      res.json(Object.assign({ ok: true }, r));
    } catch (e) {
      log.error('ports', what + ' failed', { target: redactTarget(target), message: e.message });
      res.status(USER_ERROR.test(e.message) ? 400 : 502).json({ error: e.message });
    }
  });
}

module.exports = function register(app) {
  // Body: { target }
  app.post('/api/ports/status', async (req, res) => {
    const target = needTarget(req, res); if (!target) return;
    try {
      res.json(await withSession(target, (s) => ports.readPorts(s)));
    } catch (e) {
      res.status(502).json({ error: e.message });
    }
  });

  // { group, port, admin?, priority?, limitMw? }
  writeRoute(app, '/api/ports/poe', 'PoE settings changed', (s, b) =>
    ports.setPoe(s, b.group, b.port, { admin: b.admin, priority: b.priority, limitMw: b.limitMw }));
  // { ifIndex, locked?, mode?, maxMacs? }
  writeRoute(app, '/api/ports/security', 'Port security changed', (s, b) =>
    ports.setPortSecurity(s, b.ifIndex, { locked: b.locked, mode: b.mode, maxMacs: b.maxMacs }));
  // { ifIndex, traffic: 'broadcast' | 'multicastAll' | 'unknownUnicast', rate }
  writeRoute(app, '/api/ports/storm', 'Storm control changed', (s, b) => ports.setStorm(s, b.ifIndex, b.traffic, b.rate));
  // { seconds }
  writeRoute(app, '/api/ports/errdisable/interval', 'Errdisable recovery interval set', (s, b) => ports.setErrdisableInterval(s, b.seconds));
  // { cause, on }
  writeRoute(app, '/api/ports/errdisable/cause', 'Errdisable recovery cause changed', (s, b) => ports.setErrdisableCause(s, b.cause, !!b.on));
  // { feature: 'lldp' | 'cdp' | 'eee', on }
  writeRoute(app, '/api/ports/global', 'Port feature turned on or off', (s, b) => ports.setGlobal(s, b.feature, !!b.on));
  // { ifIndex, lldp?: 'txAndRx' | ..., cdp?: bool, eee?: bool }
  writeRoute(app, '/api/ports/discovery', 'Port LLDP, CDP or EEE changed', async (s, b) => {
    const out = {};
    if (b.lldp != null) Object.assign(out, await ports.setLldpPort(s, b.ifIndex, b.lldp));
    if (b.cdp != null) Object.assign(out, await ports.setCdpPort(s, b.ifIndex, !!b.cdp));
    if (b.eee != null) Object.assign(out, await ports.setEeePort(s, b.ifIndex, !!b.eee));
    if (!Object.keys(out).length) throw new Error('Nothing to change.');
    return out;
  });
  // { session, dest, sources: [{ ifIndex, direction }] }
  writeRoute(app, '/api/ports/mirror/add', 'Mirroring session added', (s, b) => ports.addMirror(s, b.session, b.dest, b.sources));
  // { session, ifIndex, direction } / { session, ifIndex }
  writeRoute(app, '/api/ports/mirror/source/add', 'Port added to a mirroring session', (s, b) => ports.addMirrorSource(s, b.session, b.ifIndex, b.direction));
  writeRoute(app, '/api/ports/mirror/source/remove', 'Port taken out of a mirroring session', (s, b) => ports.removeMirrorSource(s, b.session, b.ifIndex));
  // { session }
  writeRoute(app, '/api/ports/mirror/remove', 'Mirroring session removed', (s, b) => ports.removeMirror(s, b.session));
  // { ifIndex, kind: 'full' | 'length' }
  writeRoute(app, '/api/ports/cable-test', 'Cable test run', (s, b) => ports.cableTest(s, b.ifIndex, b.kind));
};
