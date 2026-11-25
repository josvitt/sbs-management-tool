'use strict';

/**
 * System settings (switch-system.js): clock, SNTP servers, local users and
 * management access. Every route that changes the switch passes
 * writeHold(), so the collector is not reading while it writes.
 */

const { writeHold } = require('../write-hold');
const log = require('../logger');
const { buildSnmpSession, redactTarget } = require('../snmp-core');
const sys = require('../switch-system');

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

// One write route: run fn(session, body), log it without secrets, answer
// { ok, ...result } or the switch's error.
function writeRoute(app, path, what, fn) {
  app.post(path, writeHold(), async (req, res) => {
    const target = needTarget(req, res); if (!target) return;
    try {
      const r = await withSession(target, (s) => fn(s, req.body || {}));
      log.info('system', what, Object.assign({ host: target.host }, r));
      res.json(Object.assign({ ok: true }, r));
    } catch (e) {
      log.error('system', what + ' failed', { target: redactTarget(target), message: e.message });
      res.status(/must|cannot|already|only admin|would leave|not a valid|not supported|Enter a/.test(e.message) ? 400 : 502).json({ error: e.message });
    }
  });
}

module.exports = function register(app) {
  // Body: { target }
  app.post('/api/system/status', async (req, res) => {
    const target = needTarget(req, res); if (!target) return;
    try {
      res.json(await withSession(target, (s) => sys.readSystem(s)));
    } catch (e) {
      res.status(502).json({ error: e.message });
    }
  });

  // { offset: '+01:00', code: 'CET' }
  writeRoute(app, '/api/system/timezone', 'Time zone set', (s, b) => sys.setTimeZone(s, b.offset, b.code));
  // { on: true }
  writeRoute(app, '/api/system/sntp', 'SNTP turned on or off', (s, b) => sys.setSntp(s, !!b.on));
  // { address }
  writeRoute(app, '/api/system/sntp/add', 'SNTP server added', (s, b) => sys.addSntpServer(s, b.address));
  writeRoute(app, '/api/system/sntp/remove', 'SNTP server removed', (s, b) => sys.removeSntpServer(s, b.address));
  // { local: 'YYYY-MM-DD hh:mm:ss' }
  writeRoute(app, '/api/system/clock', 'Clock set', (s, b) => sys.setClock(s, b.local));
  // { name, password, privilege }. The password is never logged.
  writeRoute(app, '/api/system/user/add', 'Local user added', (s, b) => sys.addUser(s, b.name, b.password, b.privilege));
  writeRoute(app, '/api/system/user/password', 'Local user password changed', (s, b) => sys.setUserPassword(s, b.name, b.password));
  writeRoute(app, '/api/system/user/privilege', 'Local user privilege changed', (s, b) => sys.setUserPrivilege(s, b.name, b.privilege));
  writeRoute(app, '/api/system/user/delete', 'Local user deleted', (s, b) => sys.deleteUser(s, b.name));
  // { service: 'ssh' | 'telnet' | 'https' | 'http', on }
  writeRoute(app, '/api/system/service', 'Management service turned on or off', (s, b) => sys.setService(s, b.service, !!b.on));
};
