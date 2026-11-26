'use strict';

/**
 * Shared shape of the settings routes (stp, security, ipv6): each takes
 * { target, ... } in the body, opens one SNMP session for the request and
 * closes it after. A write passes writeHold(), so the collector is not
 * reading while it writes, and a message that names a bad value is a 400.
 */

const { writeHold } = require('../../write-hold');
const log = require('../../logger');
const { buildSnmpSession, redactTarget } = require('../../snmp-core');

const USER_ERROR = /must|is required|Nothing to change|is 0 to|is 1 to/;

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

/** POST path: read with fn(session, body), no write hold. */
function readRoute(app, path, fn) {
  app.post(path, async (req, res) => {
    const target = needTarget(req, res); if (!target) return;
    try { res.json(await withSession(target, (s) => fn(s, req.body || {}))); }
    catch (e) { res.status(502).json({ error: e.message }); }
  });
}

/** POST path: a write under the write hold, logged under tag. */
function writeRoute(app, tag, path, what, fn) {
  app.post(path, writeHold(), async (req, res) => {
    const target = needTarget(req, res); if (!target) return;
    try {
      const r = await withSession(target, (s) => fn(s, req.body || {}));
      log.info(tag, what, Object.assign({ host: target.host }, r));
      res.json(Object.assign({ ok: true }, r));
    } catch (e) {
      log.error(tag, what + ' failed', { target: redactTarget(target), message: e.message });
      res.status(USER_ERROR.test(e.message) ? 400 : 502).json({ error: e.message });
    }
  });
}

const pick = (b, keys) => { const o = {}; for (const k of keys) if (b[k] != null) o[k] = b[k]; return o; };

module.exports = { needTarget, withSession, readRoute, writeRoute, pick, USER_ERROR };
