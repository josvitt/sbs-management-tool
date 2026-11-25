'use strict';

/**
 * Spanning tree settings (switch-stp.js): on or off, the mode, the bridge
 * priority (switch, VLAN or MSTP instance) and per-port settings. Every
 * route that changes the switch passes writeHold(), so the collector is not
 * reading while it writes.
 */

const { writeHold } = require('../write-hold');
const log = require('../logger');
const { buildSnmpSession, redactTarget } = require('../snmp-core');
const stp = require('../switch-stp');

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

const USER_ERROR = /must|is required|Nothing to change|Name a vlan|is 0 to|is 1 to/;

function writeRoute(app, path, what, fn) {
  app.post(path, writeHold(), async (req, res) => {
    const target = needTarget(req, res); if (!target) return;
    try {
      const r = await withSession(target, (s) => fn(s, req.body || {}));
      log.info('stp', what, Object.assign({ host: target.host }, r));
      res.json(Object.assign({ ok: true }, r));
    } catch (e) {
      log.error('stp', what + ' failed', { target: redactTarget(target), message: e.message });
      res.status(USER_ERROR.test(e.message) ? 400 : 502).json({ error: e.message });
    }
  });
}

module.exports = function register(app) {
  // Body: { target }
  app.post('/api/stp/status', async (req, res) => {
    const target = needTarget(req, res); if (!target) return;
    try {
      res.json(await withSession(target, (s) => stp.readStp(s)));
    } catch (e) {
      res.status(502).json({ error: e.message });
    }
  });

  // { on }
  writeRoute(app, '/api/stp/enabled', 'Spanning tree turned on or off', (s, b) => stp.setEnabled(s, !!b.on));
  // { mode }
  writeRoute(app, '/api/stp/mode', 'Spanning tree mode changed', (s, b) => stp.setMode(s, b.mode));
  // { priority, vlan?, instance? }
  writeRoute(app, '/api/stp/priority', 'Bridge priority changed', (s, b) =>
    stp.setBridgePriority(s, b.priority, b.vlan != null ? { vlan: b.vlan } : (b.instance != null ? { instance: b.instance } : null)));
  // { port, enabled?, priority?, cost?, edge?, autoEdge?, bpduGuard? }
  writeRoute(app, '/api/stp/port', 'Spanning tree port settings changed', (s, b) =>
    stp.setPort(s, b.port, { enabled: b.enabled, priority: b.priority, cost: b.cost, edge: b.edge, autoEdge: b.autoEdge, bpduGuard: b.bpduGuard }));
  // { port, vlan? | instance?, priority?, cost? }
  writeRoute(app, '/api/stp/port-in', 'Spanning tree port settings changed for a VLAN or instance', (s, b) =>
    stp.setPortIn(s, b.vlan != null ? { vlan: b.vlan } : (b.instance != null ? { instance: b.instance } : {}), b.port, { priority: b.priority, cost: b.cost }));
};
