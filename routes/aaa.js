'use strict';

/**
 * RADIUS and TACACS+ servers over SNMP (aaa.js owns the index encoding).
 */

const log = require('../logger');
const aaa = require('../aaa');
const { v3SecurityOf, buildSnmpSession, redactTarget, mapSetVarbinds, snmpSetPromise } = require('../snmp-core');

module.exports = function register(app) {
  // -----------------------------------------------------------------
  // AAA servers (RADIUS / TACACS+): add, edit, delete via RowStatus
  // -----------------------------------------------------------------

  // Run a set of varbind groups as one SET each. Returns on first failure.
  async function runAaaSteps(target, groups) {
    const session = buildSnmpSession(target);
    try {
      for (const g of groups) {
        if (!g || !g.length) continue;
        await snmpSetPromise(session, mapSetVarbinds(g));   // the shared SET type-mapping
      }
    } finally {
      try { session.close(); } catch (e) { /* ignore */ }
    }
  }

  // Warn (not block) when a shared key would travel over a session weaker than
  // SNMPv3 authPriv. The caller decides whether to proceed.
  function keyTransportWarning(target, cfg) {
    const hasKey = cfg && !cfg.useGlobalKey && cfg.key !== undefined && cfg.key !== null && cfg.key !== '';
    if (!hasKey) return null;
    // Judged from what the session will actually negotiate, not the saved
    // `level` label, which can say authPriv while privacy is set to None.
    let isV3Priv = false;
    try { isV3Priv = String(target.version) === '3' && !!target.v3 && v3SecurityOf(target.v3).level === 'authPriv'; }
    catch (e) { isV3Priv = false; }   // an unsupported method: the session build reports it
    return isV3Priv ? null : 'The shared key will be sent in cleartext because this session is not SNMPv3 with privacy (authPriv). Anyone capturing the traffic could read it.';
  }

  // RADIUS add/edit. Body: { target, ...cfg, edit?, confirm? }
  app.post('/api/aaa/radius', async (req, res) => {
    const b = req.body || {};
    if (!b.target || !b.target.host) return res.status(400).json({ error: 'target.host is required.' });
    if (!b.address || !aaa.ipv4Octets(b.address)) return res.status(400).json({ error: 'A valid IPv4 server address is required.' });
    const warning = keyTransportWarning(b.target, b);
    if (warning && !b.confirm) return res.status(409).json({ warning });   // caller must confirm to proceed
    try {
      const plan = aaa.planRadius(b);
      await runAaaSteps(b.target, [plan.varbinds]);
      log.info('aaa', 'RADIUS server ' + (b.edit ? 'edited' : 'added'), { host: b.target.host, address: b.address });
      res.json({ ok: true, warning });
    } catch (e) {
      log.error('aaa', 'RADIUS write failed', { target: redactTarget(b.target), message: e.message });
      res.status(502).json({ error: e.message });
    }
  });

  // RADIUS delete. Body: { target, address, authPort, acctPort }
  app.post('/api/aaa/radius/delete', async (req, res) => {
    const b = req.body || {};
    if (!b.target || !b.target.host) return res.status(400).json({ error: 'target.host is required.' });
    if (!b.address) return res.status(400).json({ error: 'address is required.' });
    try {
      await runAaaSteps(b.target, [aaa.planRadiusDelete(b.address, b.authPort, b.acctPort)]);
      log.info('aaa', 'RADIUS server deleted', { host: b.target.host, address: b.address });
      res.json({ ok: true });
    } catch (e) {
      res.status(502).json({ error: e.message });
    }
  });

  // TACACS add/edit. Body: { target, ...cfg, edit?, confirm? }
  app.post('/api/aaa/tacacs', async (req, res) => {
    const b = req.body || {};
    if (!b.target || !b.target.host) return res.status(400).json({ error: 'target.host is required.' });
    if (!b.address || !aaa.ipv4Octets(b.address)) return res.status(400).json({ error: 'A valid IPv4 server address is required.' });
    const warning = keyTransportWarning(b.target, b);
    if (warning && !b.confirm) return res.status(409).json({ warning });
    try {
      const plan = aaa.planTacacs(b);
      await runAaaSteps(b.target, [plan.varbinds]);
      log.info('aaa', 'TACACS server ' + (b.edit ? 'edited' : 'added'), { host: b.target.host, address: b.address });
      res.json({ ok: true, warning });
    } catch (e) {
      log.error('aaa', 'TACACS write failed', { target: redactTarget(b.target), message: e.message });
      res.status(502).json({ error: e.message });
    }
  });

  // TACACS delete. Body: { target, address }
  app.post('/api/aaa/tacacs/delete', async (req, res) => {
    const b = req.body || {};
    if (!b.target || !b.target.host) return res.status(400).json({ error: 'target.host is required.' });
    if (!b.address) return res.status(400).json({ error: 'address is required.' });
    try {
      await runAaaSteps(b.target, [aaa.planTacacsDelete(b.address)]);
      log.info('aaa', 'TACACS server deleted', { host: b.target.host, address: b.address });
      res.json({ ok: true });
    } catch (e) {
      res.status(502).json({ error: e.message });
    }
  });
};
