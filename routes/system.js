'use strict';

/**
 * System settings (switch-system.js): clock, SNTP servers, local users and
 * management access. Read-only for now; the writes follow once the
 * switch-made rows are recorded.
 */

const { buildSnmpSession } = require('../snmp-core');
const { readSystem } = require('../switch-system');

module.exports = function register(app) {
  // Body: { target }
  app.post('/api/system/status', async (req, res) => {
    const target = req.body && req.body.target;
    if (!target || !target.host) return res.status(400).json({ error: 'target.host is required.' });
    const session = buildSnmpSession(target);
    try {
      res.json(await readSystem(session));
    } catch (e) {
      res.status(502).json({ error: e.message });
    } finally {
      try { session.close(); } catch (e) {}
    }
  });
};
