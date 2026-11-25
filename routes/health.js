'use strict';

/**
 * The on-demand health collection route.
 */

const log = require('../logger');
const { redactTarget } = require('../snmp-core');
const { collectHealthFor } = require('../collection');

module.exports = function register(app) {
  app.post('/api/health', async (req, res) => {
    const { target, mode, only } = req.body || {};
    if (!target || !target.host) {
      return res.status(400).json({ error: 'target.host is required.' });
    }
    log.info('health', 'Health collection requested', { target: redactTarget(target) });
    try {
      const data = await collectHealthFor(target, { mode, only });
      log.info('health', data.partial ? 'Partial collection complete' : 'Health collection complete', {
        target: redactTarget(target),
        tables: data.partial ? data.keys.join(',') : undefined,
        // Per-table row counts for partial walks, so a table that comes back empty
        // (e.g. an Owner/companion table a module relies on) is visible in the log.
        counts: data.partial ? data.keys.reduce((acc, k) => {
          if (Array.isArray(data[k])) acc[k] = data[k].length;
          return acc;
        }, {}) : undefined,
        alerts: data.alerts ? data.alerts.length : undefined,
        worst: data.summary ? data.summary.worstSeverity : undefined,
        failed: data.failed.length
      });
      res.json(data);
    } catch (e) {
      log.error('health', 'Health collection failed', { message: e.message });
      // A credential/validation problem is the caller's fault (400); anything
      // else is the switch not answering (502) - same split as before.
      const code = /required|SNMPv3|password|username/i.test(e.message) ? 400 : 502;
      res.status(code).json({ error: e.message });
    }
  });
};
