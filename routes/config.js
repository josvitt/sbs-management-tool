'use strict';

/**
 * Configuration retrieval and sync over the embedded TFTP receiver.
 */

const log = require('../logger');
const tftp = require('../tftp');
const configFetch = require('../config-fetch');
const { copyFinishedWaiter, buildSnmpSession, redactTarget } = require('../snmp-core');

module.exports = function register(app) {
  // -----------------------------------------------------------------
  // Configuration retrieval
  // -----------------------------------------------------------------
  // No MIB object returns configuration text, so this drives rlCopyTable to
  // have the switch upload the file to the TFTP receiver embedded in this
  // app. Needs SNMP *write* access, and the switch must be able to reach
  // this machine on the TFTP port.


  app.get('/api/tftp/status', (req, res) => res.json(tftp.status()));

  app.post('/api/config/fetch', async (req, res) => {
    const { target, kind, tftpPort } = req.body || {};
    if (!target || !target.host) {
      return res.status(400).json({ error: 'target.host is required.' });
    }
    try {
      const result = await configFetch.fetchConfig(() => buildSnmpSession(target), {
        host: target.host, kind: kind || 'running',
        // TFTP is port 69 by convention and the switch will not be told
        // otherwise; TFTP_PORT exists for the case where binding a
        // privileged port is not possible (a non-root Linux run).
        tftpPort: tftpPort || Number(process.env.TFTP_PORT) || undefined
      });
      res.json(result);
    } catch (e) {
      log.error('config', 'Configuration fetch failed', {
        target: redactTarget(target), kind, message: e.message
      });
      res.status(502).json({ error: e.message });
    }
  });

  // Writes to the switch: copies one config over another, which is how
  // "sync" saves the running configuration to startup.
  app.post('/api/config/sync', async (req, res) => {
    const { target, from, to } = req.body || {};
    if (!target || !target.host) return res.status(400).json({ error: 'target.host is required.' });
    try {
      const result = await configFetch.copyConfig(() => buildSnmpSession(target), {
        host: target.host, from: from || 'running', to: to || 'startup', unit: req.body && req.body.unit,
        waitForFinish: copyFinishedWaiter(target.host)
      });
      res.json(result);
    } catch (e) {
      log.error('config', 'Configuration sync failed', {
        target: redactTarget(target), from, to, message: e.message
      });
      res.status(502).json({ error: e.message });
    }
  });

};
