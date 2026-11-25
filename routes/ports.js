'use strict';

/**
 * Port actions: PoE power cycle and admin up/down.
 */

const { writeHold } = require('../write-hold');
const snmp = require('net-snmp');
const log = require('../logger');
const configFetch = require('../config-fetch');
const { copyFinishedWaiter, buildSnmpSession } = require('../snmp-core');

module.exports = function register(app) {
  // -----------------------------------------------------------------
  // Port actions
  // -----------------------------------------------------------------
  /**
   * The two changes worth making from a dashboard.
   *
   * Power-cycling a PoE port is how a wedged phone, camera or access point
   * gets rebooted -- the commonest physical-layer fix there is, and one that
   * otherwise means finding a CLI or walking to a rack. Admin shut/no-shut
   * is its companion.
   *
   * Both write to the switch, so both are deliberate: the browser confirms
   * first, and each returns the port's state afterwards so the page can show
   * what actually happened rather than assume.
   */
  const PETH_ADMIN = '1.3.6.1.2.1.105.1.1.1.3';     // pethPsePortAdminEnable
  const IF_ADMIN = '1.3.6.1.2.1.2.2.1.7';           // ifAdminStatus
  const IF_OPER = '1.3.6.1.2.1.2.2.1.8';
  const CONFIG_EQUAL_OID = '1.3.6.1.4.1.9.6.1.101.1.13.0';

  function snmpSet(session, varbinds) {
    return new Promise((resolve, reject) => {
      session.set(varbinds, (error, result) => {
        if (error) return reject(error);
        const bad = (result || []).find((vb) => snmp.isVarbindError(vb));
        if (bad) return reject(new Error(snmp.varbindError(bad)));
        resolve(result);
      });
    });
  }

  function snmpGetOne(session, oid) {
    return new Promise((resolve, reject) => {
      session.get([oid], (error, vbs) => {
        if (error) return reject(error);
        const vb = vbs && vbs[0];
        if (!vb || snmp.isVarbindError(vb)) return reject(new Error('no value for ' + oid));
        resolve(Number(vb.value));
      });
    });
  }

  app.post('/api/port/poe', writeHold(), async (req, res) => {
    const { target, group, port, action } = req.body || {};
    if (!target || !target.host || port === undefined) {
      return res.status(400).json({ error: 'target.host and port are required.' });
    }
    const oid = PETH_ADMIN + '.' + (Number(group) || 1) + '.' + Number(port);
    const session = buildSnmpSession(target);
    const set = (v) => snmpSet(session, [{ oid, type: snmp.ObjectType.Integer, value: v }]);
    try {
      log.info('port', 'PoE action', { host: target.host, port, action });

      /**
       * A power cycle is two writes to the port's admin state, so the switch
       * marks its configuration dirty even though the port ends up exactly
       * as it started. There is no "reset power" action to use instead --
       * rlPethPsePortReactivate only recovers ports disabled by a hardware
       * fault -- so the tidying is done here rather than explained to the
       * operator afterwards.
       *
       * Only when the configuration was already saved beforehand. If it was
       * dirty, saving would commit somebody else's pending changes, which is
       * not ours to do.
       */
      const wasSaved = await snmpGetOne(session, CONFIG_EQUAL_OID).then((v) => v === 1).catch(() => null);

      if (action === 'off') {
        await set(2);
      } else if (action === 'on') {
        await set(1);
      } else {
        // Bounce: off, pause long enough for the powered device to notice,
        // then on. Anything shorter and some devices do not reboot at all.
        await set(2);
        await new Promise((r) => setTimeout(r, 3000));
        await set(1);
      }
      const now = await snmpGetOne(session, oid);
      session.close();

      let restored = null;
      if (wasSaved === true) {
        try {
          await configFetch.copyConfig(() => buildSnmpSession(target), {
            host: target.host, from: 'running', to: 'startup', timeoutMs: 20000,
            waitForFinish: copyFinishedWaiter(target.host, 20000)
          });
          restored = true;
          log.info('port', 'Configuration re-saved after the power cycle', { host: target.host, port });
        } catch (e) {
          // Not fatal: the port was still cycled, and the dashboard will
          // simply show unsaved changes, which the comparison explains.
          restored = false;
          log.warn('port', 'Could not re-save after the power cycle', {
            host: target.host, port, message: e.message
          });
        }
      }

      log.info('port', 'PoE action complete', { host: target.host, port, action, adminEnable: now });
      res.json({ port, action, adminEnable: now, enabled: now === 1, configRestored: restored });
    } catch (e) {
      try { session.close(); } catch (x) {}
      log.error('port', 'PoE action failed', { host: target.host, port, action, message: e.message });
      res.status(502).json({ error: e.message });
    }
  });

  app.post('/api/port/admin', writeHold(), async (req, res) => {
    const { target, ifIndex, action } = req.body || {};
    if (!target || !target.host || ifIndex === undefined) {
      return res.status(400).json({ error: 'target.host and ifIndex are required.' });
    }
    const oid = IF_ADMIN + '.' + Number(ifIndex);
    const session = buildSnmpSession(target);
    try {
      log.info('port', 'Admin state change', { host: target.host, ifIndex, action });
      await snmpSet(session, [{
        oid, type: snmp.ObjectType.Integer, value: action === 'down' ? 2 : 1
      }]);
      // Give the port a moment to settle before reporting where it landed.
      await new Promise((r) => setTimeout(r, 1200));
      const admin = await snmpGetOne(session, oid).catch(() => null);
      const oper = await snmpGetOne(session, IF_OPER + '.' + Number(ifIndex)).catch(() => null);
      session.close();
      log.info('port', 'Admin state changed', { host: target.host, ifIndex, admin, oper });
      res.json({ ifIndex, action, admin, oper });
    } catch (e) {
      try { session.close(); } catch (x) {}
      log.error('port', 'Admin state change failed', {
        host: target.host, ifIndex, action, message: e.message
      });
      res.status(502).json({ error: e.message });
    }
  });
};
