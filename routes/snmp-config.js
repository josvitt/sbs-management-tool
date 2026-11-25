'use strict';

/**
 * SNMP configuration (recipients, communities, VACM groups, users, system
 * identity): one dispatch route; snmp-config.js owns the logic.
 */

const { writeHold } = require('../write-hold');
const log = require('../logger');
const snmpConfig = require('../snmp-config');
const { buildSnmpSession, snmpConfigBundle } = require('../snmp-core');

const { markInUse } = snmpConfig;

module.exports = function register(app) {
  // SNMP configuration (recipients, communities, VACM groups, users,
  // system identity) — the write side and its config-specific reads.
  // snmp-config.js owns the logic; here we just build the session and
  // hand it the raw get/walk/set primitives it expects.
  // -----------------------------------------------------------------


  // snmp-config dispatch. One route; the action decides read or apply (every
  // *-apply action builds its plan of SETs and runs it in one call).
  app.post('/api/snmp-config/:action', writeHold((req) => /-apply$/.test(req.params.action)), async (req, res) => {
    const action = req.params.action;
    const { target } = req.body || {};
    if (!target || !target.host) return res.status(400).json({ error: 'target.host is required.' });

    let session;
    try { session = buildSnmpSession(target); }
    catch (e) { return res.status(400).json({ error: e.message }); }
    session.on('error', (err) => log.error('snmp-config', 'session error', { message: err.message }));

    const S = snmpConfigBundle(session);
    const meta = { version: target.version, community: target.community, user: target.v3 && target.v3.username };
    const body = req.body || {};

    try {
      let result;
      switch (action) {
        case 'access': result = await snmpConfig.accessCheck(S, meta); break;
        case 'recipients': result = await snmpConfig.listRecipients(S, { all: body.all }); break;
        case 'communities': result = markInUse(await snmpConfig.listCommunities(S), 'communities', 'community', meta.version !== '3' && meta.community); break;
        case 'groups': result = await snmpConfig.listGroups(S); break;
        case 'users': result = markInUse(await snmpConfig.listUsers(S), 'users', 'name', meta.version === '3' && meta.user); break;
        case 'views': result = await snmpConfig.listViewNames(S); break;
        case 'target-check': result = await snmpConfig.checkTargetRows(S); break;
        case 'target-row-delete-apply': {
          const oid = String((body.key || {}).destroyOid || '');
          if (!/^1\.3\.6\.1\.6\.3\.12\.1\.2\.1\.9\./.test(oid)) throw new Error('Invalid target-row reference.');
          const err = await S.set([{ oid, type: 'Integer', value: 6 }]);
          result = { applied: { ok: err == null, log: [{ title: 'Remove malformed target row', ok: err == null, detail: err == null ? 'destroyed' : err }] } };
          break;
        }

        case 'status-set-apply': result = { applied: await snmpConfig.applyPlan(S, snmpConfig.planSetSystem(body.cfg)) }; break;
        case 'recipient-add-apply': result = { applied: await snmpConfig.applyPlan(S, await snmpConfig.planAddRecipient(S, body.cfg)) }; break;
        case 'recipient-delete-apply': result = { applied: await snmpConfig.applyPlan(S, await snmpConfig.planDeleteRecipient(S, body.key)) }; break;
        case 'community-modify-apply': result = { applied: await snmpConfig.applyPlan(S, await snmpConfig.planModifyCommunity(S, body.cfg)) }; break;
        case 'community-add-apply': result = { applied: await snmpConfig.applyPlan(S, await snmpConfig.planAddCommunity(S, body.cfg)) }; break;
        case 'community-delete-apply': result = { applied: await snmpConfig.applyPlan(S, await snmpConfig.planDeleteCommunity(S, body.key)) }; break;
        case 'group-add-apply': result = { applied: await snmpConfig.applyPlan(S, await snmpConfig.planAddGroup(S, body.cfg)) }; break;
        case 'group-modify-apply': result = { applied: await snmpConfig.applyPlan(S, await snmpConfig.planModifyGroup(S, body.cfg)) }; break;
        case 'user-delete-apply': result = { applied: await snmpConfig.applyPlan(S, await snmpConfig.planDeleteUser(S, body.key)) }; break;

        default: return res.status(404).json({ error: 'Unknown action: ' + action });
      }
      res.json({ ok: true, ...result });
    } catch (e) {
      log.error('snmp-config', action + ' failed', { message: e.message });
      res.status(400).json({ ok: false, error: e.message });
    } finally {
      try { session.close(); } catch (e) { /* already closed */ }
    }
  });
};
module.exports.markInUse = markInUse;
