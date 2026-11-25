'use strict';

/**
 * Express middleware for every route that writes to a switch.
 *
 * This firmware has crashed when a full multi-table read lands on top of a
 * config-touching SET. The browser used to guard against that by pausing its
 * own polling, but collection now runs on the server, so the guard lives
 * here: before the route sends anything, the collector holds that switch's
 * full collection (collector.holdForWrite) and waits for a poll already in
 * progress to finish. See SERVER-STANDARD.md §3d.
 *
 * `when` (optional) decides per request whether it writes, for a route that
 * serves reads and writes alike (snmp-config's `*-apply` actions).
 */

const collector = require('./collector');
const log = require('./logger');

function writeHold(when) {
  return async function holdWrites(req, res, next) {
    const target = req.body && req.body.target;
    if (!target || !target.host || (when && !when(req))) return next();
    try { await collector.holdForWrite(target.host); }
    catch (e) { log.warn('collector', 'Write hold failed; writing anyway', { host: target.host, message: e.message }); }
    next();
  };
}

module.exports = { writeHold };
