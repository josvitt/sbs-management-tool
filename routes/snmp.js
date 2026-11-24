'use strict';

/**
 * Raw SNMP request/response routes: GET, GETNEXT, WALK, SET, and the MIB
 * and SNMPv3 option lookups the UI needs to build them.
 */

const snmp = require('net-snmp');
const log = require('../logger');
const mib = require('../mibdb');
const v3crypto = require('../snmp-crypto');
const { buildSnmpSession, resolveOids, annotate, boundedWalk, describeVarbind, redactTarget, snmpResponder, mapSetVarbinds } = require('../snmp-core');

module.exports = function register(app) {
  app.post('/api/snmp/get', (req, res) => {
    const { target, oids, next } = req.body || {};
    if (!target || !target.host || !Array.isArray(oids) || oids.length === 0) {
      return res.status(400).json({ error: 'target.host and a non-empty oids array are required.' });
    }

    log.info('snmp', `${next ? 'GETNEXT' : 'GET'} request`, { target: redactTarget(target), oids });

    let resolvedOids;
    let session;
    try {
      resolvedOids = resolveOids(oids);
      session = buildSnmpSession(target);
    } catch (e) {
      log.error('snmp', 'Failed to prepare SNMP request', { message: e.message, target: redactTarget(target) });
      return res.status(400).json({ error: e.message });
    }

    session.on('error', (err) => {
      log.error('snmp', 'SNMP session error', { message: err.message, target: redactTarget(target) });
    });

    const method = next ? 'getNext' : 'get';
    const responder = snmpResponder(res, session, method, 12000);
    session[method](resolvedOids, (error, varbinds) => {
      if (error) {
        log.error('snmp', `${method} failed`, { message: error.message, target: redactTarget(target) });
        return responder.fail(502, error.message);
      }
      const results = varbinds.map((vb) => {
        if (snmp.isVarbindError(vb)) {
          return annotate({ oid: vb.oid, error: snmp.varbindError(vb) });
        }
        return describeVarbind(vb);
      });
      log.info('snmp', `${method} succeeded`, { target: redactTarget(target), count: results.length });
      responder.ok({ results });
    });
  });

  // WALK a subtree from a base OID.
  app.post('/api/snmp/walk', (req, res) => {
    const { target, oid } = req.body || {};
    if (!target || !target.host || !oid) {
      return res.status(400).json({ error: 'target.host and oid are required.' });
    }

    log.info('snmp', 'WALK request', { target: redactTarget(target), oid });

    let resolvedOid;
    let session;
    try {
      resolvedOid = resolveOids([oid])[0];
      session = buildSnmpSession(target);
    } catch (e) {
      log.error('snmp', 'Failed to prepare SNMP request', { message: e.message, target: redactTarget(target) });
      return res.status(400).json({ error: e.message });
    }

    session.on('error', (err) => {
      log.error('snmp', 'SNMP session error', { message: err.message, target: redactTarget(target) });
    });

    const results = [];
    boundedWalk(session, resolvedOid, { mode: req.body.mode }, (error, rows, truncated) => {
      session.close();
      results.push(...rows);
      if (error) {
        log.error('snmp', 'walk failed', { message: error.message, target: redactTarget(target), rows: results.length });
        return res.status(502).json({ error: error.message, results });
      }
      log.info('snmp', 'walk succeeded', {
        target: redactTarget(target), oid: resolvedOid, count: results.length,
        mode: req.body.mode === 'next' ? 'getnext' : 'getbulk'
      });
      res.json({ results, truncated });
    });
  });

  // SET one or more OIDs.
  app.post('/api/snmp/set', (req, res) => {
    const { target, varbinds } = req.body || {};
    if (!target || !target.host || !Array.isArray(varbinds) || varbinds.length === 0) {
      return res.status(400).json({ error: 'target.host and a non-empty varbinds array are required.' });
    }

    // OIDs and types only: a SET value can be a community string, a shared
    // key or a password, and the log is not the place for any of them.
    log.info('snmp', 'SET request', {
      target: redactTarget(target),
      varbinds: varbinds.map((vb) => ({ oid: vb && vb.oid, type: vb && vb.type }))
    });

    let session;
    try {
      session = buildSnmpSession(target);
    } catch (e) {
      log.error('snmp', 'Failed to build SNMP session', { message: e.message, target: redactTarget(target) });
      return res.status(400).json({ error: e.message });
    }

    session.on('error', (err) => {
      log.error('snmp', 'SNMP session error', { message: err.message, target: redactTarget(target) });
    });

    let mapped;
    try {
      mapped = mapSetVarbinds(varbinds);
    } catch (e) {
      session.close();
      return res.status(400).json({ error: e.message });
    }

    const responder = snmpResponder(res, session, 'set', 12000);
    session.set(mapped, (error, resultVarbinds) => {
      if (error) {
        log.error('snmp', 'set failed', { message: error.message, target: redactTarget(target) });
        return responder.fail(502, error.message);
      }
      const results = resultVarbinds.map((vb) => {
        if (snmp.isVarbindError(vb)) {
          return annotate({ oid: vb.oid, error: snmp.varbindError(vb) });
        }
        return describeVarbind(vb);
      });
      log.info('snmp', 'set succeeded', { target: redactTarget(target), count: results.length });
      responder.ok({ results });
    });
  });


  // Lets the UI report how many OIDs are loaded, and surfaces a clear error
  // if the generated MIB database is missing or corrupt.

  app.get('/api/mib/stats', (req, res) => {
    res.json(mib.stats());
  });

  app.get('/api/snmp/v3-options', (req, res) => {
    res.json({ auth: v3crypto.AUTH_CHOICES, priv: v3crypto.PRIV_CHOICES });
  });
};
