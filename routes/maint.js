'use strict';

/**
 * Reboot, firmware and configuration restore (switch-maint.js).
 *
 * Every route that changes the switch passes writeHold(), so the collector
 * is not reading the switch while it copies a file or goes down.
 */

const crypto = require('crypto');
const express = require('express');
const { writeHold } = require('../write-hold');
const log = require('../logger');
const maint = require('../switch-maint');
const configFetch = require('../config-fetch');
const configHistory = require('../config-history');
const { buildSnmpSession, copyFinishedWaiter, redactTarget } = require('../snmp-core');

// Firmware for this family is 30 to 60 MB. The cap only guards memory.
const MAX_IMAGE_BYTES = Number(process.env.SBS_MAX_IMAGE_BYTES) || 128 * 1024 * 1024;
const MIN_IMAGE_BYTES = 1024 * 1024;
const STAGE_TTL_MS = 30 * 60000;
const MAX_STAGED = 2;
const staged = new Map();   // id -> { buffer, name, sha256, at, timer }

function tftpPort() { return Number(process.env.TFTP_PORT) || undefined; }

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

function dropStaged(id) {
  const s = staged.get(id);
  if (!s) return;
  clearTimeout(s.timer);
  staged.delete(id);
}

module.exports = function register(app) {
  // The reboot schedule and the firmware images. Body: { target }
  app.post('/api/maint/status', async (req, res) => {
    const target = needTarget(req, res); if (!target) return;
    try {
      res.json(await withSession(target, (s) => maint.readMaint(s)));
    } catch (e) {
      res.status(502).json({ error: e.message });
    }
  });

  // Reboot now (seconds 0) or later. Body: { target, seconds }
  app.post('/api/maint/reboot', writeHold(), async (req, res) => {
    const target = needTarget(req, res); if (!target) return;
    try {
      const r = await withSession(target, (s) => maint.scheduleReboot(s, req.body.seconds));
      log.warn('maint', 'Reboot requested', { host: target.host, inSeconds: r.inSeconds, via: r.via });
      res.json(Object.assign({ ok: true }, r));
    } catch (e) {
      log.error('maint', 'Reboot failed', { target: redactTarget(target), message: e.message });
      res.status(502).json({ error: e.message });
    }
  });

  // Cancel a scheduled reboot. Body: { target }
  app.post('/api/maint/reboot/cancel', writeHold(), async (req, res) => {
    const target = needTarget(req, res); if (!target) return;
    try {
      const r = await withSession(target, (s) => maint.cancelReboot(s));
      log.info('maint', 'Scheduled reboot cancelled', { host: target.host });
      res.json(Object.assign({ ok: true }, r));
    } catch (e) {
      log.error('maint', 'Cancelling the reboot failed', { target: redactTarget(target), message: e.message });
      res.status(502).json({ error: e.message });
    }
  });

  // Choose the image to boot next. Body: { target, unit, image }
  app.post('/api/maint/next-boot', writeHold(), async (req, res) => {
    const target = needTarget(req, res); if (!target) return;
    try {
      const r = await withSession(target, (s) => maint.setNextBoot(s, req.body.unit, req.body.image));
      log.info('maint', 'Next boot image set', { host: target.host, unit: r.unit, image: r.nextBoot });
      res.json(Object.assign({ ok: true }, r));
    } catch (e) {
      log.error('maint', 'Setting the next boot image failed', { target: redactTarget(target), message: e.message });
      res.status(502).json({ error: e.message });
    }
  });

  // Copy a stored configuration version into the startup configuration,
  // then read startup back to check it. The running configuration is not
  // touched: the switch uses the restored version after its next reboot.
  // Body: { target, id }
  app.post('/api/config/restore', writeHold(), async (req, res) => {
    const target = needTarget(req, res); if (!target) return;
    const version = configHistory.get(target.host, String(req.body.id || ''));
    if (!version) return res.status(404).json({ error: 'No such stored version.' });
    try {
      const pushed = await maint.pushFile(() => buildSnmpSession(target), {
        host: target.host, dest: 'startup', buffer: Buffer.from(version.text, 'utf8'),
        tftpPort: tftpPort(), waitForFinish: copyFinishedWaiter(target.host), unit: req.body.unit
      });
      let check = { matches: null };
      try {
        const back = await configFetch.fetchConfig(() => buildSnmpSession(target), {
          host: target.host, kind: 'startup', tftpPort: tftpPort()
        });
        check = { matches: maint.sameConfig(back.text, version.text), lines: back.lines };
      } catch (e) {
        check = { matches: null, error: 'Restored, but reading startup back failed: ' + e.message };
      }
      log.warn('maint', 'Configuration version restored to startup', {
        host: target.host, id: version.id, shape: pushed.shape, matches: check.matches
      });
      res.json({ ok: true, id: version.id, shape: pushed.shape, check });
    } catch (e) {
      log.error('maint', 'Restore failed', { target: redactTarget(target), message: e.message });
      res.status(502).json({ error: e.message });
    }
  });

  // Hold a firmware image the browser uploaded, until it is installed or
  // half an hour passes. The body is the raw file; ?name= is its file name.
  app.post('/api/firmware/stage',
    express.raw({ type: 'application/octet-stream', limit: MAX_IMAGE_BYTES }),
    (req, res) => {
      const buf = req.body;
      if (!Buffer.isBuffer(buf) || buf.length < MIN_IMAGE_BYTES) {
        return res.status(400).json({ error: 'That file is too small to be a firmware image.' });
      }
      const name = String(req.query.name || 'image.bin').replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 120);
      while (staged.size >= MAX_STAGED) dropStaged(staged.keys().next().value);
      const id = crypto.randomBytes(12).toString('hex');
      const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
      staged.set(id, { buffer: buf, name, sha256, at: Date.now(), timer: setTimeout(() => dropStaged(id), STAGE_TTL_MS) });
      log.info('maint', 'Firmware image staged', { name, bytes: buf.length, sha256 });
      res.json({ ok: true, id, name, bytes: buf.length, sha256 });
    });

  // Have the switch pull a staged image into its inactive slot, then read
  // the images back. Body: { target, id }
  app.post('/api/firmware/install', writeHold(), async (req, res) => {
    const target = needTarget(req, res); if (!target) return;
    const s = staged.get(String(req.body.id || ''));
    if (!s) return res.status(404).json({ error: 'That upload has expired. Choose the file again.' });
    try {
      const pushed = await maint.pushFile(() => buildSnmpSession(target), {
        host: target.host, dest: 'image', buffer: s.buffer,
        tftpPort: tftpPort(), waitForFinish: copyFinishedWaiter(target.host), unit: req.body.unit
      });
      dropStaged(req.body.id);
      const status = await withSession(target, (sess) => maint.readMaint(sess)).catch(() => null);
      log.warn('maint', 'Firmware image installed', { host: target.host, name: s.name, sha256: s.sha256, shape: pushed.shape });
      res.json({ ok: true, shape: pushed.shape, status });
    } catch (e) {
      log.error('maint', 'Firmware install failed', { target: redactTarget(target), name: s.name, message: e.message });
      res.status(502).json({ error: e.message });
    }
  });
};

module.exports.MAX_IMAGE_BYTES = MAX_IMAGE_BYTES;
