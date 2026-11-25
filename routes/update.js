'use strict';

/**
 * Self-update: the Updates window's routes. The work is in updater.js
 * (check, download, prepare) and update-boot.js (the swap and rollback).
 *
 * The GitHub token goes in through POST /api/update/token and never comes
 * back out: the status carries only whether one is set.
 */

const log = require('../logger');

module.exports = function register(app, updater) {
  app.get('/api/update/status', (req, res) => {
    res.json(updater.status());
  });

  app.post('/api/update/check', async (req, res) => {
    try {
      res.json(await updater.check());
    } catch (e) {
      res.status(409).json({ error: e.message });
    }
  });

  // Answers once the new version is downloaded, installed beside the app and
  // checked; the app then restarts into it a moment later.
  app.post('/api/update/install', async (req, res) => {
    try {
      res.json(await updater.install());
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  app.post('/api/update/rollback', (req, res) => {
    try {
      res.json(updater.requestRollback());
    } catch (e) {
      res.status(409).json({ error: e.message });
    }
  });

  app.post('/api/update/token', (req, res) => {
    const body = req.body || {};
    try {
      updater.saveToken(body.token);
      log.info('update', body.token ? 'GitHub token saved' : 'GitHub token removed');
      res.json(updater.status());
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  });

  app.post('/api/update/settings', (req, res) => {
    try {
      updater.saveSettings(req.body || {});
      res.json(updater.status());
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });
};
