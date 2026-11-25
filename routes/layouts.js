'use strict';

/**
 * Per-switch dashboard layouts (layouts.json).
 */

const fs = require('fs');
const path = require('path');
const log = require('../logger');
const rotate = require('../rotate');

module.exports = function register(app) {
  // -----------------------------------------------------------------
  // Dashboard layouts
  // -----------------------------------------------------------------
  // The health page is user-editable, so the arrangement has to outlive a
  // browser refresh. Layouts are keyed by host and kept in one small JSON
  // file next to the app. This is configuration, not captured device data --
  // no session output or query results are stored here.

  const LAYOUT_FILE = path.join(__dirname, 'layouts.json');
  let layouts = null;

  function loadLayouts() {
    if (layouts) return layouts;
    try {
      layouts = JSON.parse(fs.readFileSync(LAYOUT_FILE, 'utf8'));
    } catch (e) {
      layouts = {};   // missing or unreadable: start clean rather than fail
    }
    // Keyed by a host taken from the URL: with no prototype, a host such as
    // "__proto__" or "constructor" is an ordinary key, not Object.prototype.
    layouts = Object.assign(Object.create(null), layouts);
    return layouts;
  }

  function saveLayouts() {
    try {
      rotate.writeFileAtomic(LAYOUT_FILE, JSON.stringify(layouts, null, 2));
    } catch (e) {
      log.error('layout', 'Could not write layouts.json', { message: e.message });
    }
  }

  app.get('/api/layout/:host', (req, res) => {
    const all = loadLayouts();
    res.json({ layout: all[req.params.host] || null });
  });

  app.put('/api/layout/:host', (req, res) => {
    const all = loadLayouts();
    const body = req.body || {};
    if (!Array.isArray(body.panels)) {
      return res.status(400).json({ error: 'panels array required' });
    }
    all[req.params.host] = {
      panels: body.panels,
      refresh: body.refresh || {},
      // Which console port belongs to which switch is worth remembering:
      // the cable does not move just because the browser was closed. Only
      // the port and rate are kept -- there is no credential here.
      console: body.console && body.console.path
        ? { path: String(body.console.path), baudRate: Number(body.console.baudRate) || 115200 }
        : null,
      savedAt: new Date().toISOString()
    };
    saveLayouts();
    res.json({ ok: true });
  });

  app.delete('/api/layout/:host', (req, res) => {
    const all = loadLayouts();
    delete all[req.params.host];
    saveLayouts();
    res.json({ ok: true });
  });
};
