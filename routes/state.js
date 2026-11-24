'use strict';

/**
 * Saved state: the encrypted vault of switches and credentials.
 */

const vault = require('../vault');
const collector = require('../collector');

module.exports = function register(app) {
  // -----------------------------------------------------------------
  // Saved state
  // -----------------------------------------------------------------
  /**
   * The switches you had open, and what it takes to reach them. Encrypted at
   * rest -- see vault.js for exactly what that does and does not protect
   * against, stated plainly.
   */
  app.get('/api/state', (req, res) => {
    const state = vault.load();
    res.json({
      state: state && !state.unreadable ? state : null,
      unreadable: !!(state && state.unreadable),
      storage: vault.describe()
    });
  });

  app.put('/api/state', (req, res) => {
    const body = req.body || {};
    if (!Array.isArray(body.switches)) {
      return res.status(400).json({ error: 'switches must be an array.' });
    }
    const ok = vault.save({
      switches: body.switches,
      activeId: body.activeId || null,
      savedAt: new Date().toISOString()
    });
    // The collector polls whatever is saved; let it pick up an add/remove at
    // once rather than at the next cycle boundary.
    try { collector.reload(); } catch (e) { /* next cycle re-reads anyway */ }
    res.json({ saved: ok, storage: vault.describe() });
  });

  app.delete('/api/state', (req, res) => {
    vault.clear();
    res.json({ cleared: true });
  });
};
