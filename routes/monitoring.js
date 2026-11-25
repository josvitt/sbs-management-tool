'use strict';

/**
 * Reachability, metric history, the collector's snapshots and the event log.
 */

const history = require('../history');
const events = require('../events');
const collector = require('../collector');
const { redactTarget } = require('../snmp-core');
const { probeSwitch } = require('../collection');

module.exports = function register(app) {
  app.post('/api/ping', async (req, res) => {
    const { target } = req.body || {};
    if (!target || !target.host) return res.status(400).json({ error: 'target.host is required.' });
    const result = await probeSwitch(target);
    // Preserve the prior contract: a bad session (credential problem) was a 400.
    if (!result.reachable && result.ms === 0 && result.error) {
      return res.status(400).json({ error: result.error });
    }
    res.json(result);
  });

  // -----------------------------------------------------------------
  // Metric history
  // -----------------------------------------------------------------
  /**
   * The browser samples; this keeps. Sent in batches rather than one at a
   * time, and kept whether or not the switch's tab is still open.
   */
  app.post('/api/history', (req, res) => {
    const { host, samples } = req.body || {};
    if (!host) return res.status(400).json({ error: 'host is required.' });
    const added = history.append(host, samples || []);
    res.json({ added });
  });

  app.get('/api/history', (req, res) => {
    const host = req.query.host;
    if (!host) return res.status(400).json({ error: 'host is required.' });
    const since = Number(req.query.since) || 0;
    res.json({ host, samples: history.get(host, since) });
  });

  app.get('/api/history/hosts', (req, res) => res.json({ hosts: history.hosts() }));

  app.delete('/api/history', (req, res) => {
    history.forget(req.query.host);
    res.json({ cleared: true });
  });

  // -----------------------------------------------------------------
  // Server-side collector: snapshots + event log
  // -----------------------------------------------------------------
  // What the server knows about each saved switch right now, without walking
  // anything (the browser-independent view).
  app.get('/api/collector/status', (req, res) => {
    res.json({ switches: collector.status() });
  });

  // A snapshot as it leaves the server. The collector keeps the full target
  // (it needs the credentials to poll); a response never carries them, the same
  // redaction the log applies. The browser does not read snapshot.target.
  function publicSnapshot(snap) {
    return snap && snap.target ? { ...snap, target: redactTarget(snap.target) } : snap;
  }

  // The latest server-collected health snapshot for one switch, so a browser
  // can render current state without polling the switch itself.
  app.get('/api/collector/snapshot', (req, res) => {
    const host = req.query.host;
    if (!host) return res.status(400).json({ error: 'host is required.' });
    const snap = collector.snapshotByHost(host);
    if (!snap) return res.status(404).json({ error: 'No snapshot yet for ' + host });
    // The browser says which collection it already shows (`have`, its
    // collectedAt). The full collection changes every few minutes while the
    // view re-reads every 30 s, so most reads find the same data: answer
    // those with a few bytes and let the page skip the download and repaint.
    const have = req.query.have;
    if (have && !snap.error && snap.data && snap.data.collectedAt === have) {
      return res.json({ unchanged: true, at: snap.at, collectedAt: have });
    }
    res.json(publicSnapshot(snap));
  });

  // Manual "Refresh" = nudge the server to poll this switch now, then return the
  // fresh snapshot. No direct browser->switch walk (the chosen manual-refresh
  // behaviour); the single polling authority stays on the server.
  app.post('/api/collect/now', async (req, res) => {
    const { target } = req.body || {};
    if (!target || !target.host) return res.status(400).json({ error: 'target.host is required.' });
    try {
      const snap = await collector.nudge(target);
      if (!snap) return res.status(503).json({ error: 'Collector is not running.' });
      if (snap.error) return res.status(502).json({ error: snap.error, snapshot: publicSnapshot(snap) });
      res.json(publicSnapshot(snap));
    } catch (e) {
      res.status(502).json({ error: e.message });
    }
  });

  // The event log for one switch (alert raised/cleared, reachability down/up,
  // reboot, config-change), oldest first.
  app.get('/api/events', (req, res) => {
    const host = req.query.host;
    if (!host) return res.status(400).json({ error: 'host is required.' });
    res.json({
      host,
      events: events.recent(host, {
        limit: Number(req.query.limit) || 200,
        type: req.query.type || undefined,
        since: Number(req.query.since) || undefined,
        generations: Number(req.query.generations) || 0
      })
    });
  });
};
