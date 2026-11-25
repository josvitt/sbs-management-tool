'use strict';

/**
 * SNMP traps and syslog: the receivers' persistence and their routes.
 */

const { writeHold } = require('../write-hold');
const log = require('../logger');
const mib = require('../mibdb');
const syslog = require('../syslog');
const syslogConfig = require('../syslog-config');
const traps = require('../traps');
const collector = require('../collector');
const rotate = require('../rotate');
const { buildSnmpSession, redactTarget } = require('../snmp-core');

module.exports = function register(app) {
  // -----------------------------------------------------------------
  // SNMP traps
  // -----------------------------------------------------------------
  /**
   * Traps are the switch interrupting us rather than answering a question,
   * so the receiver is started with the app and left running: a trap that
   * arrives while nobody is looking is exactly the one worth having kept.
   */
  traps.start({
    port: Number(process.env.TRAP_PORT) || 162,
    // The MIB database turns an OID into a name, and where the object has
    // an enumeration, a value into the label a person would recognise:
    // "linkDown" and "down (2)" rather than two numbers.
    describe: (oid, value) => {
      try {
        const name = mib.describeOid(oid);
        const hit = mib.entryForOid(oid);
        const entry = hit && hit.entry;
        let display;
        if (value !== undefined && value !== null) {
          const raw = Buffer.isBuffer(value) ? value.toString('latin1') : value;
          display = String(raw);
          if (entry && entry.enum && entry.enum[String(raw)]) {
            display = entry.enum[String(raw)] + ' (' + raw + ')';
          } else if (entry && entry.units) {
            display = raw + ' ' + entry.units;
          }
        }
        return { name: name || oid, display };
      } catch (e) {
        // Worth knowing about rather than silently degrading to raw OIDs.
        log.warn('traps', 'Could not describe an OID', { oid, message: e.message });
        return null;
      }
    }
  });

  // Traps and syslog were received but only ever held in memory and streamed,
  // so a notification that arrived while nobody was looking was lost on restart.
  // Persist each to a rotating per-host store so the unattended collector keeps a
  // durable record. The in-memory ring buffers / SSE are unchanged; this is an
  // additional always-on sink.
  const path_ = require('path');
  // logs/ in the install folder. Versions before 1.2.0 wrote these under
  // routes/logs/ by mistake (left over from the route split); moved once.
  const STREAM_LOG_DIR = path_.join(__dirname, '..', 'logs');
  for (const kind of ['traps', 'syslog']) {
    rotate.adoptLegacy(path_.join(__dirname, 'logs', kind), path_.join(STREAM_LOG_DIR, kind));
  }
  try { require('fs').rmdirSync(path_.join(__dirname, 'logs')); } catch (e) { /* not there, or not empty */ }
  function persistStreamLine(kind, host, obj) {
    const safe = String(host || 'unknown').replace(/[^A-Za-z0-9._-]/g, '_');
    const file = path_.join(STREAM_LOG_DIR, kind, safe + '.log');
    rotate.appendLine(file, JSON.stringify(obj), { maxBytes: 5 * 1024 * 1024, keep: 10 });
  }

  // A trap that specifically announces a running-config CHANGE should trip the
  // config gate. The C1200/1300 MIB has no such trap - its only config-related
  // traps are rlCopyFinished/rlCopyFailed, which fire on ANY copy, including the
  // app's OWN config pulls (the gate's diff fetches, and user fetch/sync). Keying
  // on those would make every pull re-arm the gate and pull again every interval
  // forever. So copy traps are deliberately NOT treated as a change signal; on
  // this platform the gate is driven by the unsaved-config flag (read on the ~30s
  // probe) plus reboot. This matcher stays for platforms that DO emit a genuine
  // running-config-changed notification (e.g. enterprise IOS ccmCLIRunningConfigChanged).
  function trapSuggestsConfigChange(message) {
    const hay = (message.name || '') + ' ' + (message.oid || '') + ' ' +
      (message.varbinds || []).map((v) => (v.name || '') + ' ' + (v.oid || '')).join(' ');
    return /ccmCLIRunningConfigChanged|runningConfigChanged/i.test(hay);
  }

  traps.subscribe((message) => {
    try {
      persistStreamLine('traps', message.source, message);
      if (trapSuggestsConfigChange(message) && message.source) {
        collector.flagConfigChange(message.source);
      }
    } catch (e) { /* persistence must never disturb trap handling */ }
  });
  syslog.subscribe((entry) => {
    try { persistStreamLine('syslog', entry.from, entry); } catch (e) { /* best effort */ }
  });

  app.get('/api/traps/status', (req, res) => res.json(traps.status()));

  app.post('/api/traps/messages', (req, res) => {
    const { host, limit, search } = req.body || {};
    if (!host) return res.status(400).json({ error: 'host is required.' });
    res.json(traps.messagesFor(host, { limit, search }));
  });

  app.get('/api/traps/stream', (req, res) => {
    const host = req.query.host;
    res.set({
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no'
    });
    res.flushHeaders();
    res.write('retry: 3000\n\n');

    const unsubscribe = traps.subscribe((message) => {
      if (host && message.source !== host) return;
      try {
        res.write('data: ' + JSON.stringify(message) + '\n\n');
      } catch (e) { /* the browser went away */ }
    });

    const keepAlive = setInterval(() => {
      try { res.write(': ping\n\n'); } catch (e) { /* closed */ }
    }, 25000);

    req.on('close', () => { clearInterval(keepAlive); unsubscribe(); });
  });

  // -----------------------------------------------------------------
  // Syslog
  // -----------------------------------------------------------------
  // The receiver runs inside this app, so a switch can be pointed at it with
  // nothing else to install. Messages are held in memory only.

  app.get('/api/syslog/status', (req, res) => res.json(syslog.status()));

  /**
   * Live message stream, as server-sent events. One-way and text-based, so
   * it needs no protocol of its own and reconnects by itself if the link
   * drops -- which is the whole requirement here.
   */
  app.get('/api/syslog/stream', (req, res) => {
    const host = req.query.host;
    res.set({
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no'
    });
    res.flushHeaders();
    res.write('retry: 3000\n\n');

    const unsubscribe = syslog.subscribe((entry, bucket) => {
      if (host && entry.from !== host) return;
      res.write('data: ' + JSON.stringify({ message: entry, total: bucket.total }) + '\n\n');
    });

    // Comment frames keep proxies and idle timeouts from closing the stream.
    const keepAlive = setInterval(() => res.write(': keep-alive\n\n'), 25000);
    req.on('close', () => {
      clearInterval(keepAlive);
      unsubscribe();
    });
  });

  app.post('/api/syslog/messages', (req, res) => {
    const { host, limit, maxSeverity, search } = req.body || {};
    if (!host) return res.status(400).json({ error: 'host is required.' });
    res.json(Object.assign({ receiver: syslog.status() },
      syslog.messagesFor(host, { limit, maxSeverity, search })));
  });

  // Is this switch already sending to us? Answered two ways: what the switch
  // says its collectors are, and whether anything has actually arrived.
  app.post('/api/syslog/collectors', async (req, res) => {
    const { target } = req.body || {};
    if (!target || !target.host) return res.status(400).json({ error: 'target.host is required.' });
    try {
      const ourAddress = await syslogConfig.localAddressFor(target.host);
      const info = await syslogConfig.readCollectors(() => buildSnmpSession(target), { ourAddress });
      const status = syslog.status();
      const heard = status.sources.find((s) => s.from === target.host) || null;
      res.json(Object.assign({ ourAddress, receiver: status, heard }, info));
    } catch (e) {
      log.error('syslog', 'Could not read syslog collectors', {
        target: redactTarget(target), message: e.message
      });
      res.status(502).json({ error: e.message });
    }
  });

  // Writes to the switch: adds this machine as a syslog destination.
  app.post('/api/syslog/configure', writeHold(), async (req, res) => {
    const { target, severity } = req.body || {};
    if (!target || !target.host) return res.status(400).json({ error: 'target.host is required.' });
    try {
      const started = await syslog.start(Number(process.env.SYSLOG_PORT) || undefined);
      if (!started.listening) {
        throw new Error('The syslog receiver is not running, so there is nothing to point the ' +
          'switch at: ' + (started.error || 'unknown reason'));
      }
      const address = await syslogConfig.localAddressFor(target.host);
      const result = await syslogConfig.addCollector(() => buildSnmpSession(target), {
        host: target.host, address, port: started.port, severity
      });
      res.json(result);
    } catch (e) {
      log.error('syslog', 'Could not configure syslog', {
        target: redactTarget(target), message: e.message
      });
      res.status(502).json({ error: e.message });
    }
  });

  app.post('/api/syslog/remove', writeHold(), async (req, res) => {
    const { target, index, table } = req.body || {};
    if (!target || !target.host || index === undefined) {
      return res.status(400).json({ error: 'target.host and index are required.' });
    }
    try {
      res.json(await syslogConfig.removeCollector(() => buildSnmpSession(target), index, table));
    } catch (e) {
      res.status(502).json({ error: e.message });
    }
  });
};
