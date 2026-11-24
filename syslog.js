/**
 * Embedded syslog receiver.
 *
 * Switches only tell you about an event as it happens over syslog -- the
 * SNMP log tables are a snapshot and the tech-support capture is a text
 * dump. Running the collector inside the app means a switch can be pointed
 * at it with nothing else to install.
 *
 * Messages are held in memory, in a bounded ring per source. Nothing is
 * written to disk: log lines routinely carry usernames, addresses and
 * topology detail, and persisting them by default would be a decision the
 * operator did not make.
 */

const dgram = require('dgram');
const log = require('./logger');

const DEFAULT_PORT = 514;
const PER_SOURCE_LIMIT = 2000;

// RFC 3164: PRI = facility * 8 + severity.
const SEVERITIES = ['Emergency', 'Alert', 'Critical', 'Error', 'Warning', 'Notice', 'Info', 'Debug'];
const FACILITIES = [
  'kernel', 'user', 'mail', 'daemon', 'auth', 'syslog', 'lpr', 'news',
  'uucp', 'cron', 'authpriv', 'ftp', 'ntp', 'audit', 'alert', 'clock',
  'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7'
];

// Subscribers are notified as each message lands, so the UI can show it
// without polling. Kept deliberately simple: a Set of callbacks, cleared
// by the unsubscribe function each caller gets back.
const subscribers = new Set();

function subscribe(fn) {
  subscribers.add(fn);
  return () => subscribers.delete(fn);
}

let socket = null;
let listening = false;
let listenPort = null;
let bindError = null;
let received = 0;
const bySource = new Map();   // source IP -> { messages: [], total, firstAt, lastAt }

/**
 * Parse a syslog line. Both RFC 3164 ("<190>Jan  2 15:04:05 host tag: msg")
 * and RFC 5424 ("<190>1 2026-01-02T15:04:05Z host app - - - msg") appear in
 * the wild; Catalyst switches emit the former, often with their own
 * "%FACILITY-S-MNEMONIC:" convention inside the message body.
 */
function parseMessage(text, from) {
  const raw = String(text).replace(/\0+$/, '').trim();
  const out = {
    from, raw,
    at: new Date().toISOString(),
    severity: null, severityName: 'Unknown', facility: null, facilityName: null,
    host: null, tag: null, message: raw, mnemonic: null
  };

  let rest = raw;
  const pri = rest.match(/^<(\d{1,3})>/);
  if (pri) {
    const value = Number(pri[1]);
    out.severity = value & 0x07;
    out.facility = value >> 3;
    out.severityName = SEVERITIES[out.severity] || String(out.severity);
    out.facilityName = FACILITIES[out.facility] || ('facility ' + out.facility);
    rest = rest.slice(pri[0].length);
  }

  // RFC 5424 puts a version digit and an ISO timestamp next.
  const v5 = rest.match(/^1\s+(\S+)\s+(\S+)\s+(\S+)\s+\S+\s+\S+\s+(?:\[[^\]]*\]|-)\s*(.*)$/s);
  if (v5) {
    out.timestamp = v5[1];
    out.host = v5[2] !== '-' ? v5[2] : null;
    out.tag = v5[3] !== '-' ? v5[3] : null;
    out.message = v5[4];
  } else {
    const v3 = rest.match(/^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)$/s);
    if (v3) {
      out.timestamp = v3[1];
      out.host = v3[2];
      out.message = v3[3];
    } else {
      out.message = rest;
    }
    const tag = out.message.match(/^([\w.\-\/]+)(?:\[(\d+)\])?:\s*(.*)$/s);
    if (tag) { out.tag = tag[1]; out.message = tag[3]; }
  }

  // The switch's own %FACILITY-SEVERITY-MNEMONIC marker, which is what an
  // operator actually recognises. The mnemonic is not all-caps in practice
  // -- %LINK-W-Down and %3SWCOS-F-InitFail are both real -- so only the
  // facility and the single severity letter are anchored to upper case.
  const cisco = out.message.match(/%%?([A-Z0-9_]+(?:-[A-Z0-9_]+)*?)-([A-Z])-(\w+)\s*:\s*(.*)$/s);
  if (cisco) {
    out.mnemonic = cisco[1] + '-' + cisco[2] + '-' + cisco[3];
    out.facilityMnemonic = cisco[1];
    out.message = cisco[4];
    // With no PRI header the severity letter is the only signal there is.
    if (out.severity === null) {
      const fromLetter = { F: 0, M: 0, A: 1, C: 2, E: 3, W: 4, N: 5, P: 5, I: 6, D: 7 }[cisco[2]];
      if (fromLetter !== undefined) {
        out.severity = fromLetter;
        out.severityName = SEVERITIES[fromLetter];
      }
    }
  }
  return out;
}

function record(entry) {
  received += 1;
  let bucket = bySource.get(entry.from);
  if (!bucket) {
    bucket = { messages: [], total: 0, firstAt: entry.at, lastAt: entry.at };
    bySource.set(entry.from, bucket);
    log.info('syslog', 'First message from a new source', { from: entry.from });
  }
  bucket.messages.push(entry);
  bucket.total += 1;
  bucket.lastAt = entry.at;
  // Bounded: a chatty switch must not grow the process without limit.
  if (bucket.messages.length > PER_SOURCE_LIMIT) {
    bucket.messages.splice(0, bucket.messages.length - PER_SOURCE_LIMIT);
  }
  for (const fn of subscribers) {
    // One broken subscriber must not stop the others, or stop reception.
    try { fn(entry, bucket); } catch (e) {
      log.error('syslog', 'Subscriber threw', { message: e.message });
    }
  }
}

/** Start listening. Resolves even on failure so the app still runs. */
function start(port) {
  if (listening) return Promise.resolve({ listening, port: listenPort });
  const want = port || DEFAULT_PORT;
  return new Promise((resolve) => {
    socket = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    socket.on('error', (err) => {
      bindError = err.message + (err.code === 'EACCES'
        ? ' (ports below 1024 need elevated privileges on this OS; set SYSLOG_PORT to use another)'
        : (err.code === 'EADDRINUSE' ? ' (another syslog collector is already running)' : ''));
      log.error('syslog', 'Could not start the syslog receiver', { port: want, message: err.message });
      listening = false;
      try { socket.close(); } catch (e) { /* already down */ }
      socket = null;
      resolve({ listening: false, port: want, error: bindError });
    });
    socket.on('message', (buf, rinfo) => {
      try {
        record(parseMessage(buf.toString('utf8'), rinfo.address));
      } catch (e) {
        log.error('syslog', 'Failed to parse a message', { from: rinfo.address, message: e.message });
      }
    });
    socket.bind(want, () => {
      listening = true;
      listenPort = socket.address().port;
      bindError = null;
      log.info('syslog', 'Syslog receiver listening', { port: listenPort });
      resolve({ listening: true, port: listenPort });
    });
  });
}

function status() {
  return {
    listening, port: listenPort, error: bindError, received,
    sources: Array.from(bySource.entries()).map(([from, b]) => ({
      from, total: b.total, held: b.messages.length, firstAt: b.firstAt, lastAt: b.lastAt
    }))
  };
}

/** Messages from one source, newest first, optionally filtered by severity. */
function messagesFor(host, opts) {
  opts = opts || {};
  const bucket = bySource.get(host);
  if (!bucket) return { messages: [], total: 0, held: 0 };
  let list = bucket.messages;
  if (opts.maxSeverity !== undefined && opts.maxSeverity !== null && opts.maxSeverity !== '') {
    const limit = Number(opts.maxSeverity);
    list = list.filter((m) => m.severity === null || m.severity <= limit);
  }
  if (opts.search) {
    const q = String(opts.search).toLowerCase();
    list = list.filter((m) => m.raw.toLowerCase().indexOf(q) >= 0);
  }
  const limit = Math.max(1, Math.min(1000, Number(opts.limit) || 200));
  return {
    total: bucket.total,
    held: bucket.messages.length,
    matched: list.length,
    firstAt: bucket.firstAt,
    lastAt: bucket.lastAt,
    messages: list.slice(-limit).reverse()
  };
}

function clear(host) {
  if (host) bySource.delete(host);
  else bySource.clear();
}

module.exports = {
  start, status, messagesFor, clear, parseMessage, subscribe,
  SEVERITIES, FACILITIES, DEFAULT_PORT
};
