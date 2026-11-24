/**
 * SBS Management Tool - backend
 *
 * A browser can't open a raw SSH/TCP socket, so this small local server
 * does the actual SSH connection (via ssh2) and streams the terminal
 * session to the browser over a WebSocket. It also proxies SNMP
 * requests (via net-snmp), since browsers can't send raw UDP either.
 * The HTML page in /public is the entire user-facing frontend, and
 * supports multiple concurrent sessions as browser tabs -- SSH tabs
 * each get their own WebSocket here (independent SSH client, stream,
 * and state per connection); SNMP "tabs" are stateless request/response
 * calls to the REST endpoint below, so no per-tab backend state is
 * needed for those at all.
 *
 * All errors -- backend and frontend -- are logged with timestamps to
 * both the console and logs/app.log. See logger.js. This is metadata
 * only (host, username, error text) for troubleshooting the tool
 * itself -- never the actual content of an SSH session or SNMP query.
 *
 * Session output is NEVER written to disk automatically. The only way
 * to save it is the "Save Output" button in the browser, which
 * downloads what's currently on screen on demand -- there is no
 * separate always-on recording path to keep in sync with it.
 *
 * Run with:  start.bat  (Windows)  or  npm install && npm start
 * Then open: http://localhost:3000
 */

const express = require('express');
const http = require('http');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');
const { Client } = require('ssh2');
const snmp = require('net-snmp');
const log = require('./logger');
const mib = require('./mibdb');
const health = require('./health');
const tftp = require('./tftp');
const configFetch = require('./config-fetch');
const opc = require('./opc');
const aaa = require('./aaa');
const syslog = require('./syslog');
const syslogConfig = require('./syslog-config');
const serial = require('./serial');
const traps = require('./traps');
const vault = require('./vault');
const history = require('./history');
const events = require('./events');
const collector = require('./collector');
const rotate = require('./rotate');
const v3crypto = require('./snmp-crypto');
const snmpConfig = require('./snmp-config');
const guard = require('./request-guard');

// Catch anything that would otherwise silently kill the process.
process.on('uncaughtException', (err) => {
  log.error('process', 'Uncaught exception', { message: err.message, stack: err.stack });
});
process.on('unhandledRejection', (reason) => {
  log.error('process', 'Unhandled promise rejection', {
    message: reason && reason.message ? reason.message : String(reason)
  });
});

const app = express();
// First, before any asset or route: refuse cross-site and DNS-rebinding
// requests (see request-guard.js). LAN access is unaffected.
app.use(guard.middleware(log));
app.use(express.json());
/**
 * Compress static assets. The MIB database alone is 2 MB of JSON fetched
 * on every page load and gzips to about 315 KB, so this is the single
 * biggest saving available. The files never change while the server runs,
 * so each compressed body is built once and reused.
 */
const gzipCache = new Map();
app.use((req, res, next) => {
  if (!/\.(json|js|css|html|svg|map)$/i.test(req.path)) return next();
  if (!/\bgzip\b/.test(req.headers['accept-encoding'] || '')) return next();

  const filePath = path.join(__dirname, 'public', path.normalize(req.path).replace(/^([.][.][/\\])+/, ''));
  if (!filePath.startsWith(path.join(__dirname, 'public'))) return next();   // no path escapes

  /**
   * Serve from the cache with a validator. Without one the browser
   * re-downloads every asset on every reload -- 315 KB of compressed MIB
   * database each time, for a file that has not changed. With it the
   * second load is a handful of 304s.
   */
  const serve = (entry) => {
    res.set({
      'Content-Encoding': 'gzip',
      'Content-Type': entry.type,
      Vary: 'Accept-Encoding',
      ETag: entry.etag,
      // Must-revalidate rather than a long max-age: these files change
      // when the app is updated, and a stale UI is worse than a request.
      'Cache-Control': 'no-cache'
    });
    if (req.headers['if-none-match'] === entry.etag) return res.status(304).end();
    return res.end(entry.body);
  };

  const cached = gzipCache.get(filePath);
  if (cached) return serve(cached);

  fs.readFile(filePath, (err, raw) => {
    if (err) return next();                        // not ours; let express.static answer
    zlib.gzip(raw, { level: 6 }, (gzErr, body) => {
      if (gzErr) return next();
      const type = express.static.mime.lookup(filePath) || 'application/octet-stream';
      const entry = {
        body, type,
        etag: '"' + crypto.createHash('sha1').update(raw).digest('base64').slice(0, 22) + '"'
      };
      gzipCache.set(filePath, entry);
      log.info('http', 'Compressed asset', {
        path: req.path, from: raw.length, to: body.length,
        saved: Math.round(100 - (100 * body.length) / raw.length) + '%'
      });
      serve(entry);
    });
  });
});

/**
 * Compress API responses too. A health collection from a switch with a
 * full forwarding database is a few hundred KB of highly repetitive JSON,
 * and it is re-fetched on every auto-refresh.
 */
app.use((req, res, next) => {
  const wantsGzip = /\bgzip\b/.test(req.headers['accept-encoding'] || '');
  if (!wantsGzip) return next();
  const original = res.json.bind(res);
  res.json = (body) => {
    let text;
    try { text = JSON.stringify(body); } catch (e) { return original(body); }
    if (text.length < 8192) return original(body);      // not worth the CPU
    zlib.gzip(text, { level: 6 }, (err, buf) => {
      if (err) return original(body);
      res.set({ 'Content-Type': 'application/json; charset=utf-8',
                'Content-Encoding': 'gzip', 'Vary': 'Accept-Encoding' });
      res.end(buf);
    });
    return res;
  };
  next();
});

app.use(express.static(path.join(__dirname, 'public')));

// Basic request logging.
app.use((req, res, next) => {
  log.info('http', `${req.method} ${req.url}`, { ip: req.ip });
  next();
});

// Frontend errors get POSTed here so they land in the same log file
// as backend events -- one place to look when something breaks.
app.post('/api/log', (req, res) => {
  const { level, message, meta } = req.body || {};
  const lvl = ['info', 'warn', 'error'].includes(level) ? level : 'error';
  log[lvl]('client', message || '(no message)', meta);
  res.status(204).end();
});

// -----------------------------------------------------------------
// SNMP
// -----------------------------------------------------------------
// SNMP is a stateless, connectionless (UDP) request/response protocol,
// unlike the SSH terminal above -- there's no persistent "session" to
// maintain across requests, so each API call opens a short-lived
// net-snmp session, performs one operation, and closes it. No SNMP
// content (query results) is ever written to disk here either; the
// frontend holds results in memory and the user can export them the
// same on-demand way as SSH output.

// The rlCopyFinished trap OID. Any rlCopyTable operation (config save, capture
// -> flash, ...) emits it on completion, so every copy call site wires the same
// event-driven waiter through this one helper rather than repeating the OID.
const RL_COPY_FINISHED_OID = '1.3.6.1.4.1.9.6.1.101.0.180';
function copyFinishedWaiter(host, timeoutMs) {
  return () => traps.waitForTrap({ source: host, oid: RL_COPY_FINISHED_OID, timeoutMs: timeoutMs || 600000 }).promise;
}

// The ONE derivation of an SNMPv3 target's methods and security level, used
// to build the session and to judge whether it encrypts (keyTransportWarning),
// so the two can never disagree. An explicit method wins; an older saved
// target that only carries `level` gets the defaults it always got.
function v3SecurityOf(v3) {
  const authName = v3.authProtocol === undefined ? (v3.level === 'noAuthNoPriv' ? 'none' : 'sha') : v3.authProtocol;
  const privName = v3.privProtocol === undefined ? (v3.level === 'authPriv' ? 'aes128' : 'none') : v3.privProtocol;
  return { authName, privName, level: v3crypto.securityLevelFor(authName, privName) };
}

function buildSnmpSession(target) {
  const { host, port, version, community, v3 } = target;
  const commonOptions = {
    port: port || 161,
    // A caller that knows it wants a quick answer (the reachability
    // probe) can say so rather than waiting on the collection defaults.
    retries: target.retries === undefined ? 1 : target.retries,
    timeout: target.timeout === undefined ? 3000 : target.timeout
  };

  if (version === '3') {
    if (!v3 || !v3.username) {
      throw new Error('SNMPv3 requires a username.');
    }
    // The security level is derived from the two method choices rather
    // than asked for separately -- "authPriv with privacy None" is a
    // contradiction the user should never have to resolve.
    const { authName, privName, level } = v3SecurityOf(v3);

    const user = { name: v3.username, level: snmp.SecurityLevel[level] };
    if (level !== 'noAuthNoPriv') {
      user.authProtocol = v3crypto.resolveAuth(authName);
      user.authKey = v3.authKey;
      if (!user.authKey) throw new Error('An authentication password is required for ' + authName.toUpperCase() + '.');
    }
    if (level === 'authPriv') {
      user.privProtocol = v3crypto.resolvePriv(privName);
      user.privKey = v3.privKey;
      if (!user.privKey) throw new Error('A privacy password is required when privacy is enabled.');
    }
    return snmp.createV3Session(host, user, commonOptions);
  }

  const snmpVersion = version === '1' ? snmp.Version1 : snmp.Version2c;
  return snmp.createSession(host, community || 'public', { ...commonOptions, version: snmpVersion });
}

// Every OID that comes in from the UI or the API may be either a numeric
// OID or a MIB name from the C1200/C1300 set ("sysName", "sysName.0",
// "rlPethPsePortPowerLimit.1.5"). Resolve them all up front so a typo in a
// name is reported clearly instead of being sent to the switch as garbage.
function resolveOids(list) {
  return list.map((o) => {
    try {
      return mib.resolveOid(o);
    } catch (e) {
      const err = new Error(e.message);
      err.userFacing = true;
      throw err;
    }
  });
}

// Attach the MIB name to each returned varbind so the UI can show
// "ifDescr.3" next to 1.3.6.1.2.1.2.2.1.2.3.
function annotate(result) {
  const name = mib.describeOid(result.oid);
  return name ? { ...result, name } : result;
}

// ---------------------------------------------------------------
// Bounded walk
// ---------------------------------------------------------------
// net-snmp's session.walk() issues GETBULK with maxRepetitions for v2c/v3.
// At the end of a subtree the agent still has to compute the remaining
// repetitions, so it keeps producing lexicographic successors *past* the
// requested subtree -- wandering into unrelated variables. On Catalyst
// 1200/1300 firmware that can make the switch log
//   %SNMP-D-MAXOIDSINKEYREACHED: too many oids in key for variable NN
// when a successor lands on an object whose instance key is longer than
// its handler accepts.
//
// This implementation keeps the same GETBULK speed but enforces the
// subtree boundary in our own code: results outside the base OID are
// discarded and the walk stops immediately rather than requesting more.
// 'next' mode drops to one-at-a-time GETNEXT, which never speculates
// beyond the boundary at all -- slower, but the safest option for
// firmware that complains.

const WALK_DEFAULTS = {
  maxRepetitions: 10,   // deliberately below net-snmp's default of 20
  maxRows: 10000,       // stop runaway walks
  maxOidLength: 128,    // sub-identifier sanity guard
  // Milliseconds to wait between consecutive GETBULK/GETNEXT requests in a
  // single walk. Without this, requests fire as fast as the switch answers, so
  // a full collection becomes a brief high-pps burst that loads the switch CPU.
  // A small gap turns each walk into gentle, steady traffic. Tunable via env.
  // 20ms between requests per stream = up to ~50 req/s per stream; with the
  // default 2 concurrent walks that is a ~100 pps ceiling - the agreed maximum
  // CPU input rate for the switch, while giving faster collections than a
  // gentler pace would. Raise paceMs (or lower concurrency) to go gentler.
  paceMs: Number(process.env.SNMP_PACE_MS) || 20,
  // A safety net per request, the same one snmpResponder gives GET and SET:
  // net-snmp normally answers or times out on its own, but a reply that fails
  // to parse can leave a callback pending forever. Without this a stuck walk
  // hangs its HTTP request and, in the collector, leaves that switch marked
  // in-flight so it is never polled again until a restart. It bounds ONE
  // request, not the whole walk, so a long legitimate walk is unaffected.
  stepWatchdogMs: Number(process.env.SNMP_STEP_WATCHDOG_MS) || 12000
};

function isWithinSubtree(base, oid) {
  if (oid === base) return true;
  return oid.startsWith(base + '.');
}

// Lexicographic OID comparison, so we can detect an agent that fails to
// advance (which would otherwise loop forever).
function oidCompare(a, b) {
  const x = a.split('.').map(Number);
  const y = b.split('.').map(Number);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const xi = x[i] === undefined ? -1 : x[i];
    const yi = y[i] === undefined ? -1 : y[i];
    if (xi !== yi) return xi < yi ? -1 : 1;
  }
  return 0;
}

// The ONE walk. `raw: true` returns untouched net-snmp varbinds
// ({ oid, value, type }) for callers that decode values themselves
// (snmp-config) and skips per-varbind errors; otherwise rows are described
// for the UI. onDone fires exactly once.
function boundedWalk(session, baseOid, options, onDone) {
  const opts = Object.assign({}, WALK_DEFAULTS, options || {});
  const useBulk = opts.mode !== 'next' && session.version !== snmp.Version1;
  const results = [];
  let current = baseOid;
  let truncated = null;
  let done = false;
  let watchdog = null;

  function finish(error) {
    if (done) return;
    done = true;
    clearTimeout(watchdog);
    onDone(error || null, results, truncated);
  }

  function handle(error, varbinds) {
    if (done) return;               // the watchdog already ended this walk
    clearTimeout(watchdog);
    if (error) return finish(error);

    for (const vb of varbinds) {
      // endOfMibView / noSuchObject terminate the walk cleanly.
      if (vb.type === snmp.ObjectType.EndOfMibView ||
          vb.type === snmp.ObjectType.NoSuchObject ||
          vb.type === snmp.ObjectType.NoSuchInstance) {
        return finish(null);
      }
      // The boundary check: anything outside the requested subtree is an
      // over-fetch, not a result. Drop it and stop.
      if (!isWithinSubtree(baseOid, vb.oid)) {
        return finish(null);
      }
      if (oidCompare(vb.oid, current) <= 0) {
        // Agent did not advance -- bail out instead of looping forever.
        return finish(null);
      }
      if (vb.oid.split('.').length > opts.maxOidLength) {
        truncated = 'Stopped: OID depth exceeded the safety limit.';
        return finish(null);
      }

      if (opts.raw) {
        if (!snmp.isVarbindError(vb)) results.push({ oid: vb.oid, value: vb.value, type: vb.type });
      } else if (snmp.isVarbindError(vb)) {
        results.push(annotate({ oid: vb.oid, error: snmp.varbindError(vb) }));
      } else {
        results.push(describeVarbind(vb));
      }
      current = vb.oid;

      if (results.length >= opts.maxRows) {
        truncated = `Stopped after ${opts.maxRows} rows.`;
        return finish(null);
      }
    }

    // Pace the next request so the walk is gentle on the switch CPU rather than
    // a burst. A zero/negative paceMs fires immediately (old behaviour).
    if (opts.paceMs > 0) setTimeout(step, opts.paceMs);
    else step();
  }

  function step() {
    if (done) return;
    if (opts.stepWatchdogMs > 0) {
      watchdog = setTimeout(() => {
        log.error('snmp', 'Walk request got no SNMP reply; ending the walk', { oid: current, rows: results.length });
        finish(new Error('The switch did not reply in time.'));
      }, opts.stepWatchdogMs);
    }
    if (useBulk) {
      session.getBulk([current], 0, opts.maxRepetitions, (error, varbinds) => {
        // getBulk hands back an array of arrays for the repeater.
        if (error) return handle(error);
        const flat = Array.isArray(varbinds[0]) ? varbinds[0] : varbinds;
        handle(null, flat);
      });
    } else {
      session.getNext([current], handle);
    }
  }

  step();
}

// ---------------------------------------------------------------
// Value formatting
// ---------------------------------------------------------------
// Each result carries both `value` (machine-readable) and `display`
// (what a human should read). The raw form is kept so the UI can sort,
// graph or export without re-parsing prose.

// net-snmp hands back Counter64 as a Buffer of big-endian bytes. Decoding
// it as text -- which is what a naive printable-ASCII check does -- turns
// 0x32 0x78 0x59 into the string "2xY" instead of 3307609, so counters
// must be read as an integer, never as a string.
function bufferToBigInt(buf) {
  if (!buf || buf.length === 0) return 0n;
  return BigInt('0x' + (buf.toString('hex') || '0'));
}

function groupDigits(value) {
  const s = String(value);
  return s.replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

// TimeTicks are hundredths of a second since the counter started.
function formatTimeTicks(ticks) {
  const n = Number(ticks);
  if (!Number.isFinite(n)) return String(ticks);
  const totalSec = Math.floor(n / 100);
  const hundredths = n % 100;
  const d = Math.floor(totalSec / 86400);
  const h = Math.floor((totalSec % 86400) / 3600);
  const m = Math.floor((totalSec % 3600) / 60);
  const s = totalSec % 60;
  const parts = [];
  if (d) parts.push(d + 'd');
  if (d || h) parts.push(h + 'h');
  if (d || h || m) parts.push(m + 'm');
  parts.push(s + (hundredths ? '.' + String(hundredths).padStart(2, '0') : '') + 's');
  return parts.join(' ');
}

function formatBitsPerSecond(n) {
  const v = Number(n);
  if (!Number.isFinite(v) || v <= 0) return null;
  // 4294967295 is the documented "speed unknown / too large" sentinel for
  // the 32-bit Speed column; ifHighSpeed carries the real value instead.
  if (v === 4294967295) return 'unknown (use HighSpeed)';
  if (v >= 1e9) return (v / 1e9).toFixed(v % 1e9 ? 1 : 0) + ' Gbps';
  if (v >= 1e6) return (v / 1e6).toFixed(v % 1e6 ? 1 : 0) + ' Mbps';
  if (v >= 1e3) return (v / 1e3).toFixed(v % 1e3 ? 1 : 0) + ' kbps';
  return v + ' bps';
}

const MAC_SYNTAX = /PhysAddress|MacAddress/i;

function looksPrintable(text) {
  // eslint-disable-next-line no-control-regex
  return /^[\x20-\x7e\r\n\t]*$/.test(text);
}

function formatOctetString(buf, mibEntry) {
  const syntax = (mibEntry && mibEntry.syntax) || '';
  if (MAC_SYNTAX.test(syntax) || buf.length === 6) {
    // 6 raw bytes in a PhysAddress column is a MAC; render it the way it
    // appears everywhere else in the switch UI and CLI.
    const hex = buf.toString('hex').toUpperCase().match(/../g) || [];
    if (MAC_SYNTAX.test(syntax)) return { value: hex.join(':'), display: hex.join(':') };
  }
  const text = buf.toString('utf8');
  if (looksPrintable(text)) {
    const trimmed = text.replace(/\0+$/, '');
    return {
      value: trimmed,
      display: trimmed.length ? trimmed : '(empty)'
    };
  }
  const hex = (buf.toString('hex').match(/../g) || []).join(' ');
  return { value: hex, display: hex + '  (hex)' };
}

/**
 * Build { value, display } for a varbind, using the MIB definition when one
 * is known. typeName is the net-snmp ObjectType name.
 */
function formatVarbind(typeName, rawValue, mibEntry) {
  const units = (mibEntry && mibEntry.units) || '';
  const withUnits = (s) => (units ? s + ' ' + units : s);

  // Counters and Gauges: always numeric, never text.
  if (typeName === 'Counter64') {
    const n = Buffer.isBuffer(rawValue) ? bufferToBigInt(rawValue) : BigInt(rawValue || 0);
    return { value: n.toString(), display: withUnits(groupDigits(n.toString())) };
  }
  if (typeName === 'Counter' || typeName === 'Counter32') {
    const n = Buffer.isBuffer(rawValue) ? bufferToBigInt(rawValue).toString() : String(rawValue);
    return { value: n, display: withUnits(groupDigits(n)) };
  }
  if (typeName === 'TimeTicks') {
    const n = Number(rawValue);
    // The raw tick count adds nothing once the duration is spelled out.
    return { value: n, display: formatTimeTicks(n) };
  }
  if (typeName === 'Gauge' || typeName === 'Gauge32' || typeName === 'Unsigned32') {
    const n = Number(rawValue);
    const name = (mibEntry && mibEntry.name) || '';
    // Speed columns are far easier to read as a rate than as raw bits.
    if (/Speed$/i.test(name) && !/HighSpeed$/i.test(name)) {
      const rate = formatBitsPerSecond(n);
      if (rate) return { value: n, display: `${rate}  (${groupDigits(n)})` };
    }
    if (/HighSpeed$/i.test(name)) {
      return { value: n, display: n ? `${groupDigits(n)} Mbps` : '0' };
    }
    return { value: n, display: withUnits(groupDigits(n)) };
  }
  if (typeName === 'Integer' || typeName === 'Integer32') {
    const n = Number(rawValue);
    const label = mibEntry && mibEntry.enum && mibEntry.enum[String(n)];
    if (label) return { value: n, display: `${label} (${n})` };
    return { value: n, display: withUnits(groupDigits(n)) };
  }
  if (typeName === 'OctetString') {
    if (Buffer.isBuffer(rawValue)) return formatOctetString(rawValue, mibEntry);
    const s = String(rawValue);
    return { value: s, display: s.length ? s : '(empty)' };
  }
  if (typeName === 'OID') {
    const s = String(rawValue);
    const named = mib.describeOid(s);
    return { value: s, display: named ? `${named}  (${s})` : s };
  }
  if (typeName === 'IpAddress') {
    const s = String(rawValue);
    return { value: s, display: s };
  }
  if (Buffer.isBuffer(rawValue)) return formatOctetString(rawValue, mibEntry);
  return { value: rawValue, display: String(rawValue) };
}

// Wraps a raw varbind into the shape the UI consumes.
function describeVarbind(vb) {
  const info = mib.entryForOid(vb.oid);
  const mibEntry = info && info.entry;
  const typeName = snmp.ObjectType[vb.type] || String(vb.type);
  const { value, display } = formatVarbind(typeName, vb.value, mibEntry);
  const out = {
    oid: vb.oid,
    type: typeName,
    value,
    display
  };
  if (mibEntry) {
    out.name = info.index ? `${mibEntry.name}.${info.index}` : mibEntry.name;
    out.column = mibEntry.name;
    out.index = info.index;
    if (mibEntry.description) out.description = mibEntry.description;
    if (mibEntry.units) out.units = mibEntry.units;
  }
  return out;
}

function redactTarget(target) {
  const clone = { ...target };
  if (clone.community) clone.community = '[REDACTED]';
  if (clone.v3) {
    clone.v3 = { ...clone.v3 };
    if (clone.v3.authKey) clone.v3.authKey = '[REDACTED]';
    if (clone.v3.privKey) clone.v3.privKey = '[REDACTED]';
  }
  return clone;
}

// GET or GETNEXT one or more OIDs.
// A safety net for the request/response SNMP endpoints. node-snmp normally
// fires its callback on success or after its own timeout, but a reply that
// fails to parse (seen with large multi-OID GETs) can leave the callback
// pending forever, which hangs the HTTP request and, in the UI, leaves a
// spinner stuck. finishOnce guarantees exactly one response and a watchdog
// guarantees one arrives: whichever of the SNMP callback or the timer fires
// first wins, the session is closed once, and later calls are ignored.
function snmpResponder(res, session, label, ms) {
  let done = false;
  const finish = (fn) => {
    if (done) return;
    done = true;
    clearTimeout(timer);
    try { if (session) session.close(); } catch (e) { /* already closed */ }
    fn();
  };
  const timer = setTimeout(() => {
    finish(() => {
      log.error('snmp', label + ' timed out with no SNMP reply', {});
      if (!res.headersSent) res.status(504).json({ error: 'The switch did not reply in time.' });
    });
  }, ms || 12000);
  return {
    ok: (payload) => finish(() => { if (!res.headersSent) res.json(payload); }),
    fail: (status, message) => finish(() => { if (!res.headersSent) res.status(status).json({ error: message }); })
  };
}

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

// The ONE conversion from the JSON varbind shape the UI and the plan builders
// use ({ oid, type, value | valueHex }) to what net-snmp's session.set takes.
// Every SET path goes through it: /api/snmp/set, snmp-config's bundle, and the
// OPC / AAA / flash step runners. Numeric types become numbers; an OctetString
// may arrive as a hex string (VLAN bitmaps and other binary values cannot
// travel through JSON as raw bytes) and becomes a Buffer; anything else, a
// Buffer included, passes through unchanged. Throws on an unknown type or an
// odd-length hex string rather than sending a corrupted value.
function mapSetVarbinds(varbinds) {
  return varbinds.map((vb) => {
    const type = snmp.ObjectType[vb.type];
    if (type === undefined) throw new Error(`Unknown SNMP type: ${vb.type}`);
    let value;
    if (type === snmp.ObjectType.Integer || type === snmp.ObjectType.Counter
      || type === snmp.ObjectType.Gauge || type === snmp.ObjectType.TimeTicks) {
      value = Number(vb.value);
    } else if (type === snmp.ObjectType.OctetString && vb.valueHex !== undefined) {
      // Whitespace is tolerated so "00 60 .." pastes work.
      const hex = String(vb.valueHex).replace(/[^0-9a-fA-F]/g, '');
      if (hex.length % 2 !== 0) throw new Error('valueHex must have an even number of hex digits');
      value = Buffer.from(hex, 'hex');
    } else {
      value = vb.value;
    }
    return { oid: mib.resolveOid(vb.oid), type, value };
  });
}

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


// -----------------------------------------------------------------
// SSH (WebSocket)
// -----------------------------------------------------------------

// Lets the UI report how many OIDs are loaded, and surfaces a clear error
// if the generated MIB database is missing or corrupt.
// -----------------------------------------------------------------
// SNMP configuration (recipients, communities, VACM groups, users,
// system identity) — the write side and its config-specific reads.
// snmp-config.js owns the logic; here we just build the session and
// hand it the raw get/walk/set primitives it expects.
// -----------------------------------------------------------------

// Raw SNMP primitives for snmp-config: values stay as net-snmp gives them
// (Buffer / number / OID string), which is what the module decodes.
function snmpConfigBundle(session) {
  return {
    get: (oids) => new Promise((resolve, reject) => {
      session.get(resolveOids(oids), (error, vbs) => {
        if (error) return reject(error);
        resolve(vbs.map((vb) => snmp.isVarbindError(vb)
          ? { oid: vb.oid, value: null, error: snmp.varbindError(vb) }
          : { oid: vb.oid, value: vb.value, type: vb.type }));
      });
    }),
    walk: (base) => boundedWalkRaw(session, mib.resolveOid(base)),
    set: (varbinds) => new Promise((resolve) => {
      let mapped;
      try {
        mapped = mapSetVarbinds(varbinds);
      } catch (e) { return resolve(e.message); }
      session.set(mapped, (error, resultVarbinds) => {
        if (error) return resolve(error.message);
        for (const vb of resultVarbinds || []) {
          if (snmp.isVarbindError(vb)) return resolve(snmp.varbindError(vb));
        }
        resolve(null);
      });
    })
  };
}

// A walk that returns RAW varbinds (oid + untouched net-snmp value + type),
// which snmp-config decodes itself: the shared boundedWalk in raw mode, with
// the tighter limits the config tables have always used. GETBULK for v2c/v3
// keeps a small switch (C1300) stable: a config table like snmpTargetAddrTable
// is ~120 varbinds, ~12 frames instead of ~120. A table the model doesn't
// implement (or any error) resolves to the rows read so far rather than
// rejecting, so one hidden table never blocks the rest.
function boundedWalkRaw(session, baseOid) {
  return new Promise((resolve) => {
    boundedWalk(session, baseOid, { raw: true, maxRows: 4000, maxOidLength: 64, maxRepetitions: 10 },
      (error, rows) => resolve(rows));
  });
}

// snmp-config dispatch. One route; the action decides read vs plan vs apply.
app.post('/api/snmp-config/:action', async (req, res) => {
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
      case 'status': result = await snmpConfig.systemStatus(S); break;
      case 'access': result = await snmpConfig.accessCheck(S, meta); break;
      case 'recipients': result = await snmpConfig.listRecipients(S, { all: body.all }); break;
      case 'communities': result = await snmpConfig.listCommunities(S); break;
      case 'groups': result = await snmpConfig.listGroups(S); break;
      case 'users': result = await snmpConfig.listUsers(S); break;
      case 'views': result = await snmpConfig.listViewNames(S); break;
      case 'diagnostics': result = await snmpConfig.diagnostics(S, { ...body.opts, meta }); break;
      case 'target-check': result = await snmpConfig.checkTargetRows(S); break;
      case 'target-row-delete-apply': {
        const oid = String((body.key || {}).destroyOid || '');
        if (!/^1\.3\.6\.1\.6\.3\.12\.1\.2\.1\.9\./.test(oid)) throw new Error('Invalid target-row reference.');
        const err = await S.set([{ oid, type: 'Integer', value: 6 }]);
        result = { applied: { ok: err == null, log: [{ title: 'Remove malformed target row', ok: err == null, detail: err == null ? 'destroyed' : err }] } };
        break;
      }

      case 'status-set-preview': result = { plan: snmpConfig.planSetSystem(body.cfg) }; break;
      case 'recipient-add-preview': result = { plan: await snmpConfig.planAddRecipient(S, body.cfg) }; break;
      case 'recipient-delete-preview': result = { plan: await snmpConfig.planDeleteRecipient(S, body.key) }; break;
      case 'community-add-preview': result = { plan: await snmpConfig.planAddCommunity(S, body.cfg) }; break;
      case 'community-delete-preview': result = { plan: await snmpConfig.planDeleteCommunity(S, body.key) }; break;
      case 'group-add-preview': result = { plan: await snmpConfig.planAddGroup(S, body.cfg) }; break;
      case 'group-modify-preview': result = { plan: await snmpConfig.planModifyGroup(S, body.cfg) }; break;
      case 'user-delete-preview': result = { plan: await snmpConfig.planDeleteUser(S, body.key) }; break;

      case 'status-set-apply': result = { applied: await snmpConfig.applyPlan(S, snmpConfig.planSetSystem(body.cfg)) }; break;
      case 'recipient-add-apply': result = { applied: await snmpConfig.applyPlan(S, await snmpConfig.planAddRecipient(S, body.cfg)) }; break;
      case 'recipient-delete-apply': result = { applied: await snmpConfig.applyPlan(S, await snmpConfig.planDeleteRecipient(S, body.key)) }; break;
      case 'community-modify-preview': result = { plan: await snmpConfig.planModifyCommunity(S, body.cfg) }; break;
      case 'community-modify-apply': result = { applied: await snmpConfig.applyPlan(S, await snmpConfig.planModifyCommunity(S, body.cfg)) }; break;
      case 'community-add-apply': result = { applied: await snmpConfig.applyPlan(S, await snmpConfig.planAddCommunity(S, body.cfg)) }; break;
      case 'community-delete-apply': result = { applied: await snmpConfig.applyPlan(S, await snmpConfig.planDeleteCommunity(S, body.key)) }; break;
      case 'group-add-apply': result = { applied: await snmpConfig.applyPlan(S, await snmpConfig.planAddGroup(S, body.cfg)) }; break;
      case 'group-modify-apply': result = { applied: await snmpConfig.applyPlan(S, await snmpConfig.planModifyGroup(S, body.cfg)) }; break;
      case 'user-delete-apply': result = { applied: await snmpConfig.applyPlan(S, await snmpConfig.planDeleteUser(S, body.key)) }; break;

      default: session.close(); return res.status(404).json({ error: 'Unknown action: ' + action });
    }
    session.close();
    res.json({ ok: true, ...result });
  } catch (e) {
    session.close();
    log.error('snmp-config', action + ' failed', { message: e.message });
    res.status(400).json({ ok: false, error: e.message });
  }
});

app.get('/api/mib/stats', (req, res) => {
  res.json(mib.stats());
});

// -----------------------------------------------------------------
// Configuration retrieval
// -----------------------------------------------------------------
// No MIB object returns configuration text, so this drives rlCopyTable to
// have the switch upload the file to the TFTP receiver embedded in this
// app. Needs SNMP *write* access, and the switch must be able to reach
// this machine on the TFTP port.

app.get('/api/snmp/v3-options', (req, res) => {
  res.json({ auth: v3crypto.AUTH_CHOICES, priv: v3crypto.PRIV_CHOICES });
});

app.get('/api/tftp/status', (req, res) => res.json(tftp.status()));

app.post('/api/config/fetch', async (req, res) => {
  const { target, kind, tftpPort } = req.body || {};
  if (!target || !target.host) {
    return res.status(400).json({ error: 'target.host is required.' });
  }
  try {
    const result = await configFetch.fetchConfig(() => buildSnmpSession(target), {
      host: target.host, kind: kind || 'running',
      // TFTP is port 69 by convention and the switch will not be told
      // otherwise; TFTP_PORT exists for the case where binding a
      // privileged port is not possible (a non-root Linux run).
      tftpPort: tftpPort || Number(process.env.TFTP_PORT) || undefined
    });
    res.json(result);
  } catch (e) {
    log.error('config', 'Configuration fetch failed', {
      target: redactTarget(target), kind, message: e.message
    });
    res.status(502).json({ error: e.message });
  }
});

// Writes to the switch: copies one config over another, which is how
// "sync" saves the running configuration to startup.
app.post('/api/config/sync', async (req, res) => {
  const { target, from, to } = req.body || {};
  if (!target || !target.host) return res.status(400).json({ error: 'target.host is required.' });
  try {
    const result = await configFetch.copyConfig(() => buildSnmpSession(target), {
      host: target.host, from: from || 'running', to: to || 'startup', unit: req.body && req.body.unit,
      waitForFinish: copyFinishedWaiter(target.host)
    });
    res.json(result);
  } catch (e) {
    log.error('config', 'Configuration sync failed', {
      target: redactTarget(target), from, to, message: e.message
    });
    res.status(502).json({ error: e.message });
  }
});

// -----------------------------------------------------------------
// Onboard Packet Capture (OPC)
// -----------------------------------------------------------------

// Map opc plan varbinds ({oid,type,value|valueHex}) to net-snmp varbinds,
// resolving type names and hex octet strings the same way /api/snmp/set does.
function snmpSetPromise(session, varbinds) {
  return new Promise((resolve, reject) => {
    session.set(varbinds, (error, result) => {
      if (error) return reject(error);
      const bad = (result || []).find((vb) => snmp.isVarbindError(vb));
      if (bad) return reject(new Error(snmp.varbindError(bad)));
      resolve(result);
    });
  });
}

// Run a sequence of varbind groups as separate SETs, in order, over one
// session. Returns on the first failure (attributable to its group).
async function runOpcSteps(target, groups) {
  const session = buildSnmpSession(target);
  try {
    for (const g of groups) {
      if (!g.varbinds || !g.varbinds.length) continue;
      await snmpSetPromise(session, mapSetVarbinds(g.varbinds));
    }
  } finally {
    try { session.close(); } catch (e) { /* ignore */ }
  }
}

// Configure (create) the capture point + bind the control plane. Body:
// { target, name, bufferType, bufferSizeMb, filter, aclName, direction,
//   limitDurationSec, limitPackets, limitMaxLen }
app.post('/api/opc/configure', async (req, res) => {
  const b = req.body || {};
  if (!b.target || !b.target.host) return res.status(400).json({ error: 'target.host is required.' });
  if (!b.name) return res.status(400).json({ error: 'A capture name is required.' });
  try {
    const steps = [{ varbinds: opc.planCreateCapture(b) }];
    // For a new capture, bind the control plane. The action row is NOT created
    // here: its columns are written (and the row created implicitly) at export
    // time, which is the form the switch accepts. For a reconfigure the rows
    // already exist, so only the direction is updated.
    if (!b.existing) {
      steps.push({ varbinds: opc.planBindControlPlane(b.name, b.direction || 'both') });
    } else {
      // Only update the direction on the existing control-plane row.
      steps.push({ varbinds: [{ oid: opc.OID.ifDirection + '.' + opc.ifIndex(b.name, opc.CONTROL_PLANE_IFINDEX),
        type: 'Integer', value: opc.DIRECTION[b.direction] || opc.DIRECTION.both }] });
    }
    await runOpcSteps(b.target, steps);
    res.json({ ok: true });
  } catch (e) {
    log.error('opc', 'configure failed', { target: redactTarget(b.target), message: e.message });
    res.status(502).json({ error: e.message });
  }
});

// List existing capture points. Body: { target }
app.post('/api/opc/list', async (req, res) => {
  const b = req.body || {};
  if (!b.target || !b.target.host) return res.status(400).json({ error: 'target.host is required.' });
  const session = buildSnmpSession(b.target);
  try {
    const rows = await boundedWalkPromise(session, opc.WALK.capturePoint, 'getbulk', { maxRows: 2000 });
    // Reduce to {oid, value} using decoded display where it differs.
    const simple = rows.map((vb) => {
      const d = describeVarbind(vb);
      return { oid: vb.oid, value: (d.display !== undefined && d.display !== null && d.display !== String(d.value)) ? d.display : d.value };
    });
    res.json({ ok: true, captures: opc.parseCaptureList(simple) });
  } catch (e) {
    res.status(502).json({ error: e.message });
  } finally {
    try { session.close(); } catch (e) {}
  }
});

// Start / stop / clear. Body: { target, name, action: 'start'|'stop'|'clear' }
// rlOpcAction lives in rlOpcActionTable, and that row must exist before the
// action column can be SET (otherwise the switch returns CommitFailed). The
// action row is NOT created with the capture point — it is created on demand —
// so every start/stop/export first ensures the row exists. Creating a row that
// already exists is refused, which is fine: we ignore that and proceed.
app.post('/api/opc/action', async (req, res) => {
  const b = req.body || {};
  if (!b.target || !b.target.host) return res.status(400).json({ error: 'target.host is required.' });
  if (!b.name || !opc.ACTION[b.action]) return res.status(400).json({ error: 'name and a valid action are required.' });
  try {
    // rlOpcAction is one column whose write creates/uses the action row
    // implicitly, so it is set on its own in a single PDU.
    await runOpcSteps(b.target, [{ varbinds: opc.planAction(b.name, b.action) }]);
    res.json({ ok: true });
  } catch (e) {
    log.error('opc', 'action failed', { target: redactTarget(b.target), action: b.action, message: e.message });
    res.status(502).json({ error: e.message });
  }
});

// Live status of a capture point. Body: { target, name }
app.post('/api/opc/status', async (req, res) => {
  const b = req.body || {};
  if (!b.target || !b.target.host) return res.status(400).json({ error: 'target.host is required.' });
  if (!b.name) return res.status(400).json({ error: 'name is required.' });
  const session = buildSnmpSession(b.target);
  const responder = snmpResponder(res, session, 'opc-status', 10000);
  const so = opc.statusOids(b.name);
  const names = Object.keys(so);
  session.get(names.map((k) => so[k]), (error, varbinds) => {
    if (error) return responder.fail(502, error.message);
    const out = {};
    varbinds.forEach((vb, i) => {
      out[names[i]] = snmp.isVarbindError(vb) ? null : vb.value;
    });
    // Decode state 1=active 2=inactive.
    out.stateText = out.state === 1 ? 'active' : (out.state === 2 ? 'inactive' : null);
    responder.ok(out);
  });
});

// Delete the capture point. Body: { target, name }
app.post('/api/opc/delete', async (req, res) => {
  const b = req.body || {};
  if (!b.target || !b.target.host) return res.status(400).json({ error: 'target.host is required.' });
  if (!b.name) return res.status(400).json({ error: 'name is required.' });
  try {
    // Each destroy is attempted independently: a missing companion row should
    // not block removing the capture point itself.
    const session = buildSnmpSession(b.target);
    for (const vb of opc.planDeleteCapture(b.name)) {
      try { await snmpSetPromise(session, mapSetVarbinds([vb])); } catch (e) { /* ignore */ }
    }
    try { session.close(); } catch (e) {}
    res.json({ ok: true });
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

// Export the capture to a flash .pcap, then copy that flash file to the
// built-in TFTP receiver and stream it back as a download.
// Body: { target, name, tftpPort }
// Read one capture point's state + packet count, for export preconditions.
function readCaptureState(target, name) {
  return new Promise((resolve) => {
    const session = buildSnmpSession(target);
    const so = opc.statusOids(name);
    session.get([so.state, so.packets], (error, varbinds) => {
      try { session.close(); } catch (e) {}
      if (error) return resolve({ error: error.message });
      const state = varbinds[0] && !snmp.isVarbindError(varbinds[0]) ? Number(varbinds[0].value) : null;
      const packets = varbinds[1] && !snmp.isVarbindError(varbinds[1]) ? Number(varbinds[1].value) : null;
      resolve({ state, packets });
    });
  });
}

// Export the capture buffer to a flash .pcap, switch-side only. Two methods:
//   'combined'  : dest + filename + action=export in ONE PDU, no RowStatus.
//                 The switch acks noError and writes a valid pcap, but it
//                 crashes the control plane. Kept only as a comparison.
//   'cw-setup'  : the RFC 2579 createAndWait lifecycle WITHOUT the trigger -
//                 createAndWait, populate (dest+filename), activate - reading
//                 the row back after each step so its state is reported. Leaves
//                 an active, managed action row ready to trigger.
//   'cw-trigger': set action=export on the active row, then destroy it (clean
//                 teardown). Run after a successful 'cw-setup'.
// All require confirm:true. cw-setup/combined enforce the capture is present,
// stopped, and non-empty; cw-trigger acts on the row left by cw-setup.
// Body: { target, name, confirm, method, flashFileName? }
app.post('/api/opc/export-to-flash', async (req, res) => {
  const b = req.body || {};
  if (!b.target || !b.target.host) return res.status(400).json({ error: 'target.host is required.' });
  if (!b.name) return res.status(400).json({ error: 'name is required.' });
  if (!b.confirm) return res.status(400).json({ error: 'Export is not confirmed.' });
  const method = b.method || 'combined';

  if (method !== 'cw-trigger') {
    const st = await readCaptureState(b.target, b.name);
    if (st.error) return res.status(502).json({ error: 'Could not read capture state: ' + st.error });
    if (st.state === null) return res.status(409).json({ error: 'Capture "' + b.name + '" does not exist on the switch.' });
    if (st.state === 1) return res.status(409).json({ error: 'Capture is still running. Stop it before exporting.' });
    if (!st.packets || st.packets <= 0) {
      return res.status(409).json({ error: 'Capture buffer is empty (0 packets). Exporting an empty capture previously crashed the switch, so it is blocked. Start the capture, collect packets, stop it, then export.' });
    }
    req._packets = st.packets;
  }

  const flashName = (method === 'cw-trigger' && b.flashFileName)
    ? b.flashFileName
    : ('cap_' + b.name + '_' + Date.now().toString(36) + '.pcap').replace(/[^A-Za-z0-9._-]/g, '_');

  // Read the action row's columns and return a compact state object.
  const readActionRow = async () => {
    const o = opc.actionRowOids(b.name);
    const session = buildSnmpSession(b.target);
    try {
      const vbs = await snmpGetPromise(session, [o.dest, o.fileName, o.rowStatus]);
      const v = (x) => (x && !x.error) ? x.value : null;
      return { dest: v(vbs[0]), fileName: v(vbs[1]), rowStatus: v(vbs[2]) };
    } catch (e) { return { error: e.message }; }
    finally { try { session.close(); } catch (x) {} }
  };

  try {
    if (method === 'combined') {
      await runOpcSteps(b.target, [{ varbinds: opc.planExport(b.name, flashName) }]);
      return res.json({ ok: true, flashFileName: flashName, method, packets: req._packets });
    }
    if (method === 'order-action-first') {
      await runOpcSteps(b.target, [{ varbinds: opc.planExportActionFirst(b.name, flashName) }]);
      return res.json({ ok: true, flashFileName: flashName, method, packets: req._packets });
    }
    if (method === 'order-filename-first') {
      await runOpcSteps(b.target, [{ varbinds: opc.planExportFilenameFirst(b.name, flashName) }]);
      return res.json({ ok: true, flashFileName: flashName, method, packets: req._packets });
    }

    if (method === 'create-go-name' || method === 'create-wait-name') {
      // Create the action row WITH the index/name column explicitly included.
      // No export is triggered - this only attempts to make the row exist and
      // reads it back, so it is safe. If the row materialises (readback shows
      // values, not null), the action table CAN be managed after all.
      const steps = [];
      const plan = method === 'create-go-name'
        ? opc.planActionCreateGoWithName(b.name, flashName)
        : opc.planActionCreateWaitWithName(b.name);
      try { await runOpcSteps(b.target, [{ varbinds: plan }]); steps.push(method + ': ok'); }
      catch (e) { steps.push(method + ': ' + e.message); }
      const after = await readActionRow();
      steps.push('  row after create: ' + JSON.stringify(after));
      const exists = after && !after.error &&
        (after.rowStatus !== null || after.dest !== null || after.fileName !== null);
      steps.push(exists ? '  ROW EXISTS - the action table can be managed!' : '  row still absent (null) - create was not honoured.');
      return res.json({ ok: true, flashFileName: flashName, method, setupOnly: true, rowExists: exists, packets: req._packets, steps });
    }

    if (method === 'cw-setup') {
      const steps = [];
      // Step 1: createAndWait.
      try { await runOpcSteps(b.target, [{ varbinds: opc.planCwCreate(b.name) }]); steps.push('createAndWait: ok'); }
      catch (e) { steps.push('createAndWait: ' + e.message); }
      let after1 = await readActionRow();
      steps.push('  row after create: ' + JSON.stringify(after1));
      // Step 2: populate dest + filename.
      try { await runOpcSteps(b.target, [{ varbinds: opc.planCwPopulate(b.name, flashName) }]); steps.push('populate dest+filename: ok'); }
      catch (e) { steps.push('populate dest+filename: ' + e.message); }
      let after2 = await readActionRow();
      steps.push('  row after populate: ' + JSON.stringify(after2));
      // Step 3: activate.
      try { await runOpcSteps(b.target, [{ varbinds: opc.planCwActivate(b.name) }]); steps.push('activate: ok'); }
      catch (e) { steps.push('activate: ' + e.message); }
      let after3 = await readActionRow();
      steps.push('  row after activate: ' + JSON.stringify(after3));
      log.info('opc', 'cw-setup', { host: b.target.host, name: b.name, flashName });
      return res.json({ ok: true, flashFileName: flashName, method, setupOnly: true, packets: req._packets, steps });
    }

    if (method === 'cw-trigger') {
      const steps = [];
      try { await runOpcSteps(b.target, [{ varbinds: opc.planCwTrigger(b.name) }]); steps.push('trigger export: ok'); }
      catch (e) { steps.push('trigger export: ' + e.message); }
      // Best-effort teardown.
      try { await runOpcSteps(b.target, [{ varbinds: opc.planCwDestroy(b.name) }]); steps.push('destroy row: ok'); }
      catch (e) { steps.push('destroy row: ' + e.message); }
      return res.json({ ok: true, flashFileName: flashName, method, packets: req._packets, steps });
    }

    if (method === 'two-pdu') {
      // The key experiment. The combined (same-PDU) export crashes; the action
      // alone does not. This separates them: PDU1 sets dest+filename, PDU2 sets
      // the action alone. The readback after PDU1 shows whether the dest/
      // filename persisted despite an expected InconsistentValue - which is what
      // determines whether a separated export can work at all.
      const steps = [];
      // PDU1: dest + filename, no action, no RowStatus.
      try { await runOpcSteps(b.target, [{ varbinds: opc.planCwPopulate(b.name, flashName) }]); steps.push('PDU1 set dest+filename: ok'); }
      catch (e) { steps.push('PDU1 set dest+filename: ' + e.message); }
      const afterSet = await readActionRow();
      steps.push('  row after PDU1: ' + JSON.stringify(afterSet));
      const persisted = afterSet && !afterSet.error &&
        (afterSet.fileName !== null && afterSet.fileName !== undefined && String(afterSet.fileName).length > 0);
      if (!persisted) {
        steps.push('  dest/filename did NOT persist -> triggering the action now would just CommitFailed (safe but useless). Not triggering.');
        return res.json({ ok: true, flashFileName: flashName, method, packets: req._packets, steps, persisted: false });
      }
      steps.push('  dest/filename PERSISTED -> triggering action in a SEPARATE PDU.');
      // Small settle before the separate trigger.
      await new Promise((r) => setTimeout(r, 600));
      // PDU2: action alone.
      try { await runOpcSteps(b.target, [{ varbinds: opc.planCwTrigger(b.name) }]); steps.push('PDU2 action=export: ok'); }
      catch (e) { steps.push('PDU2 action=export: ' + e.message); }
      const afterTrigger = await readActionRow();
      steps.push('  row after PDU2: ' + JSON.stringify(afterTrigger));
      return res.json({ ok: true, flashFileName: flashName, method, packets: req._packets, steps, persisted: true });
    }

    return res.status(400).json({ error: 'Unknown export method: ' + method });
  } catch (e) {
    log.error('opc', 'export-to-flash failed', { target: redactTarget(b.target), method, message: e.message });
    res.status(502).json({ error: e.message, flashFileName: flashName });
  }
});

// STEP 2: Copy a flash .pcap to this app over TFTP and return it. Separate so
// it only runs after a successful flash export, and never auto-chains into the
// step that crashed. Body: { target, flashFileName, tftpPort }
app.post('/api/opc/fetch-flash', async (req, res) => {
  const b = req.body || {};
  if (!b.target || !b.target.host) return res.status(400).json({ error: 'target.host is required.' });
  if (!b.flashFileName) return res.status(400).json({ error: 'flashFileName is required.' });
  try {
    const result = await configFetch.fetchPcap(() => buildSnmpSession(b.target), {
      host: b.target.host, flashFileName: b.flashFileName,
      tftpPort: b.tftpPort || Number(process.env.TFTP_PORT) || undefined
    });
    res.json({ ok: true, flashFileName: b.flashFileName, bytes: result.bytes, pcapBase64: result.buf.toString('base64') });
  } catch (e) {
    log.error('opc', 'fetch-flash failed', { target: redactTarget(b.target), message: e.message });
    res.status(502).json({ error: e.message });
  }
});

// Diagnostic: walk every OPC table and the copy table, returning the raw
// varbinds as a downloadable blob (the client saves it; nothing is shown in
// the browser). Body: { target }
app.post('/api/opc/diag', async (req, res) => {
  const b = req.body || {};
  if (!b.target || !b.target.host) return res.status(400).json({ error: 'target.host is required.' });
  const session = buildSnmpSession(b.target);
  const roots = [
    ['rlOpcCapturePointTable', opc.WALK.capturePoint],
    ['rlOpcInterfaceTable', opc.WALK.iface],
    ['rlOpcActionTable', opc.WALK.action],
    ['rlOpcOperState', opc.WALK.operState],
    ['rlCopyTable', '1.3.6.1.4.1.9.6.1.101.87.2.1']
  ];
  const lines = ['OPC diagnostic  .  ' + b.target.host + '  .  ' + new Date().toISOString(), ''];
  try {
    for (const [label, root] of roots) {
      lines.push('=== ' + label + '  [' + root + '] ===');
      try {
        const rows = await boundedWalkPromise(session, root, 'getbulk', { maxRows: 2000 });
        if (!rows.length) lines.push('  (no rows)');
        for (const vb of rows) {
          const d = describeVarbind(vb);
          const val = d.display !== undefined && d.display !== null && d.display !== String(d.value)
            ? (d.value + '  (' + d.display + ')') : d.value;
          lines.push('  ' + vb.oid + ' = ' + val);
        }
      } catch (e) {
        lines.push('  (walk failed: ' + e.message + ')');
      }
      lines.push('');
    }
  } finally {
    try { session.close(); } catch (e) {}
  }
  res.json({ ok: true, text: lines.join('\n') });
});

// -----------------------------------------------------------------
// Flash file system (CISCOSB-FILE-MIB, rlFileTable = ...101.96.2)
// -----------------------------------------------------------------

const FILE_T = '1.3.6.1.4.1.9.6.1.101.96.2.1';   // rlFileEntry
const FILE_COL = { name: 1, permission: 2, size: 3, date: 4, time: 5, rowStatus: 6, flashSize: 7, fullName: 8 };
const FILE_FLASH_TOTAL = '1.3.6.1.4.1.9.6.1.101.96.4.0';
const FILE_FLASH_FREE = '1.3.6.1.4.1.9.6.1.101.96.5.0';

// The table is indexed by IMPLIED rlFileName: the raw filename bytes, no length
// prefix. Decode the tail of an OID after the column number back to a string.
function decodeImpliedName(tailParts) {
  return tailParts.map((n) => String.fromCharCode(Number(n))).join('');
}

// List flash files. Body: { target }
// -----------------------------------------------------------------
// AAA servers (RADIUS / TACACS+): add, edit, delete via RowStatus
// -----------------------------------------------------------------

// Run a set of varbind groups as one SET each. Returns on first failure.
async function runAaaSteps(target, groups) {
  const session = buildSnmpSession(target);
  try {
    for (const g of groups) {
      if (!g || !g.length) continue;
      await snmpSetPromise(session, mapSetVarbinds(g));   // the shared SET type-mapping
    }
  } finally {
    try { session.close(); } catch (e) { /* ignore */ }
  }
}

// Warn (not block) when a shared key would travel over a session weaker than
// SNMPv3 authPriv. The caller decides whether to proceed.
function keyTransportWarning(target, cfg) {
  const hasKey = cfg && !cfg.useGlobalKey && cfg.key !== undefined && cfg.key !== null && cfg.key !== '';
  if (!hasKey) return null;
  // Judged from what the session will actually negotiate, not the saved
  // `level` label, which can say authPriv while privacy is set to None.
  let isV3Priv = false;
  try { isV3Priv = String(target.version) === '3' && !!target.v3 && v3SecurityOf(target.v3).level === 'authPriv'; }
  catch (e) { isV3Priv = false; }   // an unsupported method: the session build reports it
  return isV3Priv ? null : 'The shared key will be sent in cleartext because this session is not SNMPv3 with privacy (authPriv). Anyone capturing the traffic could read it.';
}

// RADIUS add/edit. Body: { target, ...cfg, edit?, confirm? }
app.post('/api/aaa/radius', async (req, res) => {
  const b = req.body || {};
  if (!b.target || !b.target.host) return res.status(400).json({ error: 'target.host is required.' });
  if (!b.address || !aaa.ipv4Octets(b.address)) return res.status(400).json({ error: 'A valid IPv4 server address is required.' });
  const warning = keyTransportWarning(b.target, b);
  if (warning && !b.confirm) return res.status(409).json({ warning });   // caller must confirm to proceed
  try {
    const plan = aaa.planRadius(b);
    await runAaaSteps(b.target, [plan.varbinds]);
    log.info('aaa', 'RADIUS server ' + (b.edit ? 'edited' : 'added'), { host: b.target.host, address: b.address });
    res.json({ ok: true, warning });
  } catch (e) {
    log.error('aaa', 'RADIUS write failed', { target: redactTarget(b.target), message: e.message });
    res.status(502).json({ error: e.message });
  }
});

// RADIUS delete. Body: { target, address, authPort, acctPort }
app.post('/api/aaa/radius/delete', async (req, res) => {
  const b = req.body || {};
  if (!b.target || !b.target.host) return res.status(400).json({ error: 'target.host is required.' });
  if (!b.address) return res.status(400).json({ error: 'address is required.' });
  try {
    await runAaaSteps(b.target, [aaa.planRadiusDelete(b.address, b.authPort, b.acctPort)]);
    log.info('aaa', 'RADIUS server deleted', { host: b.target.host, address: b.address });
    res.json({ ok: true });
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

// TACACS add/edit. Body: { target, ...cfg, edit?, confirm? }
app.post('/api/aaa/tacacs', async (req, res) => {
  const b = req.body || {};
  if (!b.target || !b.target.host) return res.status(400).json({ error: 'target.host is required.' });
  if (!b.address || !aaa.ipv4Octets(b.address)) return res.status(400).json({ error: 'A valid IPv4 server address is required.' });
  const warning = keyTransportWarning(b.target, b);
  if (warning && !b.confirm) return res.status(409).json({ warning });
  try {
    const plan = aaa.planTacacs(b);
    await runAaaSteps(b.target, [plan.varbinds]);
    log.info('aaa', 'TACACS server ' + (b.edit ? 'edited' : 'added'), { host: b.target.host, address: b.address });
    res.json({ ok: true, warning });
  } catch (e) {
    log.error('aaa', 'TACACS write failed', { target: redactTarget(b.target), message: e.message });
    res.status(502).json({ error: e.message });
  }
});

// TACACS delete. Body: { target, address }
app.post('/api/aaa/tacacs/delete', async (req, res) => {
  const b = req.body || {};
  if (!b.target || !b.target.host) return res.status(400).json({ error: 'target.host is required.' });
  if (!b.address) return res.status(400).json({ error: 'address is required.' });
  try {
    await runAaaSteps(b.target, [aaa.planTacacsDelete(b.address)]);
    log.info('aaa', 'TACACS server deleted', { host: b.target.host, address: b.address });
    res.json({ ok: true });
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

app.post('/api/flash/list', async (req, res) => {
  const b = req.body || {};
  if (!b.target || !b.target.host) return res.status(400).json({ error: 'target.host is required.' });
  const session = buildSnmpSession(b.target);
  try {
    const rows = await boundedWalkPromise(session, FILE_T, 'getbulk', { maxRows: 4000 });
    // Pivot by filename (the implied index after the column sub-id).
    const byName = new Map();
    const base = FILE_T + '.';
    for (const vb of rows) {
      const oid = String(vb.oid);
      if (oid.indexOf(base) !== 0) continue;
      const tail = oid.slice(base.length).split('.');
      const col = Number(tail[0]);
      const name = decodeImpliedName(tail.slice(1));
      if (!name) continue;
      if (!byName.has(name)) byName.set(name, { name });
      const d = describeVarbind(vb);
      const val = (d.display !== undefined && d.display !== null && d.display !== String(d.value)) ? d.display : d.value;
      if (col === FILE_COL.size) byName.get(name).size = val;
      else if (col === FILE_COL.date) byName.get(name).date = val;
      else if (col === FILE_COL.time) byName.get(name).time = val;
      else if (col === FILE_COL.flashSize) byName.get(name).flashSize = val;
      else if (col === FILE_COL.fullName) byName.get(name).fullName = val;
      // Permission is handled separately below via a raw GET, because the walk
      // runs values through describeVarbind, which turns a BITS octet into a
      // printable character when the byte happens to be printable ASCII - losing
      // the raw bits. A direct GET preserves the Buffer.
    }
    // Fetch the permission BITS for each file with a RAW get (reading vb.value
    // directly, not through describeVarbind), so the bits survive. FilePermission
    // BITS { read(0), write(1), execute(2), dir(3) } — bit 0 is the MSB of the
    // first octet. Done in batches to keep PDUs small.
    const names = Array.from(byName.keys());
    const rawGet = (oids) => new Promise((resolve) => {
      session.get(oids, (error, vbs) => resolve(error ? [] : vbs));
    });
    for (let i = 0; i < names.length; i += 10) {
      const slice = names.slice(i, i + 10);
      const permOids = slice.map((nm) => FILE_T + '.' + FILE_COL.permission + '.' + Array.from(Buffer.from(nm, 'latin1')).join('.'));
      const vbs = await rawGet(permOids);
      vbs.forEach((vb, k) => {
        const nm = slice[k];
        if (!vb || snmp.isVarbindError(vb)) return;
        const raw = vb.value;
        let b0 = 0;
        if (Buffer.isBuffer(raw)) b0 = raw.length ? raw[0] : 0;
        else if (typeof raw === 'number') b0 = raw;
        // This firmware encodes FilePermission LSB-first (a plain integer),
        // confirmed against the switch: a read+write file reads 0x03. So
        // read=0x01(bit0), write=0x02(bit1), execute=0x04(bit2), dir=0x08(bit3)
        // - NOT the MSB-first order the SMIv2 BITS convention would imply.
        const bitSet = (n) => !!(b0 & (1 << n));
        if (byName.has(nm)) {
          byName.get(nm).writable = bitSet(1);        // write
          byName.get(nm).isDir = bitSet(3);           // dir
          byName.get(nm).permByte = b0;               // shown in UI for verification
        }
      });
    }
    const files = Array.from(byName.values()).sort((a, b2) => String(a.name).localeCompare(String(b2.name)));
    // Flash capacity (best-effort).
    let flash = null;
    try {
      const vbs = await snmpGetPromise(session, [FILE_FLASH_TOTAL, FILE_FLASH_FREE]);
      const num = (x) => (x && !x.error) ? Number(x.value) : null;
      flash = { total: num(vbs[0]), free: num(vbs[1]) };
    } catch (e) { /* capacity is optional */ }
    res.json({ ok: true, files, flash });
  } catch (e) {
    res.status(502).json({ error: e.message });
  } finally {
    try { session.close(); } catch (e) {}
  }
});

// Delete a flash file: rlFileRowStatus = destroy(6), keyed by the implied
// filename. Body: { target, fileName }
app.post('/api/flash/delete', async (req, res) => {
  const b = req.body || {};
  if (!b.target || !b.target.host) return res.status(400).json({ error: 'target.host is required.' });
  if (!b.fileName) return res.status(400).json({ error: 'fileName is required.' });
  // Build the implied index: raw filename bytes, dot-joined.
  const idx = Array.from(Buffer.from(String(b.fileName), 'latin1')).join('.');
  const oid = FILE_T + '.' + FILE_COL.rowStatus + '.' + idx;
  const session = buildSnmpSession(b.target);
  try {
    await snmpSetPromise(session, [{ oid, type: snmp.ObjectType.Integer, value: 6 }]); // destroy
    log.info('flash', 'file deleted', { host: b.target.host, fileName: b.fileName });
    res.json({ ok: true, fileName: b.fileName });
  } catch (e) {
    log.error('flash', 'delete failed', { target: redactTarget(b.target), message: e.message });
    res.status(502).json({ error: e.message });
  } finally {
    try { session.close(); } catch (e) {}
  }
});

// -----------------------------------------------------------------
// TEST (RISK): export a capture to flash via rlCopyTable instead of
// rlOpcAction. This EXECUTES a copy (createAndGo) and may crash the switch -
// it is gated by confirm:true and clearly labelled in the UI. The point is to
// test whether the stable copy engine behaves differently from the OPC action.
// Body: { target, name, confirm }
app.post('/api/copy/capture-to-flash', async (req, res) => {
  const b = req.body || {};
  if (!b.target || !b.target.host) return res.status(400).json({ error: 'target.host is required.' });
  if (!b.name) return res.status(400).json({ error: 'name (capture name) is required.' });
  if (!b.confirm) return res.status(400).json({ error: 'Not confirmed.' });
  try {
    const result = await configFetch.copyCaptureToFlash(() => buildSnmpSession(b.target), {
      host: b.target.host, captureName: b.name,
      // Event-driven completion: await the switch's rlCopyFinished trap rather
      // than guessing with a timer. Polling remains a backstop inside the copy.
      waitForFinish: copyFinishedWaiter(b.target.host)
    });
    res.json(result);
  } catch (e) {
    log.error('opc', 'copy-capture-to-flash failed', { target: redactTarget(b.target), message: e.message });
    res.status(502).json({ error: e.message });
  }
});

/**
 * Reachability probe: one GET of sysUpTime, nothing else.
 *
 * The full health collection is dozens of walks; asking whether the switch
 * is still answering does not need any of that. A single varbind is about
 * as small as SNMP gets, and the uptime it returns doubles as a reboot
 * detector -- an uptime lower than the last one means the switch restarted
 * between polls, which is worth knowing and free to notice.
 */
/**
 * The probe carries a few numbers as well as the uptime, so the dashboard
 * can show how they are *moving* rather than only where they are now.
 * Still one PDU, four varbinds: cheap enough to run every 30 seconds
 * whether or not auto-refresh is on.
 */
const PROBE_OIDS = [
  '1.3.6.1.2.1.1.3.0',                       // sysUpTime
  '1.3.6.1.4.1.9.6.1.101.1.9.0',             // CPU, 5 minute average
  '1.3.6.1.2.1.105.1.3.1.1.4.1',             // PoE watts drawn
  '1.3.6.1.4.1.9.6.1.101.1.13.0',            // running == startup
  '1.3.6.1.4.1.9.6.1.101.203.2.0'            // packets per second to the CPU
];

// A fast, single-PDU reachability + quick-metrics probe (sysUpTime, CPU, PoE,
// config-saved flag, cpu pps). Shared by the HTTP ping and the collector: the
// collector probes BEFORE a full collection, so reachability is decided in one
// PDU and a dead host never incurs a dozens-of-walks collection (budget,
// MODULE-STANDARD §B5a). `collect` returns a resilient partial even when a host
// is unreachable, so this probe - not a collect failure - is the reachability
// signal. Never rejects; resolves { reachable, ... }.
function probeSwitch(target) {
  return new Promise((resolve) => {
    const started = Date.now();
    let session;
    try {
      session = buildSnmpSession(Object.assign({}, target, { timeout: 2500, retries: 1 }));
    } catch (e) {
      return resolve({ reachable: false, error: e.message, ms: 0 });
    }
    session.get(PROBE_OIDS, (error, varbinds) => {
      try { session.close(); } catch (e) {}
      if (error) return resolve({ reachable: false, error: error.message, ms: Date.now() - started });
      const num = (i) => {
        const vb = varbinds && varbinds[i];
        if (!vb || snmp.isVarbindError(vb)) return null;
        const n = Number(vb.value);
        return Number.isFinite(n) ? n : null;
      };
      const uptime = num(0);
      if (uptime === null) {
        return resolve({ reachable: false, error: 'no answer', ms: Date.now() - started });
      }
      resolve({
        reachable: true, ms: Date.now() - started,
        uptime, cpu: num(1), poeW: num(2), configSaved: num(3) === 1, cpuPps: num(4)
      });
    });
  });
}

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
function persistStreamLine(kind, host, obj) {
  const safe = String(host || 'unknown').replace(/[^A-Za-z0-9._-]/g, '_');
  const file = path_.join(__dirname, 'logs', kind, safe + '.log');
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
// Port actions
// -----------------------------------------------------------------
/**
 * The two changes worth making from a dashboard.
 *
 * Power-cycling a PoE port is how a wedged phone, camera or access point
 * gets rebooted -- the commonest physical-layer fix there is, and one that
 * otherwise means finding a CLI or walking to a rack. Admin shut/no-shut
 * is its companion.
 *
 * Both write to the switch, so both are deliberate: the browser confirms
 * first, and each returns the port's state afterwards so the page can show
 * what actually happened rather than assume.
 */
const PETH_ADMIN = '1.3.6.1.2.1.105.1.1.1.3';     // pethPsePortAdminEnable
const IF_ADMIN = '1.3.6.1.2.1.2.2.1.7';           // ifAdminStatus
const IF_OPER = '1.3.6.1.2.1.2.2.1.8';
const CONFIG_EQUAL_OID = '1.3.6.1.4.1.9.6.1.101.1.13.0';

function snmpSet(session, varbinds) {
  return new Promise((resolve, reject) => {
    session.set(varbinds, (error, result) => {
      if (error) return reject(error);
      const bad = (result || []).find((vb) => snmp.isVarbindError(vb));
      if (bad) return reject(new Error(snmp.varbindError(bad)));
      resolve(result);
    });
  });
}

function snmpGetOne(session, oid) {
  return new Promise((resolve, reject) => {
    session.get([oid], (error, vbs) => {
      if (error) return reject(error);
      const vb = vbs && vbs[0];
      if (!vb || snmp.isVarbindError(vb)) return reject(new Error('no value for ' + oid));
      resolve(Number(vb.value));
    });
  });
}

app.post('/api/port/poe', async (req, res) => {
  const { target, group, port, action } = req.body || {};
  if (!target || !target.host || port === undefined) {
    return res.status(400).json({ error: 'target.host and port are required.' });
  }
  const oid = PETH_ADMIN + '.' + (Number(group) || 1) + '.' + Number(port);
  const session = buildSnmpSession(target);
  const set = (v) => snmpSet(session, [{ oid, type: snmp.ObjectType.Integer, value: v }]);
  try {
    log.info('port', 'PoE action', { host: target.host, port, action });

    /**
     * A power cycle is two writes to the port's admin state, so the switch
     * marks its configuration dirty even though the port ends up exactly
     * as it started. There is no "reset power" action to use instead --
     * rlPethPsePortReactivate only recovers ports disabled by a hardware
     * fault -- so the tidying is done here rather than explained to the
     * operator afterwards.
     *
     * Only when the configuration was already saved beforehand. If it was
     * dirty, saving would commit somebody else's pending changes, which is
     * not ours to do.
     */
    const wasSaved = await snmpGetOne(session, CONFIG_EQUAL_OID).then((v) => v === 1).catch(() => null);

    if (action === 'off') {
      await set(2);
    } else if (action === 'on') {
      await set(1);
    } else {
      // Bounce: off, pause long enough for the powered device to notice,
      // then on. Anything shorter and some devices do not reboot at all.
      await set(2);
      await new Promise((r) => setTimeout(r, 3000));
      await set(1);
    }
    const now = await snmpGetOne(session, oid);
    session.close();

    let restored = null;
    if (wasSaved === true) {
      try {
        await configFetch.copyConfig(() => buildSnmpSession(target), {
          host: target.host, from: 'running', to: 'startup', timeoutMs: 20000,
          waitForFinish: copyFinishedWaiter(target.host, 20000)
        });
        restored = true;
        log.info('port', 'Configuration re-saved after the power cycle', { host: target.host, port });
      } catch (e) {
        // Not fatal: the port was still cycled, and the dashboard will
        // simply show unsaved changes, which the comparison explains.
        restored = false;
        log.warn('port', 'Could not re-save after the power cycle', {
          host: target.host, port, message: e.message
        });
      }
    }

    log.info('port', 'PoE action complete', { host: target.host, port, action, adminEnable: now });
    res.json({ port, action, adminEnable: now, enabled: now === 1, configRestored: restored });
  } catch (e) {
    try { session.close(); } catch (x) {}
    log.error('port', 'PoE action failed', { host: target.host, port, action, message: e.message });
    res.status(502).json({ error: e.message });
  }
});

app.post('/api/port/admin', async (req, res) => {
  const { target, ifIndex, action } = req.body || {};
  if (!target || !target.host || ifIndex === undefined) {
    return res.status(400).json({ error: 'target.host and ifIndex are required.' });
  }
  const oid = IF_ADMIN + '.' + Number(ifIndex);
  const session = buildSnmpSession(target);
  try {
    log.info('port', 'Admin state change', { host: target.host, ifIndex, action });
    await snmpSet(session, [{
      oid, type: snmp.ObjectType.Integer, value: action === 'down' ? 2 : 1
    }]);
    // Give the port a moment to settle before reporting where it landed.
    await new Promise((r) => setTimeout(r, 1200));
    const admin = await snmpGetOne(session, oid).catch(() => null);
    const oper = await snmpGetOne(session, IF_OPER + '.' + Number(ifIndex)).catch(() => null);
    session.close();
    log.info('port', 'Admin state changed', { host: target.host, ifIndex, admin, oper });
    res.json({ ifIndex, action, admin, oper });
  } catch (e) {
    try { session.close(); } catch (x) {}
    log.error('port', 'Admin state change failed', {
      host: target.host, ifIndex, action, message: e.message
    });
    res.status(502).json({ error: e.message });
  }
});

// -----------------------------------------------------------------
// Console (serial)
// -----------------------------------------------------------------
app.get('/api/serial/ports', async (req, res) => {
  const info = await serial.listPorts();
  res.json(Object.assign({ baudRates: serial.BAUD_RATES }, info));
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
app.post('/api/syslog/configure', async (req, res) => {
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

app.post('/api/syslog/remove', async (req, res) => {
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

// -----------------------------------------------------------------
// Health page
// -----------------------------------------------------------------
// One request collects the whole health picture so the UI doesn't have to
// orchestrate a dozen round trips. Everything runs over a single SNMP
// session, which is closed when the last walk finishes.

function snmpGetPromise(session, oids) {
  return new Promise((resolve, reject) => {
    session.get(oids, (error, varbinds) => {
      if (error) return reject(error);
      resolve(varbinds.map((vb) =>
        snmp.isVarbindError(vb)
          ? { oid: vb.oid, error: snmp.varbindError(vb), column: mib.describeOid(vb.oid) }
          : describeVarbind(vb)));
    });
  });
}

function boundedWalkPromise(session, oid, mode, opts) {
  return new Promise((resolve, reject) => {
    boundedWalk(session, oid, Object.assign({ mode }, opts || {}), (error, results) => {
      // A table the model doesn't implement is not fatal; return what we
      // have so the rest of the page still renders.
      if (error && !results.length) return reject(error);
      resolve(results);
    });
  });
}

// One previous collection per switch, kept only to turn counters into
// rates. Nothing is persisted: a restart simply means the first collection
// after it has no rate to report, which is honest.
const lastCollection = new Map();

// The ONE collection path. Both the HTTP handler below and the server-side
// collector (collector.js) run collection through here, so there is a single
// place that builds a session, walks the switch, and keeps the per-switch rate
// baseline (governing rule 4 - never a parallel poller). Throws on failure;
// the session is always closed. `previous` turns error counters into a rate:
// "4,812 since boot" says nothing on a switch up 160 days, but "up 43 in the
// last two minutes" is a fault.
async function collectHealthFor(target, opts) {
  const { mode, only } = opts || {};
  const session = buildSnmpSession(target);
  session.on('error', (err) => {
    log.error('health', 'SNMP session error', { message: err.message });
  });
  const key = redactTarget(target).host + ':' + (target.port || 161);
  try {
    const data = await health.collect({
      only,
      previous: lastCollection.get(key),
      get: (oids) => snmpGetPromise(session, resolveOids(oids)),
      walk: (oid, spec) => boundedWalkPromise(session, mib.resolveOid(oid), mode, spec)
    });
    if (!data.partial) {
      lastCollection.set(key, {
        at: Date.now(),
        interfaces: data.interfaces.map((r) => ({
          index: r.index,
          inErrors: r.rlifPresentInErrors ? Number(r.rlifPresentInErrors.value) : null,
          outErrors: r.rlifPresentOutErrors ? Number(r.rlifPresentOutErrors.value) : null
        }))
      });
    }
    return data;
  } finally {
    try { session.close(); } catch (e) { /* already closed */ }
  }
}

app.post('/api/health', async (req, res) => {
  const { target, mode, only } = req.body || {};
  if (!target || !target.host) {
    return res.status(400).json({ error: 'target.host is required.' });
  }
  log.info('health', 'Health collection requested', { target: redactTarget(target) });
  try {
    const data = await collectHealthFor(target, { mode, only });
    log.info('health', data.partial ? 'Partial collection complete' : 'Health collection complete', {
      target: redactTarget(target),
      tables: data.partial ? data.keys.join(',') : undefined,
      // Per-table row counts for partial walks, so a table that comes back empty
      // (e.g. an Owner/companion table a module relies on) is visible in the log.
      counts: data.partial ? data.keys.reduce((acc, k) => {
        if (Array.isArray(data[k])) acc[k] = data[k].length;
        return acc;
      }, {}) : undefined,
      alerts: data.alerts ? data.alerts.length : undefined,
      worst: data.summary ? data.summary.worstSeverity : undefined,
      failed: data.failed.length
    });
    res.json(data);
  } catch (e) {
    log.error('health', 'Health collection failed', { message: e.message });
    // A credential/validation problem is the caller's fault (400); anything
    // else is the switch not answering (502) - same split as before.
    const code = /required|SNMPv3|password|username/i.test(e.message) ? 400 : 502;
    res.status(code).json({ error: e.message });
  }
});

const server = http.createServer(app);
const wss = new WebSocketServer({ server, verifyClient: guard.verifyClient(log) });

// Strongest first; every algorithm the list offered before is still offered.
// SSH picks the client's FIRST choice the switch also supports, so a switch
// that only speaks the old suites still connects, and one that speaks modern
// suites is no longer talked down to SHA-1 / CBC / ssh-rsa. The
// legacy entries stay because older Cisco firmware may offer nothing else
// (modern ssh2 drops them by default).
const LEGACY_ALGORITHMS = {
  kex: [
    'curve25519-sha256', 'curve25519-sha256@libssh.org',
    'ecdh-sha2-nistp256', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp521',
    'diffie-hellman-group-exchange-sha256',
    'diffie-hellman-group14-sha256',
    // legacy
    'diffie-hellman-group14-sha1',
    'diffie-hellman-group-exchange-sha1',
    'diffie-hellman-group1-sha1'
  ],
  cipher: [
    'aes128-gcm@openssh.com', 'aes256-gcm@openssh.com', 'chacha20-poly1305@openssh.com',
    'aes128-ctr', 'aes192-ctr', 'aes256-ctr',
    // legacy
    'aes128-cbc', 'aes192-cbc', 'aes256-cbc',
    '3des-cbc'
  ],
  serverHostKey: [
    'ssh-ed25519', 'ecdsa-sha2-nistp256', 'rsa-sha2-512', 'rsa-sha2-256',
    // legacy
    'ssh-rsa', 'ssh-dss'
  ],
  hmac: [
    'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com',
    'hmac-sha2-256', 'hmac-sha2-512',
    // legacy
    'hmac-sha1', 'hmac-md5'
  ]
};

// Terminal output is full of ANSI/VT100 control sequences -- erase-line,
// cursor movement, colour. The live terminal needs them raw, but captured
// text has to be cleaned before it is parsed or saved, otherwise section
// headers and table columns are polluted with escape codes.
function stripAnsiAndControls(str) {
  if (!str) return str;
  let out = str;
  out = out.replace(/\x1b\[[0-?]*[ -\/]*[@-~]/g, '');
  out = out.replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g, '');
  out = out.replace(/\x1b./g, '').replace(/\x1b/g, '').replace(/\x07/g, '');
  let result = '';
  for (const ch of out) {
    if (ch === '\b') result = result.slice(0, -1);
    else result += ch;
  }
  return result;
}

let connectionCounter = 0;

/**
 * Every live session this app holds, so the switch's own view of who is
 * connected can be shown next to ours. A console session in particular is
 * worth knowing about: it is a physical port, and "why can I not open the
 * console" is usually answered by "because this tab already has it".
 */
const liveSessions = new Map();

app.get('/api/sessions', (req, res) => {
  const now = Date.now();
  res.json({
    sessions: Array.from(liveSessions.values()).map((x) => ({
      id: x.id, kind: x.kind, target: x.target, since: x.since,
      seconds: Math.round((now - x.started) / 1000), capturing: !!x.capturing
    }))
  });
});

wss.on('connection', (ws, req) => {
  const connId = ++connectionCounter;
  const clientIp = req.socket.remoteAddress;
  log.info('ws', `Browser tab connected [#${connId}]`, { ip: clientIp });

  let conn = null;
  let stream = null;
  let console_ = null;   // an attached serial port, when this is a console session
  let targetHost = null;
  let endedNotified = false;
  let capture = null;   // active `show tech-support` collection, if any

  const send = (obj) => {
    if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(obj));
  };

  // Sends the "session is over" signal exactly once per SSH attempt,
  // regardless of which event (stream close, conn error, conn end)
  // triggers it first. The frontend uses this to reset the
  // Connect/Disconnect state no matter how the session ended.
  function notifyEnded(message) {
    liveSessions.delete(connId);
    if (endedNotified) return;
    endedNotified = true;
    send({ type: 'ended', message });
    // The browser opens a fresh WebSocket for each new connect
    // attempt in a given tab, so it's safe -- and tidier -- to close
    // this one now.
    setImmediate(() => {
      try { ws.close(); } catch (e) { /* already closed */ }
    });
  }

  // A device prompt at the very end of the output, e.g. "core-350#" or
  // "core-350(config)#". Seeing it is the signal the command has finished,
  // but only once the stream has also gone quiet -- show tech-support
  // prints intermediate prompts inside its own output.
  const PROMPT_AT_END = /(?:^|\n)\s*\S[\w.\-]*(?:\([^)]*\))?\s*[#>]\s*$/;

  /**
   * Write to whichever transport this tab is using. A console session runs
   * the same commands as an SSH one -- the switch does not care which
   * cable the characters arrive on -- so everything above this stays
   * transport-agnostic.
   */
  /**
   * A terminal sends DEL (0x7f) for Backspace. An SSH shell has a line
   * discipline that understands that; a raw console line does not, and
   * the Catalyst CLI erases on BS (0x08, Ctrl-H) instead -- so on a
   * console the key appeared to do nothing. Cisco accepts both, so
   * translating one way is safe and fixes the case that was broken.
   */
  function forConsole(data) {
    return String(data).replace(/\x7f/g, '\b');
  }

  function writeToSession(text) {
    if (console_) { console_.write(text); return true; }
    if (stream && stream.writable) { stream.write(text); return true; }
    return false;
  }

  const sessionOpen = () => !!(console_ || stream);

  function feedCapture(text) {
    if (!capture) return;
    capture.buffer += text;
    capture.lastData = Date.now();
    clearTimeout(capture.idleTimer);
    capture.idleTimer = setTimeout(() => {
      if (!capture) return;
      const tail = stripAnsiAndControls(capture.buffer).slice(-400);
      // Quiet plus a prompt means done. Quiet without a prompt is treated
      // as done too, but flagged, so a stalled capture still returns data
      // instead of hanging until the hard limit.
      capture.finish(PROMPT_AT_END.test(tail) ? 'prompt returned' : 'output went idle');
    }, capture.idleMs);
  }

  /**
   * End the session the way a person would: send "exit" so the switch
   * closes its own side and logs a clean logout, then give it a moment
   * before dropping the transport. Killing the socket outright leaves the
   * switch with a dangling VTY line until its timeout expires.
   */
  /**
   * A session left untouched is a VTY line held open on the switch for no
   * reason, and on a console it is a serial port nobody else can use. Five
   * minutes of no input closes it the same way a person would.
   *
   * A running capture counts as activity: show tech-support prints for
   * minutes with nobody typing, and killing that would be perverse.
   */
  const IDLE_MS = Number(process.env.SESSION_IDLE_MS) || 5 * 60 * 1000;
  let idleTimer = null;
  function resetIdle() {
    if (idleTimer) clearTimeout(idleTimer);
    if (!conn && !console_) return;
    idleTimer = setTimeout(() => {
      if (capture) { resetIdle(); return; }        // still working
      log.info('ws', `Session idle, closing [#${connId}]`, {
        host: targetHost,
        idle: IDLE_MS >= 60000 ? Math.round(IDLE_MS / 60000) + ' min' : Math.round(IDLE_MS / 1000) + ' s'
      });
      send({ type: 'status', message: 'closing after 5 minutes with no activity' });
      if (console_) {
        console_.close();
        console_ = null;
        send({ type: 'ended', message: 'Console closed after 5 minutes idle.' });
      } else {
        closeGracefully('Session closed after 5 minutes idle.');
      }
    }, IDLE_MS);
  }
  function stopIdle() { if (idleTimer) { clearTimeout(idleTimer); idleTimer = null; } }

  let closing = false;
  function closeGracefully(reason) {
    if (closing) { return; }
    closing = true;
    if (!conn) { notifyEnded(reason || 'Disconnected.'); return; }
    try {
      if (stream && stream.writable) stream.write('exit\n');
    } catch (e) { /* stream already gone */ }
    setTimeout(() => {
      try { if (stream) stream.end(); } catch (e) {}
      try { conn.end(); } catch (e) {}
      // Belt and braces: if the switch does not close, drop it.
      setTimeout(() => { try { conn.destroy(); } catch (e) {} }, 2000);
    }, 400);
  }

  ws.on('message', async (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw);
    } catch (err) {
      log.error('ws', `Malformed message from browser [#${connId}]`, { error: err.message });
      return;
    }

    switch (msg.type) {
      case 'connect': {
        const { host, port, username, password, cols, rows } = msg;
        targetHost = host;
        endedNotified = false;

        if (!host || !username || !password) {
          const errMsg = 'Host, username, and password are required.';
          log.warn('ssh', `Rejected connect attempt [#${connId}]: missing fields`, { host, username });
          send({ type: 'error', message: errMsg });
          notifyEnded('Connection rejected: missing fields.');
          return;
        }

        log.info('ssh', `Connect attempt [#${connId}]`, { host, port: port || 22, username });

        conn = new Client();

        conn.on('ready', () => {
          log.info('ssh', `SSH session established [#${connId}]`, { host });
          send({ type: 'status', message: `Connected to ${host}. Starting shell...` });

          conn.shell({ term: 'xterm-256color', cols: cols || 100, rows: rows || 30 }, (err, s) => {
            if (err) {
              log.error('ssh', `Shell open failed [#${connId}]`, { host, error: err.message });
              send({ type: 'error', message: 'Shell error: ' + err.message });
              notifyEnded('Shell could not be opened.');
              return;
            }
            stream = s;
            send({ type: 'ready', message: 'Shell ready.' });
            liveSessions.set(connId, {
              id: connId, kind: 'ssh', target: targetHost,
              since: new Date().toISOString(), started: Date.now()
            });
            resetIdle();

            stream.on('data', (chunk) => {
              const text = chunk.toString('utf8');
              send({ type: 'data', data: text });
              feedCapture(text);
            });
            stream.stderr.on('data', (chunk) => {
              const text = chunk.toString('utf8');
              send({ type: 'data', data: text });
              feedCapture(text);
            });
            stream.on('close', () => {
              // This fires when the remote side closes the channel --
              // e.g. the user typed "exit" at the switch prompt.
              log.info('ssh', `Shell closed by remote host [#${connId}]`, { host });
              notifyEnded('Session closed by remote host.');
              conn.end();
            });
          });
        });

        conn.on('error', (err) => {
          log.error('ssh', `SSH error [#${connId}]`, { host, error: err.message, level: err.level });
          send({ type: 'error', message: 'SSH error: ' + err.message });
          notifyEnded('Session ended due to an error.');
        });

        conn.on('end', () => {
          log.info('ssh', `SSH connection ended [#${connId}]`, { host });
          notifyEnded('Connection ended.');
        });

        conn.connect({
          host,
          port: port || 22,
          username,
          password,
          readyTimeout: 15000,
          algorithms: LEGACY_ALGORITHMS
        });
        break;
      }

      case 'input': {
        resetIdle();
        if (console_) { console_.write(forConsole(msg.data || '')); break; }
        if (stream) stream.write(msg.data);
        break;
      }

      case 'exec': {
        // Run a long command (show tech-support) in the live shell and
        // capture everything it prints. Output still goes to the terminal
        // so the operator can watch it happen.
        if (!sessionOpen()) {
          send({ type: 'exec-error', message: 'No active session.' });
          break;
        }
        if (capture) {
          send({ type: 'exec-error', message: 'A collection is already running.' });
          break;
        }

        const command = String(msg.command || '').trim();
        if (!command) {
          send({ type: 'exec-error', message: 'No command given.' });
          break;
        }

        const idleMs = Math.max(1000, Number(msg.idleMs) || 4000);
        const maxMs = Math.max(10000, Number(msg.maxMs) || 600000);

        log.info('exec', `Starting capture [#${connId}]`, { host: targetHost, command, idleMs, maxMs });
        if (liveSessions.has(connId)) liveSessions.get(connId).capturing = true;
        resetIdle();

        capture = {
          command,
          // The browser says whether it is watching the terminal. If it is
          // not, the session existed only for this command and should be
          // closed once it finishes rather than left idle on the switch.
          keepOpen: msg.keepOpen === true,
          buffer: '',
          started: Date.now(),
          idleMs,
          lastData: Date.now(),
          idleTimer: null,
          hardTimer: null,
          progressTimer: null,
          // Cisco small-business CLI pages output with "More:" prompts,
          // which would stall a scripted capture. `terminal datadump`
          // turns paging off for the session; if a model doesn't know the
          // command it just prints an error and continues harmlessly.
          finish(reason) {
            if (!capture) return;
            clearTimeout(capture.idleTimer);
            clearTimeout(capture.hardTimer);
            clearInterval(capture.progressTimer);
            const text = stripAnsiAndControls(capture.buffer);
            log.info('exec', `Capture finished [#${connId}]`, {
              host: targetHost, reason, bytes: text.length,
              seconds: Math.round((Date.now() - capture.started) / 1000)
            });
            send({
              type: 'exec-done',
              command: capture.command,
              reason,
              text,
              bytes: text.length,
              seconds: Math.round((Date.now() - capture.started) / 1000)
            });
            const keepOpen = capture.keepOpen;
            capture = null;
            if (liveSessions.has(connId)) liveSessions.get(connId).capturing = false;
            if (keepOpen) return;
            if (console_) {
              // A console is a physical port someone else may want; hand
              // it back rather than sitting on it. There is no session to
              // log out of, so it just closes.
              log.info('serial', `Closing console after capture [#${connId}]`, { port: console_.describe() });
              console_.close();
              console_ = null;
              send({ type: 'ended', message: 'Console closed after the capture finished.' });
              return;
            }
            log.info('ssh', `Closing session after capture [#${connId}]`, { host: targetHost });
            closeGracefully('Session closed after the capture finished.');
          }
        };

        capture.hardTimer = setTimeout(() => {
          if (capture) capture.finish('time limit reached');
        }, maxMs);

        capture.progressTimer = setInterval(() => {
          if (!capture) return;
          send({
            type: 'exec-progress',
            bytes: capture.buffer.length,
            seconds: Math.round((Date.now() - capture.started) / 1000)
          });
        }, 1000);

        send({ type: 'exec-started', command });
        // Paging off first, or the capture stalls on a "More:" prompt.
        // A console needs this at least as much as an SSH session does.
        writeToSession('terminal datadump\n');
        setTimeout(() => {
          if (capture) writeToSession(command + '\n');
        }, 400);
        break;
      }

      /**
       * Push configuration lines into the live session, whether that is
       * SSH or a console. Paced rather than dumped: a switch echoing every
       * character will drop input if it arrives faster than it can parse,
       * and a half-applied configuration is worse than none.
       */
      case 'exec-cancel': {
        if (capture) capture.finish('cancelled');
        break;
      }

      case 'resize': {
        if (stream) stream.setWindow(msg.rows, msg.cols, 0, 0);
        break;
      }

      case 'disconnect': {
        if (console_) {
          log.info('serial', `Console disconnect requested [#${connId}]`, { port: console_.describe() });
          console_.close();
          console_ = null;
          break;
        }
        log.info('ssh', `Disconnect requested by browser [#${connId}]`, { host: targetHost });
        closeGracefully('Disconnected.');
        break;
      }

      // ---- console ----
      case 'serial-connect': {
        resetIdle();
        if (console_ || conn) {
          send({ type: 'ssh-error', message: 'This tab already has a session open.' });
          break;
        }
        try {
          targetHost = 'console ' + (msg.path || '');
          console_ = await serial.attach(ws, msg, {
            onOpen: (info) => {
              send({ type: 'ready', host: info.path + ' @ ' + info.baudRate });
              liveSessions.set(connId, {
                id: connId, kind: 'console', target: info.path + ' @ ' + info.baudRate,
                since: new Date().toISOString(), started: Date.now()
              });
              resetIdle();
            },
            onData: (text) => {
              send({ type: 'data', data: text });
              feedCapture(text);
            },
            onError: (message) => {
              send({ type: 'ssh-error', message });
              if (console_) { console_.close(); console_ = null; }
              // Same reasoning: a console that cannot be opened is not a
              // session, and saying so now saves a confusing reconnect.
              setTimeout(() => { try { ws.close(); } catch (e) {} }, 50);
            },
            /**
             * The port going away ends the session, so the socket goes
             * with it. Leaving the socket open left the browser believing
             * it still had a console: the transport switch showed it as
             * live, and reconnecting did nothing because there appeared to
             * be nothing to reconnect. A closed socket is unambiguous.
             */
            onClose: () => {
              console_ = null;
              send({ type: 'ended', message: 'Console closed.' });
              log.info('serial', `Console ended; closing the session [#${connId}]`, {
                host: targetHost
              });
              setTimeout(() => { try { ws.close(); } catch (e) { /* already gone */ } }, 50);
            }
          });
        } catch (e) {
          log.error('serial', `Console attach failed [#${connId}]`, { message: e.message });
          send({ type: 'ssh-error', message: e.message });
          console_ = null;
        }
        break;
      }

      case 'client-error': {
        // Frontend JS errors reported over the already-open socket.
        log.error('client', msg.message || 'Unspecified client error', msg.meta);
        break;
      }
    }
  });

  ws.on('error', (err) => {
    log.error('ws', `WebSocket error [#${connId}]`, { error: err.message });
  });

  ws.on('close', () => {
    liveSessions.delete(connId);
    log.info('ws', `Browser tab disconnected [#${connId}]`, { host: targetHost });
    if (capture) {
      clearTimeout(capture.idleTimer);
      clearTimeout(capture.hardTimer);
      clearInterval(capture.progressTimer);
      capture = null;
    }
    // A serial port stays open until it is told otherwise, so a closed tab
    // must release it or the next attempt finds the port busy.
    stopIdle();
    if (console_) { console_.close(); console_ = null; }
    if (conn) conn.end();
  });
});

const PORT = process.env.PORT || 3000;
// Start the syslog receiver alongside the web server. A failure to bind
// is logged and surfaced in the UI rather than being fatal: everything
// else in the app still works without it.
syslog.start(Number(process.env.SYSLOG_PORT) || undefined).then((r) => {
  if (!r.listening) {
    log.warn('syslog', 'Syslog receiver did not start', { port: r.port, error: r.error });
  }
});

// A build marker so the running build can be confirmed (the last captures were
// taken against a stale process/cache). Bumped when polling behaviour changes.
const BUILD_MARKER = 'sbs-12 (reopen = display the server\'s last poll, no SNMP: restore/connect now read the cached snapshot instead of forcing a fresh poll. A fresh SNMP poll happens only on the server\'s own schedule, on a manual Refresh, or the one-off auto-poll when a switch has no snapshot yet. Plus sbs-11 C1300X counter fallback.)';

// The collector runs collection THROUGH collectHealthFor (the one path) for
// every saved switch, on a wall-clock cadence, whether or not a browser is
// open. SNMP/vault/TFTP wiring is injected so collector.js stays free of it.
function startCollector() {
  collector.start({
    probe: (target) => probeSwitch(target),
    collect: (target, opts) => collectHealthFor(target, opts),
    loadSwitches: () => {
      const st = vault.load();
      return (st && !st.unreadable && Array.isArray(st.switches)) ? st.switches : [];
    },
    // Gated config content-diff: pull the running-config over the built-in
    // TFTP path (same mechanism as /api/config/fetch) and return its text.
    fetchConfig: async (target) => {
      const r = await configFetch.fetchConfig(() => buildSnmpSession(target), {
        host: target.host, kind: 'running',
        tftpPort: Number(process.env.TFTP_PORT) || undefined
      });
      return r && r.text;
    },
    history, events, log
  });
}

server.listen(PORT, () => {
  log.info('server', `SBS Management Tool running at http://localhost:${PORT}`, { logFile: log.LOG_FILE, build: BUILD_MARKER });
  // Also print plainly so it's obvious in the console which build is live.
  console.log('BUILD:', BUILD_MARKER);
  startCollector();
});

// Persist any pending metric history before the process exits, so a restart
// (or Ctrl-C) never loses the last batch of samples. flush() is synchronous and
// safe to call more than once.
let shuttingDown = false;
function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  try { collector.stop(); } catch (e) { /* best effort */ }
  try { history.flush(); } catch (e) { /* best effort */ }
  log.info('server', 'Shutting down, metric history flushed', { signal });
  // Give the log a tick to write, then exit.
  setTimeout(() => process.exit(0), 50);
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
// A last-chance synchronous flush if the process exits some other way.
process.on('exit', () => { try { history.flush(); } catch (e) {} });
