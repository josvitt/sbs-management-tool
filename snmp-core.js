'use strict';

/**
 * SNMP primitives shared by every route and the collector: building a
 * session, the ONE bounded walk, the ONE SET converter, value formatting,
 * and the response watchdog. Moved verbatim out of server.js.
 */

const snmp = require('net-snmp');
const log = require('./logger');
const mib = require('./mibdb');
const traps = require('./traps');
const v3crypto = require('./snmp-crypto');

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

module.exports = {
  copyFinishedWaiter,
  v3SecurityOf,
  buildSnmpSession,
  resolveOids,
  annotate,
  WALK_DEFAULTS,
  isWithinSubtree,
  oidCompare,
  boundedWalk,
  bufferToBigInt,
  groupDigits,
  formatTimeTicks,
  formatBitsPerSecond,
  formatOctetString,
  formatVarbind,
  describeVarbind,
  redactTarget,
  snmpResponder,
  mapSetVarbinds,
  snmpConfigBundle,
  boundedWalkRaw,
  snmpSetPromise,
  RL_COPY_FINISHED_OID
};
