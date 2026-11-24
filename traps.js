/**
 * SNMP trap and inform receiver.
 *
 * Syslog tells you what a switch decided to write down; traps tell you what
 * it decided to interrupt you about. A link going down, a fan failing, an
 * STP topology change and a failed authentication all arrive here within a
 * second of happening, where the dashboard would not notice until its next
 * poll. Between the two there is very little a switch can do quietly.
 *
 * Held in memory only, per source, like syslog. Traps are a running
 * commentary, not an archive, and an app that writes them to disk becomes
 * something that has to be pruned.
 */

const snmp = require('net-snmp');
const log = require('./logger');

const PER_SOURCE_LIMIT = 1000;
const buffers = new Map();          // source ip -> { messages: [], total }
const listeners = new Set();

let receiver = null;
let state = { listening: false, port: null, error: null };

/**
 * The traps worth naming. A switch sends its important events as generic
 * SNMPv2 notifications whose identity is an OID; showing that raw is
 * useless to a person, so the common ones are translated. Anything not
 * listed still arrives, named by whatever the MIB database resolves.
 */
const WELL_KNOWN = {
  '1.3.6.1.6.3.1.1.5.1': { name: 'coldStart', severity: 'warning' },
  '1.3.6.1.6.3.1.1.5.2': { name: 'warmStart', severity: 'warning' },
  '1.3.6.1.6.3.1.1.5.3': { name: 'linkDown', severity: 'warning' },
  '1.3.6.1.6.3.1.1.5.4': { name: 'linkUp', severity: 'info' },
  '1.3.6.1.6.3.1.1.5.5': { name: 'authenticationFailure', severity: 'warning' },
  '1.3.6.1.6.3.1.1.5.6': { name: 'egpNeighborLoss', severity: 'warning' },
  '1.3.6.1.6.3.1.2.1.1': { name: 'newRoot', severity: 'warning' },
  '1.3.6.1.6.3.1.2.1.2': { name: 'topologyChange', severity: 'warning' },
  '1.3.6.1.2.1.17.0.1': { name: 'newRoot', severity: 'warning' },
  '1.3.6.1.2.1.17.0.2': { name: 'topologyChange', severity: 'warning' }
};

/**
 * Severity from the trap's own name where the MIB gives us one. A switch
 * does not label its notifications, so this reads the name: anything that
 * says a thing failed, went down, or was denied is worth colouring.
 */
function severityFor(oid, name) {
  if (WELL_KNOWN[oid]) return WELL_KNOWN[oid].severity;
  const n = String(name || '');
  if (/fail|error|down|denied|lost|violation|fault|critical|reject/i.test(n)) return 'warning';
  if (/up|restored|added|ok|normal|success/i.test(n)) return 'info';
  return 'info';
}

function bucketFor(source) {
  if (!buffers.has(source)) buffers.set(source, { messages: [], total: 0 });
  return buffers.get(source);
}

/**
 * Turn a raw notification into something a person can read: the trap's
 * identity as a name, and its varbinds resolved to names and values.
 * `describe` is supplied by the server so this module does not have to
 * know about the MIB database.
 */
function shape(pdu, source, describe) {
  const varbinds = [];
  let trapOid = null;

  for (const vb of pdu.varbinds || []) {
    const oid = String(vb.oid);
    // The second varbind of an SNMPv2 trap is the notification's identity.
    if (oid === '1.3.6.1.6.3.1.1.4.1.0') {
      trapOid = String(vb.value);
      continue;
    }
    if (oid === '1.3.6.1.2.1.1.3.0') continue;         // sysUpTime, always present
    // describe may legitimately return nothing -- an OID outside the
    // loaded MIBs, or a value with no enumeration -- so every read of it
    // has to survive that rather than assuming a shape.
    const info = describe ? describe(oid, vb.value) : null;
    const raw = Buffer.isBuffer(vb.value) ? vb.value.toString('latin1') : String(vb.value);
    varbinds.push({
      oid,
      name: (info && info.name) || oid,
      value: info && info.display !== undefined && info.display !== null ? info.display : raw
    });
  }

  // v1 traps carry their identity in the PDU header rather than a varbind.
  if (!trapOid && pdu.enterprise) {
    trapOid = String(pdu.enterprise) + '.' + (pdu.specificTrap || 0);
  }

  const known = WELL_KNOWN[trapOid];
  const resolved = describe && trapOid ? describe(trapOid) : null;
  const name = (known && known.name) || (resolved && resolved.name) || trapOid || 'unknown';

  return {
    at: new Date().toISOString(),
    source,
    oid: trapOid,
    name,
    severity: severityFor(trapOid, name),
    varbinds
  };
}

function record(message) {
  const bucket = bucketFor(message.source);
  bucket.messages.push(message);
  bucket.total++;
  if (bucket.messages.length > PER_SOURCE_LIMIT) {
    bucket.messages.splice(0, bucket.messages.length - PER_SOURCE_LIMIT);
  }
  for (const fn of listeners) {
    try { fn(message); } catch (e) { /* a bad listener must not stop the rest */ }
  }
}

function start(options) {
  const port = Number(options && options.port) || 162;
  const describe = options && options.describe;
  const communities = (options && options.communities) || ['public'];

  if (receiver) return state;

  try {
    receiver = snmp.createReceiver({
      port,
      disableAuthorization: true,   // a trap is unsolicited; we log what arrives
      includeAuthentication: true
    }, (error, data) => {
      if (error) {
        log.error('traps', 'Receiver error', { message: error.message });
        return;
      }
      try {
        const source = (data && data.rinfo && data.rinfo.address) || 'unknown';
        const pdu = data && data.pdu;
        if (!pdu) return;
        const message = shape(pdu, source, describe);
        log.info('traps', 'Trap received', {
          source, trap: message.name, varbinds: message.varbinds.length
        });
        record(message);
      } catch (e) {
        log.error('traps', 'Could not read a trap', { message: e.message });
      }
    });

    // Communities are accepted rather than enforced: authorisation is off,
    // and registering them keeps v2c informs answerable.
    const authorizer = receiver.getAuthorizer();
    for (const community of communities) {
      try { authorizer.addCommunity(community); } catch (e) { /* already there */ }
    }

    state = { listening: true, port, error: null };
    log.info('traps', 'Trap receiver listening', { port });
  } catch (e) {
    state = { listening: false, port, error: e.message };
    log.error('traps', 'Trap receiver could not start', { port, message: e.message });
  }
  return state;
}

function stop() {
  if (receiver) {
    try { receiver.close(); } catch (e) { /* already closed */ }
    receiver = null;
  }
  state = { listening: false, port: state.port, error: null };
}

/** Messages for one source, newest first, optionally filtered. */
function messagesFor(source, opts) {
  const bucket = buffers.get(source);
  if (!bucket) return { messages: [], total: 0, listening: state.listening };
  const search = opts && opts.search ? String(opts.search).toLowerCase() : null;
  let list = bucket.messages;
  if (search) {
    list = list.filter((m) =>
      m.name.toLowerCase().indexOf(search) >= 0 ||
      m.varbinds.some((v) =>
        v.name.toLowerCase().indexOf(search) >= 0 ||
        String(v.value).toLowerCase().indexOf(search) >= 0));
  }
  const limit = Math.max(1, Math.min(1000, (opts && opts.limit) || 200));
  return {
    messages: list.slice(-limit).reverse(),
    total: bucket.total,
    shown: Math.min(list.length, limit),
    listening: state.listening,
    lastAt: bucket.messages.length ? bucket.messages[bucket.messages.length - 1].at : null
  };
}

function subscribe(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

// Resolve when a trap matching { source, name } arrives - event-driven, so an
// operation that emits a completion trap (e.g. rlCopyFinished) is awaited
// directly rather than polled. match(message) can narrow further (e.g. to a
// specific copy index in the varbinds). The timeout is a safety net only: it
// resolves with { timedOut: true } rather than rejecting, so the caller can
// fall back to a state read. Returns { promise, cancel }.
function waitForTrap(opts) {
  opts = opts || {};
  const wantSource = opts.source;
  const wantName = opts.name;
  const wantOid = opts.oid;         // match by trap OID - more robust than the resolved name
  const match = opts.match;
  const timeoutMs = opts.timeoutMs || 180000;
  let unsub = null; let timer = null; let settled = false;
  const promise = new Promise((resolve) => {
    const done = (result) => {
      if (settled) return; settled = true;
      if (unsub) unsub(); if (timer) clearTimeout(timer);
      resolve(result);
    };
    unsub = subscribe((message) => {
      if (wantSource && String(message.source) !== String(wantSource)) return;
      if (wantOid && String(message.oid) !== String(wantOid)) return;
      if (wantName && !wantOid && message.name !== wantName) return;   // name only when no OID given
      if (match && !match(message)) return;
      done({ timedOut: false, message });
    });
    timer = setTimeout(() => done({ timedOut: true }), timeoutMs);
  });
  return { promise, cancel: () => { if (unsub) unsub(); if (timer) clearTimeout(timer); settled = true; } };
}

const status = () => Object.assign({}, state, { sources: Array.from(buffers.keys()) });

module.exports = { start, stop, messagesFor, subscribe, status, record, waitForTrap };
