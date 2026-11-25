'use strict';

/**
 * Recording a real switch, and serving the recording back as a switch.
 *
 * recordingSession(real) wraps a net-snmp session so every varbind the switch
 * answers with is kept (`store`), with a count of each kind of request.
 * fakeSession(recording) is a net-snmp session that answers GET, GETNEXT and
 * GETBULK from such a recording, in the order a real agent would, and
 * refuses every SET. With snmp-core's setSessionFactory, the app's own
 * collection runs against it unchanged (test/live-agent.test.js).
 *
 * In the recording file a Buffer is { "$buf": "<hex>" } and a 64-bit counter
 * is { "$bigint": "<n>" }, as in the other live fixtures.
 */

const snmp = require('net-snmp');
const { oidCompare } = require('../../snmp-core');

const enc = (v) => (Buffer.isBuffer(v) ? { $buf: v.toString('hex') }
  : (typeof v === 'bigint' ? { $bigint: v.toString() } : v));
const dec = (v) => (v && typeof v === 'object' && typeof v.$buf === 'string' ? Buffer.from(v.$buf, 'hex')
  : (v && typeof v === 'object' && typeof v.$bigint === 'string' ? BigInt(v.$bigint) : v));

function recordingSession(real, rec) {
  rec.store = rec.store || new Map();
  rec.requests = rec.requests || { get: 0, getNext: 0, getBulk: 0 };
  const keep = (vbs) => {
    for (const vb of [].concat(...(vbs || []).map((x) => (Array.isArray(x) ? x : [x])))) {
      if (!vb || !vb.oid) continue;
      if (snmp.isVarbindError(vb)) continue;
      rec.store.set(vb.oid, [vb.oid, vb.type, enc(vb.value)]);
    }
  };
  for (const m of ['get', 'getNext', 'getBulk']) {
    const original = real[m].bind(real);
    real[m] = (...args) => {
      rec.requests[m]++;
      const cb = args[args.length - 1];
      args[args.length - 1] = (err, vbs) => { if (!err) keep(vbs); cb(err, vbs); };
      return original(...args);
    };
  }
  real.set = (vbs, cb) => cb(new Error('The recorder never writes to the switch.'));
  return real;
}

function serialise(rec) {
  return Array.from(rec.store.values()).sort((a, b) => oidCompare(a[0], b[0]));
}

function fakeSession(varbinds, counter) {
  const store = new Map();
  for (const [oid, type, value] of varbinds) store.set(oid, { oid, type, value: dec(value) });
  const sorted = Array.from(store.keys()).sort(oidCompare);
  const count = (m) => { if (counter) counter[m] = (counter[m] || 0) + 1; };
  const after = (oid) => {
    // first recorded OID greater than oid (binary search)
    let lo = 0, hi = sorted.length;
    while (lo < hi) { const mid = (lo + hi) >> 1; if (oidCompare(sorted[mid], oid) <= 0) lo = mid + 1; else hi = mid; }
    return lo < sorted.length ? store.get(sorted[lo]) : { oid, type: snmp.ObjectType.EndOfMibView, value: null };
  };
  const listeners = {};
  const session = {
    on(ev, fn) { listeners[ev] = fn; return session; },
    close() {},
    get(oids, cb) {
      count('get');
      setImmediate(() => cb(null, oids.map((oid) => store.get(oid) || { oid, type: snmp.ObjectType.NoSuchInstance, value: null })));
    },
    getNext(oids, cb) {
      count('getNext');
      setImmediate(() => cb(null, oids.map((oid) => after(oid))));
    },
    getBulk(oids, nonRepeaters, maxRepetitions, cb) {
      count('getBulk');
      const out = [];
      for (let i = 0; i < nonRepeaters && i < oids.length; i++) out.push(after(oids[i]));
      for (let i = nonRepeaters; i < oids.length; i++) {
        const col = [];
        let cur = oids[i];
        for (let r = 0; r < maxRepetitions; r++) {
          const vb = after(cur);
          col.push(vb);
          if (vb.type === snmp.ObjectType.EndOfMibView) break;
          cur = vb.oid;
        }
        out.push(col);
      }
      setImmediate(() => cb(null, out));
    },
    set(vbs, cb) { setImmediate(() => cb(new Error('The recorded switch is read-only.'))); }
  };
  return session;
}

module.exports = { recordingSession, serialise, fakeSession, enc, dec };
