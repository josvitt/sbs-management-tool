'use strict';
// A fake net-snmp session over a map of oid -> [type, value], for module tests.
const snmp = require('net-snmp');

const T = snmp.ObjectType;

function fakeSession(values, hooks) {
  const asked = [];
  const sets = [];
  const cmp = (a, b) => { const x = a.split('.').map(Number), y = b.split('.').map(Number);
    for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i] - y[i];
    return x.length - y.length; };
  return {
    asked, sets,
    on() {}, close() {},
    set(varbinds, cb) {
      sets.push(varbinds.map((v) => ({ oid: v.oid, type: v.type, value: Buffer.isBuffer(v.value) ? v.value.toString() : v.value })));
      const refuse = hooks && hooks.refuse && hooks.refuse(varbinds);
      if (refuse) return setImmediate(() => cb(new Error(refuse)));
      for (const v of varbinds) values[v.oid] = [v.type, v.value];
      setImmediate(() => cb(null, varbinds));
    },
    get(oids, cb) {
      asked.push(...oids);
      setImmediate(() => cb(null, oids.map((oid) => (oid in values)
        ? { oid, type: values[oid][0], value: values[oid][1] }
        : { oid, type: T.NoSuchObject, value: null })));
    },
    getNext(oids, cb) {
      asked.push(...oids.map((o) => 'next:' + o));
      const all = Object.keys(values).sort(cmp);
      setImmediate(() => cb(null, oids.map((start) => {
        const oid = all.find((o) => cmp(o, start) > 0);
        return oid ? { oid, type: values[oid][0], value: values[oid][1] } : { oid: start, type: T.EndOfMibView, value: null };
      })));
    },
    getBulk(oids, nonRep, reps, cb) {
      asked.push(...oids.map((o) => 'bulk:' + o));
      asked.push(...oids);
      const all = Object.keys(values).sort(cmp);
      const out = [];
      for (const start of oids) {
        const next = all.filter((o) => cmp(o, start) > 0).slice(0, reps);
        for (const oid of next) out.push({ oid, type: values[oid][0], value: values[oid][1] });
        if (next.length < reps) out.push({ oid: start, type: T.EndOfMibView, value: null });
      }
      setImmediate(() => cb(null, out));
    }
  };
}

module.exports = { fakeSession };
