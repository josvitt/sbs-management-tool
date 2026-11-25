'use strict';
// Replays a recorded live health collection through health.collect and checks
// that it reproduces the recorded result.
//   node test/fixtures/live/replay-check.js [fixture.json ...]
// Each fixture holds every get/walk the collector made ({kind, oids|oid, spec,
// result}) plus the final collect() output. Buffers are {"$buf": "<hex>"}.
const fs = require('fs');
const path = require('path');
const health = require('../../../health');

const decode = (v) => JSON.parse(JSON.stringify(v), (k, x) => {
  if (x && typeof x === 'object' && typeof x.$buf === 'string' && Object.keys(x).length === 1) return Buffer.from(x.$buf, 'hex');
  if (x && typeof x === 'object' && typeof x.$bigint === 'string' && Object.keys(x).length === 1) return BigInt(x.$bigint);
  return x;
});

async function replay(file) {
  const fx = JSON.parse(fs.readFileSync(file, 'utf8'));
  const queues = new Map();
  const keyOf = (kind, a, b) => JSON.stringify([kind, a, b === undefined ? null : b]);
  for (const c of fx.calls) {
    const k = c.kind === 'get' ? keyOf('get', c.oids) : keyOf('walk', c.oid, c.spec);
    if (!queues.has(k)) queues.set(k, []);
    queues.get(k).push(c);
  }
  const take = (k) => {
    const q = queues.get(k);
    if (!q || !q.length) throw new Error('no recorded answer for ' + k);
    const c = q.shift();
    if (c.error) throw new Error(c.error);
    return decode(c.result);
  };
  const out = await health.collect({
    get: async (oids) => take(keyOf('get', oids)),
    walk: async (oid, spec) => take(keyOf('walk', oid, JSON.parse(JSON.stringify(spec === undefined ? null : spec)))),
  });
  const want = fx.output;
  const left = [...queues.values()].reduce((n, q) => n + q.length, 0);
  const ok = out.alerts.length === want.alerts.length &&
    JSON.stringify(out.summary) === JSON.stringify(want.summary);
  console.log(path.basename(file), ok ? 'OK' : 'MISMATCH', '- alerts', out.alerts.length, 'recorded', want.alerts.length,
    '- summary', JSON.stringify(out.summary) === JSON.stringify(want.summary) ? 'same' : 'differs', '- unused calls', left);
  return ok;
}

(async () => {
  const files = process.argv.slice(2).length ? process.argv.slice(2)
    : fs.readdirSync(__dirname).filter((f) => f.endsWith('-health.json')).map((f) => path.join(__dirname, f));
  let ok = true;
  for (const f of files) ok = (await replay(f)) && ok;
  process.exit(ok ? 0 : 1);
})().catch((e) => { console.error(e); process.exit(1); });
