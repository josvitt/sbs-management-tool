'use strict';
// Offline tests for the Flash files and Packet capture panels
// (public/src/16-flash-capture.js): their loaders against a fake local server,
// and their registration as keyed panels with their own Refresh.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const SRC = path.join(__dirname, '..', 'public', 'src');
const read = (f) => fs.readFileSync(path.join(SRC, f), 'utf8');

function load(reply) {
  const calls = [];
  const repaints = [];
  const ctx = {
    console, Date, Promise, setInterval: () => 1, clearInterval: () => {},
    document: { body: { contains: () => true } },
    apiPost: async (url, payload) => { calls.push(url); return { ok: true, body: reply(url, payload) }; },
    reconcilePanelInPlace: (s, p) => { repaints.push(p.key); return true; },
    repaintPanel: () => {}
  };
  vm.createContext(ctx);
  const api = vm.runInContext(read('16-flash-capture.js') + '\n;({ flashLoad, captureLoad, captureWrite })', ctx);
  const s = { target: { host: '10.0.0.2' }, panels: [{ kind: 'builtin', key: 'flash', _body: {} }, { kind: 'builtin', key: 'capture', _body: {} }] };
  return { api, s, calls, repaints };
}

test('flash loads its listing once at a time, keeps the highlight, and reconciles', async () => {
  const { api, s, calls, repaints } = load(() => ({ files: [{ name: 'a.pcap' }] }));
  const a = api.flashLoad(s, 'flash://a.pcap');
  const b = api.flashLoad(s);
  assert.equal(a, b);
  await a;
  assert.deepEqual(calls, ['/api/flash/list']);
  assert.equal(s._flash.data.files.length, 1);
  assert.equal(s._flash.highlight, 'a.pcap');
  assert.deepEqual(repaints, ['flash']);
});

test('a failed listing is kept as an error, not as an empty list', async () => {
  const { api, s } = load(() => ({ error: 'timeout' }));
  await api.flashLoad(s);
  assert.equal(s._flash.data.error, 'timeout');
});

test('capture notes whether any capture is running, and a write clears writeBusy', async () => {
  const { api, s } = load((url) => (url === '/api/opc/list'
    ? { captures: [{ name: 'c1', stateText: 'active' }] } : { ok: false, error: 'busy' }));
  await api.captureLoad(s);
  assert.equal(s._capture.anyActive, true);
  const r = await api.captureWrite(s, '/api/opc/action', { name: 'c1', action: 'stop' });
  assert.equal(r.ok, false);
  assert.equal(r.error, 'busy');
  assert.equal(s.writeBusy, false);
});

test('both panels are keyed, no health table repaints them, and the old self-managed helpers are gone', () => {
  assert.match(read('06-panels.js'), /KEYED_PANELS = new Set\(\[[^\]]*'flash', 'capture'/);
  const health = read('04-health.js');
  assert.match(health, /flash: \[\],\s*capture: \[\]/);
  assert.doesNotMatch(health, /selfManagedRender|selfManagedReload/);
  const src = read('16-flash-capture.js');
  assert.doesNotMatch(src, /plainTable|selfManaged|clear\(body\);\n\s*if \(!s\.target\) \{\n/);
  assert.match(src, /mountInto\(body, s, p, 'flash:files'/);
  assert.match(src, /mountInto\(body, s, p, 'capture:list'/);
});
