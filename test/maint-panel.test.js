'use strict';
// Offline tests for the Reboot and firmware panel (public/src/26-maint.js):
// its loader against a fake local server, the reboot button flow, and its
// registration as a keyed panel with its own Refresh and snapshot data.
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
  const toasts = [];
  const ctx = {
    console, Date, Promise, setTimeout, clearTimeout,
    apiPost: async (url, payload) => { calls.push({ url, payload }); return { ok: true, body: reply(url, payload) }; },
    reconcilePanelInPlace: (s, p) => { repaints.push(p.key); return true; },
    repaintPanel: () => {},
    appLog: () => {},
    toast: (m, k) => toasts.push(m),
    // runButtonAction's contract, without a DOM: run, check ok, onApplied, settle.
    runButtonAction: async (btn, spec) => {
      const r = await spec.run();
      if (!spec.ok(r)) return { failed: spec.error(r) };
      if (spec.onApplied) spec.onApplied(r);
      if (spec.settle) await spec.settle(r);
      return r;
    }
  };
  vm.createContext(ctx);
  // sidePost/sideRepaint live in 16-flash-capture.js; take the panel file and those.
  const api = vm.runInContext(read('16-flash-capture.js') + '\n' + read('26-maint.js') +
    '\n;({ maintLoad, rebootAction, inWords })', ctx);
  const s = { host: '10.0.0.2', target: { host: '10.0.0.2' }, panels: [{ kind: 'builtin', key: 'maint', _body: {} }] };
  return { api, s, calls, repaints, toasts };
}

test('maint loads its status once at a time and reconciles the panel', async () => {
  const { api, s, calls, repaints } = load(() => ({ reboot: { scheduled: false, readable: true }, units: [] }));
  const a = api.maintLoad(s);
  assert.equal(api.maintLoad(s), a);
  await a;
  assert.deepEqual(calls.map((c) => c.url), ['/api/maint/status']);
  assert.equal(s._maint.data.reboot.scheduled, false);
  assert.deepEqual(repaints, ['maint']);
});

test('a failed read is kept as an error', async () => {
  const { api, s } = load(() => ({ error: 'timeout' }));
  await api.maintLoad(s);
  assert.equal(s._maint.data.error, 'timeout');
});

test('reboot now sends seconds 0 and says the switch is rebooting; a scheduled one re-reads the panel', async () => {
  const { api, s, calls, toasts } = load((url, p) => (url === '/api/maint/reboot'
    ? { ok: true, via: 'rlRebootDelay', inSeconds: p.seconds || 2 }
    : { reboot: { scheduled: true, inSeconds: 3600, readable: true }, units: [] }));
  s.sysName = 'core-1';
  await api.rebootAction(null, s, 0);
  assert.deepEqual(JSON.parse(JSON.stringify(calls[0])), { url: '/api/maint/reboot', payload: { target: s.target, seconds: 0 } });
  assert.match(toasts[0], /core-1 is rebooting/);
  assert.equal(calls.length, 1);              // nothing to re-read from a switch going down
  await api.rebootAction(null, s, 3600);
  assert.match(toasts[1], /core-1 will reboot in 60 minutes/);
  assert.equal(calls[2].url, '/api/maint/status');
  assert.equal(s.writeBusy, false);
});

test('times read as words', () => {
  const { api } = load(() => ({}));
  assert.equal(api.inWords(30), '30 seconds');
  assert.equal(api.inWords(900), '15 minutes');
  assert.equal(api.inWords(5 * 3600 + 1800), '5 h 30 min');
});

test('the panel is registered: built in, keyed, painted, refreshed by its loader, adopted from the snapshot', () => {
  const health = read('04-health.js');
  assert.match(health, /\{ key: 'maint', title: 'Reboot and firmware'/);
  assert.match(health, /maint: \['scalars'\]/);
  assert.match(health, /maint: maintLoad \}\[p\.key\]/);
  assert.match(health, /take\('_maint', body\.maint/);
  assert.match(read('06-panels.js'), /KEYED_PANELS = new Set\(\[[^\]]*'maint'/);
  assert.match(read('11-panel-bodies.js'), /key === 'maint'\) \{ paintMaintPanel\(s, body, p\)/);
  assert.match(read('26-maint.js'), /mountInto\(body, s, p, 'maint:images'/);
});

test('config history offers no Restore while the switch drops lines from a copied config', () => {
  assert.doesNotMatch(read('13-config.js'), /\/api\/config\/restore|'restore'/);
});
