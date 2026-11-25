'use strict';
// Offline tests for the SNMP configuration panel (public/src/17-snmp-config.js):
// its loader, per-section refresh and write normalisation against a fake
// /api/snmp-config, and its registration as a keyed panel with its own
// Refresh. The browser-only helpers it calls are stubbed.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const SRC = path.join(__dirname, '..', 'public', 'src');
const read = (f) => fs.readFileSync(path.join(SRC, f), 'utf8');
const plain = (x) => JSON.parse(JSON.stringify(x));

function load(reply) {
  const calls = [];
  const ctx = {
    console,
    calls,
    apiPost: async (url, payload) => {
      const action = url.split('/').pop();
      calls.push(action);
      return { ok: true, body: reply(action, payload) };
    },
    reconcilePanelInPlace: () => true,
    repaintPanel: () => {}
  };
  vm.createContext(ctx);
  const api = vm.runInContext(read('17-snmp-config.js') + '\n;({ snmpLoad, snmpRefresh, snmpWrite, ensureSnmpLoaded })', ctx);
  const s = { target: { host: '10.0.0.2' }, panels: [] };
  return { api, s, calls };
}

test('a full load reads access first, then each section one at a time', async () => {
  const { api, s, calls } = load((a) => (a === 'access' ? { ok: true, level: 'full' } : { ok: true, action: a }));
  await api.snmpLoad(s);
  assert.deepEqual(plain(calls), ['access', 'recipients', 'communities', 'groups', 'users', 'target-check', 'views']);
  assert.equal(s._snmp.editable, true);
  assert.equal(s._snmp.data.comms.action, 'communities');
  assert.equal(s._snmp.loading, null);
});

test('a credential that cannot read the config gets only the access check', async () => {
  const { api, s, calls } = load(() => ({ ok: true, level: 'limited', summary: 'no' }));
  await api.snmpLoad(s);
  assert.deepEqual(plain(calls), ['access']);
  assert.equal(s._snmp.editable, false);
});

test('opening the panel again within 30 seconds does not reload', async () => {
  const { api, s, calls } = load((a) => (a === 'access' ? { ok: true, level: 'readonly' } : { ok: true }));
  await api.snmpLoad(s);
  const n = calls.length;
  api.ensureSnmpLoaded(s);
  assert.equal(calls.length, n);
  s._snmp.fetchedAt -= 31000;
  api.ensureSnmpLoaded(s);
  await s._snmp.loading;
  assert.equal(calls.length, n * 2);
});

test('a write refreshes only its section, plus the target check for recipients and communities', async () => {
  const { api, s, calls } = load((a) => (a === 'access' ? { ok: true, level: 'full' } : { ok: true }));
  await api.snmpLoad(s);
  calls.length = 0;
  await api.snmpRefresh(s, ['users']);
  assert.deepEqual(plain(calls), ['users']);
  calls.length = 0;
  await api.snmpRefresh(s, ['communities']);
  assert.deepEqual(plain(calls), ['communities', 'target-check']);
});

test('a write reports the failing step and clears writeBusy', async () => {
  const { api, s } = load(() => ({ ok: true, applied: { ok: false, log: [{ ok: true }, { ok: false, detail: 'WrongValue' }] } }));
  const r = await api.snmpWrite(s, 'group-add-apply', {});
  assert.deepEqual(plain(r), { ok: false, error: 'WrongValue' });
  assert.equal(s.writeBusy, false);
  const { api: api2, s: s2 } = load(() => ({ ok: false, error: 'Unknown group' }));
  assert.deepEqual(plain(await api2.snmpWrite(s2, 'group-modify-apply', {})), { ok: false, error: 'Unknown group' });
});

test('the panel is keyed, no health table repaints it, and its Refresh runs its own loader', () => {
  assert.match(read('06-panels.js'), /KEYED_PANELS = new Set\(\[[^\]]*'snmpcfg'/);
  const health = read('04-health.js');
  assert.match(health, /snmpcfg: \[\]/);
  assert.match(health, /const ownLoader = \{ snmpcfg: snmpLoad,[^}]*\}\[p\.key\];/);
});

test('the server route offers no preview, status or diagnostics actions', () => {
  const route = fs.readFileSync(path.join(__dirname, '..', 'routes', 'snmp-config.js'), 'utf8');
  assert.doesNotMatch(route, /-preview'|case 'status'|case 'diagnostics'/);
  assert.match(route, /finally \{\s*try \{ session\.close\(\)/);
});

test('the community or SNMPv3 user this app connects with is flagged in use, so it offers no Delete', () => {
  const { markInUse } = require('../routes/snmp-config');
  const comms = markInUse({ communities: [{ community: 'public' }, { community: 'private' }] }, 'communities', 'community', 'private');
  assert.deepEqual(comms.communities.map((c) => !!c.inUse), [false, true]);
  const users = markInUse({ users: [{ name: 'joe' }] }, 'users', 'name', false);
  assert.equal(users.users[0].inUse, undefined);
  assert.match(read('17-snmp-config.js'), /inUseCell\(c\) \|\|/);
  assert.match(read('17-snmp-config.js'), /inUseCell\(u\) \|\|/);
});
