'use strict';

// The switchport editor's write (public/src/07-ports.js): the SET plan for
// each kind of change, and the undo that runs when the switch refuses a step.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const SRC = path.join(__dirname, '..', 'public', 'src');
const read = (f) => fs.readFileSync(path.join(SRC, f), 'utf8');
const plain = (x) => JSON.parse(JSON.stringify(x));

// Load the ports module with the shared helpers it uses. refuse(vbs) decides
// which SETs the stand-in switch rejects.
function load(refuse) {
  const sets = [];
  const ctx = {
    console,
    sets,
    appLog: () => {},
    setTimeout: (fn) => setImmediate(fn),
    teardownCalls: [],
    snmpSetResult: async (s, vbs) => {
      const list = Array.isArray(vbs) ? vbs : [vbs];
      sets.push(list.map((v) => v.oid + '=' + (v.valueHex !== undefined ? 'hex' : v.value)).join(','));
      const bad = refuse && refuse(list);
      return bad ? { ok: true, status: 200, body: { results: [{ oid: list[0].oid, error: 'WrongValue' }] } }
        : { ok: true, status: 200, body: { results: list.map((v) => ({ oid: v.oid })) } };
    }
  };
  vm.createContext(ctx);
  const core = read('01-core.js');
  const blocks = core.slice(core.indexOf('  function buildVlanListBlock'), core.indexOf('  // ---- config history'));
  const ipv4 = read('15-ipv4-addressing.js');
  const consts = ipv4.slice(ipv4.indexOf('  const SVI_IP = {'), ipv4.indexOf('  // A routable unicast IPv4'));
  const ports = read('07-ports.js');
  const code = ports.slice(ports.indexOf('  // The SET steps that put a port'), ports.indexOf('  // 802.1X per-port editor:'));
  const api = vm.runInContext(blocks + consts + code +
    '\nasync function teardownSvi(s, i) { teardownCalls.push(i); }' +
    '\n;({ planSwitchportChange, applySwitchportConfig })', ctx);
  return { api, sets, ctx };
}

const s0 = () => ({ target: { host: '10.0.0.1' }, host: '10.0.0.1' });

test('access to trunk sends native, the four VLAN blocks, then the mode last', () => {
  const { api } = load();
  const p = api.planSwitchportChange({ ifIndex: 4, mode: 'trunk', native: 1, tagged: [10, 20],
    before: { mode: 'access', access: 10 } });
  assert.deepEqual(plain(p.forward.map((x) => x[0])),
    ['native', 'vlanTrunkModeList1to1024', 'vlanTrunkModeList1025to2048', 'vlanTrunkModeList2049to3072', 'vlanTrunkModeList3073to4094', 'mode=trunk']);
  assert.deepEqual(plain(p.undo.map((x) => x[0])), ['access-vlan', 'mode=access']);
  assert.equal(p.undo[0][1][0].value, 10);
});

test('switchport to routed is one category SET, and its undo restores the VLANs', () => {
  const { api } = load();
  const p = api.planSwitchportChange({ ifIndex: 4, mode: 'routed', before: { mode: 'access', access: 30 } });
  assert.deepEqual(plain(p.forward), [['no switchport', [{ oid: 'vlanSwitchPortModeCategory.4', type: 'Integer', value: 2 }]]]);
  assert.deepEqual(plain(p.undo.map((x) => x[0])), ['switchport', 'access-vlan', 'mode=access']);
});

test('routed to switchport tears the address down first, and its undo puts it back', () => {
  const { api } = load();
  const p = api.planSwitchportChange({ ifIndex: 4, mode: 'access', access: 1, wasRouted: true,
    before: { addrs: [{ ip: '198.51.100.1', mask: '255.255.255.0', owner: 1 }] } });
  assert.equal(p.teardownFirst, true);
  assert.deepEqual(plain(p.forward.map((x) => x[0])), ['switchport', 'access-vlan', 'mode=access']);
  assert.deepEqual(plain(p.undo.map((x) => x[0])), ['no switchport', 'address 198.51.100.1']);
  assert.deepEqual(plain(p.undo[1][1].map((v) => v.value)), [1, 4, '255.255.255.0']);
});

test('a refused step stops the change and the port is put back', async () => {
  const { api, sets } = load((vbs) => vbs[0].oid.startsWith('vlanTrunkModeList1025'));
  const r = await api.applySwitchportConfig(s0(), { ifIndex: 4, mode: 'trunk', native: 1, tagged: [10],
    before: { mode: 'access', access: 10 } });
  assert.equal(r.ok, false);
  assert.equal(r.restored, true);
  // native, block 1, block 2 (refused), then the undo; mode=trunk never sent.
  assert.equal(sets.some((x) => x.includes('vlanPortModeState.4=12')), false);
  assert.deepEqual(sets.slice(-2), ['vlanAccessPortModeVlanId.4=10', 'vlanPortModeState.4=11']);
});

test('when the first step is refused nothing is undone', async () => {
  const { api, sets } = load(() => true);
  const r = await api.applySwitchportConfig(s0(), { ifIndex: 4, mode: 'access', access: 20, before: { mode: 'access', access: 10 } });
  assert.equal(r.ok, false);
  assert.equal(r.restored, true);
  assert.equal(sets.length, 1);
});

test('a failed undo is reported, not hidden', async () => {
  // The mode step is refused, and so is the undo's write of the old VLAN (10).
  const { api } = load((vbs) => vbs[0].oid.startsWith('vlanPortModeState') || vbs[0].value === 10);
  const r = await api.applySwitchportConfig(s0(), { ifIndex: 4, mode: 'access', access: 20, before: { mode: 'access', access: 10 } });
  assert.equal(r.ok, false);
  assert.equal(r.restored, false);
  assert.ok(r.log.some((l) => /Check this port/.test(l)));
});

test('a routed port whose next step fails gets its address back', async () => {
  const { api, sets, ctx } = load((vbs) => vbs[0].oid.startsWith('vlanAccessPortModeVlanId'));
  const r = await api.applySwitchportConfig(s0(), { ifIndex: 4, mode: 'access', access: 1, wasRouted: true,
    before: { addrs: [{ ip: '198.51.100.1', mask: '255.255.255.0', owner: 1 }] } });
  assert.equal(r.ok, false);
  assert.equal(r.restored, true);
  assert.deepEqual(plain(ctx.teardownCalls), [4]);
  assert.ok(sets.includes('vlanSwitchPortModeCategory.4=2'));
  assert.ok(sets.some((x) => x.startsWith('1.3.6.1.4.1.9.6.1.101.26.1.1.6.198.51.100.1=1')));
});

test('a routed port put back waits before its address, which the switch refuses for ~2 s', () => {
  const { api } = load();
  const p = api.planSwitchportChange({ ifIndex: 4, mode: 'access', access: 1, wasRouted: true,
    before: { mode: 'routed', addrs: [{ ip: '10.1.1.1', mask: '255.255.255.252', owner: 1 }] } });
  assert.deepEqual(plain(p.undo.map((x) => [x[0], x[2] || null])),
    [['no switchport', null], ['address 10.1.1.1', { waitBefore: 2500 }]]);
});
