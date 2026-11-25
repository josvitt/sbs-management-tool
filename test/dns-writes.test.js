'use strict';

// The IPv4 Addressing panel's DNS and address writes, through the same loader
// the supervised switch test uses (scripts/lib/browser-writes.js). The
// expected varbinds are the ones the C1300 accepted in earlier live tests.
const test = require('node:test');
const assert = require('node:assert/strict');
const { loadBrowserWrites } = require('../scripts/lib/browser-writes');

const plain = (x) => JSON.parse(JSON.stringify(x));
function harness(refuse) {
  const posts = [];
  const w = loadBrowserWrites({
    fetch: async (p, init) => {
      const body = JSON.parse(init.body);
      posts.push({ path: p, body });
      const bad = refuse && refuse(body.varbinds || []);
      return { ok: true, status: 200, json: async () => (bad ? { error: bad } : { results: (body.varbinds || []).map((v) => ({ oid: v.oid })) }) };
    }
  });
  return { w, posts };
}
const s = { target: { host: '10.0.0.1' }, host: '10.0.0.1' };

test('a nameserver is name ".", preference 0 and createAndGo on AddrType.len.addr.root.IN', () => {
  const { w } = harness();
  assert.deepEqual(plain(w.nameserverVarbinds('192.0.2.53')), [
    { oid: '1.3.6.1.4.1.9.6.1.101.93.9.1.3.1.4.192.0.2.53.0.1', type: 'OctetString', value: '.' },
    { oid: '1.3.6.1.4.1.9.6.1.101.93.9.1.5.1.4.192.0.2.53.0.1', type: 'Integer', value: 0 },
    { oid: '1.3.6.1.4.1.9.6.1.101.93.9.1.8.1.4.192.0.2.53.0.1', type: 'Integer', value: 4 }
  ]);
  assert.equal(w.nameserverVarbinds('300.1.1.1'), null);
});

test('a domain is Owner static and createAndGo on the DNS wire-format name', () => {
  const { w } = harness();
  // "example.com" = 7 example 3 com 0, 13 bytes, prefixed with its length.
  const idx = '13.7.101.120.97.109.112.108.101.3.99.111.109.0';
  assert.deepEqual(plain(w.dnsDomainVarbinds('example.com')), [
    { oid: '1.3.6.1.4.1.9.6.1.101.93.3.1.2.' + idx, type: 'Integer', value: 1 },
    { oid: '1.3.6.1.4.1.9.6.1.101.93.3.1.3.' + idx, type: 'Integer', value: 4 }
  ]);
});

test('a host mapping is indexed name.1.0, as the switch made its own rows', () => {
  const { w } = harness();
  const vbs = plain(w.dnsHostVarbinds('nas', '10.0.0.5'));
  assert.deepEqual(vbs.map((v) => v.oid.slice('1.3.6.1.4.1.9.6.1.101.93.6.1.'.length)),
    ['4.5.3.110.97.115.0.1.0', '5.5.3.110.97.115.0.1.0']);
  assert.deepEqual(vbs.map((v) => [v.type, v.value]), [['IpAddress', '10.0.0.5'], ['Integer', 4]]);
  assert.equal(w.dnsNameIndexParse(w.dnsHostIndex('nas')).name, 'nas');
});

test('an interface address is status, ifIndex and mask in one PDU', () => {
  const { w } = harness();
  assert.deepEqual(plain(w.ifAddressVarbinds('10.1.1.1', '255.255.255.252', '4')), [
    { oid: '1.3.6.1.4.1.9.6.1.101.26.1.1.6.10.1.1.1', type: 'Integer', value: 1 },
    { oid: '1.3.6.1.4.1.9.6.1.101.26.1.1.2.10.1.1.1', type: 'Integer', value: 4 },
    { oid: '1.3.6.1.4.1.9.6.1.101.26.1.1.3.10.1.1.1', type: 'IpAddress', value: '255.255.255.252' }
  ]);
});

test('a row delete tries destroy, then notInService and destroy when refused', async () => {
  let first = true;
  const { w, posts } = harness((vbs) => {
    if (first && vbs[0].value === 6) { first = false; return 'CommitFailed'; }
    return null;
  });
  const res = await w.rowStatusDelete(s, '1.3.6.1.4.1.9.6.1.101.93.15.1.8.1.1.0.1.4.192.0.2.53.0.1');
  assert.equal(res.ok, true);
  assert.deepEqual(posts.map((p) => p.body.varbinds[0].value), [6, 2, 6]);
});

test('removing an address takes the DHCP client off first, then the static row', async () => {
  const { w, posts } = harness();
  const r = await w.removeIfAddress(s, 4, { ip: '10.1.1.1' }, true);
  assert.equal(r.ok, true);
  assert.deepEqual(posts.map((p) => p.body.varbinds[0].oid + '=' + p.body.varbinds[0].value),
    ['1.3.6.1.4.1.9.6.1.101.76.3.1.2.4=6', '1.3.6.1.4.1.9.6.1.101.26.1.1.6.10.1.1.1=2']);
});

test('a forced refusal never reaches the switch', async () => {
  const posts = [];
  const w = loadBrowserWrites({
    fetch: async (p, init) => { posts.push(p); return { ok: true, status: 200, json: async () => ({ results: [] }) }; },
    onSet: () => 'forced'
  });
  const r = await w.snmpSetResult(s, { oid: '1.2', type: 'Integer', value: 1 });
  assert.equal(r.body.results[0].error, 'forced');
  assert.equal(posts.length, 0);
});
