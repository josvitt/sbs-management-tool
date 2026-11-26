'use strict';
// The IPv6 reader and writes (switch-ipv6.js) against a fake SNMP session.
const test = require('node:test');
const assert = require('node:assert/strict');
const snmp = require('net-snmp');
const v6 = require('../switch-ipv6');
const { fakeSession } = require('./support/fake-snmp');

const T = snmp.ObjectType;
const int = (n) => [T.Integer, n];
const V = '1.3.6.1.4.1.9.6.1.101';
const A = (text) => v6.v6Bytes(text).join('.');

// The rows .253 made for VLAN 999 (ifIndex 100998) from "ipv6 enable",
// "ipv6 address 2001:db8:999::1/64", "ipv6 route 2001:db8:998::/48
// 2001:db8:999::fe" and "ip name-server 2001:db8:999::53".
function sample() {
  const v = {};
  const ll = '4.20.' + A('fe80::200:5eff:fe00:5324') + '.0.1.138.134.5.0';
  const g = '2.16.' + A('2001:db8:999::1') + '.2.0';
  for (const [k, ifx] of [[g, 100998], [ll, 100998]]) {
    v[v6.T.rlAddr + '.5.' + k] = int(ifx);
    v[v6.T.rlAddr + '.6.' + k] = int(1);
    v[v6.T.rlAddr + '.11.' + k] = int(1);
    v[v6.T.rlAddr + '.13.' + k] = [T.Gauge, 64];
  }
  v[v6.T.rlIface + '.2.100998'] = int(1);
  v[v6.T.rlIface + '.4.100998'] = [T.Gauge, 1500];
  v[V + '.214.2.3.1.3.100998'] = int(3);
  const r = '2.16.' + A('2001:db8:998::') + '.48.2.16.' + A('2001:db8:999::fe') + '.100998';
  v[v6.T.rlStatic + '.7.' + r] = [T.Gauge, 1];
  v[v6.T.rlStatic + '.8.' + r] = int(4);
  v[v6.T.rlStatic + '.10.' + r] = int(1);
  v[v6.T.rlStatic + '.11.' + r] = int(2);
  v[v6.T.rlStatic + '.10.1.4.0.0.0.0.0.1.4.192.0.2.254.0'] = int(1);   // the IPv4 default route, same table
  v[v6.T.dns + '.8.1.1.1.2.16.' + A('2001:db8:999::53') + '.0.1'] = int(1);
  return v;
}

test('v6Bytes and v6Text read and write the forms people type', () => {
  assert.equal(v6.v6Text(v6.v6Bytes('2001:DB8:0:0:0::1')), '2001:db8::1');
  assert.equal(v6.v6Text(v6.v6Bytes('::')), '::');
  assert.equal(v6.v6Text(v6.v6Bytes('::ffff:192.0.2.1')), '::ffff:c000:201');
  for (const bad of ['', '2001:db8', '1::2::3', '2001:db8::g', '1:2:3:4:5:6:7:8:9', '::ffff:300.1.1.1']) assert.equal(v6.v6Bytes(bad), null, bad);
});

test('readIpv6 gives one line per interface, and the IPv6 routes and DNS servers by address', async () => {
  const r = await v6.readIpv6(fakeSession(sample()));
  assert.deepEqual(r.summary, [{
    ifIndex: 100998, on: true, linkLocal: 'fe80::200:5eff:fe00:5324%100998',
    global: [{ address: '2001:db8:999::1', prefixLength: 64, origin: 'manual' }], autoconfig: true, dhcp: 'autoconfig', mtu: 1500
  }]);
  assert.deepEqual(r.staticRoutes.map((x) => [x.dest, x.nextHop, x.ifIndex, x.cost, x.type, x.active]),
    [['2001:db8:998::/48', '2001:db8:999::fe', 100998, 1, 'remote', false]]);
  assert.deepEqual(r.dnsServers.map((x) => [x.address, x.source]), [['2001:db8:999::53', 'static']]);
});

// A fake that acts like the switch on a row status: createAndGo makes the
// row active, destroy removes it, and a server added through the sbelt table
// shows in the DNS servers table.
function switchLike(values) {
  const s = fakeSession(values);
  const set = s.set;
  const STATUS = [v6.T.rlAddr + '.11.', v6.T.rlStatic + '.10.', v6.T.dns + '.8.', v6.SBELT + '.8.'];
  s.set = (vbs, cb) => set(vbs, (e, r) => {
    for (const vb of vbs) {
      if (!e && vb.oid === v6.T.iface + '.5.100998' && vb.value === 2) {
        for (const o of Object.keys(values)) if (o.startsWith(v6.T.rlAddr + '.') && /\.4\.20\./.test(o) && o.endsWith('.0.1.138.134.5.0')) delete values[o];
      }
      const at = STATUS.find((p) => vb.oid.startsWith(p));
      if (!at || e) continue;
      const k = vb.oid.slice(at.length);
      if (vb.value === 6) { for (const o of Object.keys(values)) if (o.endsWith('.' + k) && o.startsWith(at.replace(/\.\d+\.$/, '.'))) delete values[o]; continue; }
      values[vb.oid] = [T.Integer, 1];
      if (at === v6.SBELT + '.8.') values[v6.T.dns + '.8.1.1.2.' + k] = [T.Integer, 1];
    }
    cb(e, r);
  });
  return s;
}

test('the writes send the rows the switch made', async () => {
  const s = switchLike(sample());
  await v6.addAddress(s, 100998, '2001:db8:999::2', 64);
  await v6.removeAddress(s, '2001:db8:999::2');
  await v6.setEnabled(s, 100998, false);
  await v6.setAutoconfig(s, 100998, false);
  await v6.addRoute(s, '2001:db8:997::', 48, '2001:db8:999::fe', 100998);
  const r = (await v6.readIpv6(s)).staticRoutes.find((x) => x.dest === '2001:db8:997::/48');
  await v6.removeRoute(s, r.index);
  await v6.addDnsServer(s, '2001:db8:999::54');
  await v6.removeDnsServer(s, '1.1.2.2.16.' + A('2001:db8:999::54') + '.0.1');
  const a2 = A('2001:db8:999::2');
  const rt = '2.16.' + A('2001:db8:997::') + '.48.2.16.' + A('2001:db8:999::fe') + '.100998';
  const d = A('2001:db8:999::54');
  assert.deepEqual(s.sets.map((vbs) => vbs.map((x) => x.oid.replace(V, 'V').replace('1.3.6.1.2.1.4', 'IP') + '=' + x.value)), [
    ['V.26.36.1.11.2.16.' + a2 + '.2.0=4', 'V.26.36.1.5.2.16.' + a2 + '.2.0=100998', 'V.26.36.1.13.2.16.' + a2 + '.2.0=64', 'V.26.36.1.6.2.16.' + a2 + '.2.0=1'],
    ['V.26.36.1.11.2.16.' + a2 + '.2.0=6'],
    ['IP.30.1.5.100998=2'],
    ['V.26.20.1.2.100998=2'],
    ['V.26.28.1.10.' + rt + '=4', 'V.26.28.1.8.' + rt + '=4', 'V.26.28.1.7.' + rt + '=1'],
    ['V.26.28.1.10.' + rt + '=6'],
    ['V.93.9.1.3.2.16.' + d + '.0.1=.', 'V.93.9.1.5.2.16.' + d + '.0.1=0', 'V.93.9.1.8.2.16.' + d + '.0.1=4'],
    ['V.93.15.1.8.1.1.2.2.16.' + d + '.0.1=6']
  ]);
});

test('the writes refuse values the switch would not take', async () => {
  const s = fakeSession(sample());
  await assert.rejects(v6.addAddress(s, 100998, 'fe80::1', 64), /global address/);
  await assert.rejects(v6.addAddress(s, 100998, '2001:db8::1', 129), /0 to 128/);
  await assert.rejects(v6.addAddress(s, 0, '2001:db8::1', 64), /ifIndex must be/);
  await assert.rejects(v6.addAddress(s, 100998, '192.0.2.1', 24), /must be an IPv6 address/);
  await assert.rejects(v6.addRoute(s, '2001:db8::', 48, '2001:db8:999::fe', 100998, 300), /metric is 1 to 255/);
  await assert.rejects(v6.removeRoute(s, '1.4.0.0.0.0.0'), /IPv6 static route index/);
  await assert.rejects(v6.addDnsServer(s, 'ff02::1'), /unicast/);
  await assert.rejects(v6.removeDnsServer(s, 'x'), /IPv6 DNS server index/);
  assert.equal(s.sets.length, 0);
});

test('a refused form is undone and the next one tried, and the error names every form', async () => {
  const s = switchLike(sample());
  const set = s.set;
  s.set = (vbs, cb) => (vbs.some((v) => v.oid.startsWith(v6.T.rlAddr + '.6.')) ? setImmediate(() => cb(new Error('NotWritable'))) : set(vbs, cb));
  const r = await v6.addAddress(s, 100998, '2001:db8:999::3', 64);
  assert.equal(r.via, 'createAndGo with ifIndex and prefix length');
  assert.deepEqual(r.refused, ['createAndGo with ifIndex, prefix length and unicast: NotWritable']);
  s.set = (vbs, cb) => setImmediate(() => cb(new Error('NoCreation')));
  await assert.rejects(v6.addRoute(s, '2001:db8:997::', 48, '2001:db8:999::fe', 100998),
    /refused every form \(createAndGo with type remote and the metric: NoCreation; createAndGo alone: NoCreation; createAndWait, columns, then active: NoCreation\)/);
});

test('IPv6 off falls back to destroying the link-local row, and on makes it from the interface identifier', async () => {
  const values = sample();
  values[v6.T.iface + '.3.100998'] = [T.OctetString, Buffer.from('02005efffe005324', 'hex')];
  const s = switchLike(values);
  const set = s.set;
  s.set = (vbs, cb) => (vbs[0].oid.startsWith(v6.T.iface + '.5.') ? setImmediate(() => cb(new Error('WrongValue'))) : set(vbs, cb));
  const off = await v6.setEnabled(s, 100998, false);
  assert.equal(off.via, 'destroy the link-local row');
  assert.equal((await v6.readIpv6(s)).summary.find((x) => x.ifIndex === 100998).linkLocal, null);
  const on = await v6.setEnabled(s, 100998, true);
  assert.equal(on.via, 'a link-local row from the interface identifier');
  assert.deepEqual(on.refused, ['ipv6InterfaceEnableStatus up: WrongValue']);
  assert.equal((await v6.readIpv6(s)).summary.find((x) => x.ifIndex === 100998).linkLocal, 'fe80::200:5eff:fe00:5324%100998');
});
