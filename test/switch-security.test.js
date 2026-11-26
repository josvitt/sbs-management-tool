'use strict';
// The switching security reader and writes (switch-security.js) against a fake SNMP session.
const test = require('node:test');
const assert = require('node:assert/strict');
const snmp = require('net-snmp');
const sec = require('../switch-security');
const { fakeSession } = require('./support/fake-snmp');

const T = snmp.ObjectType;
const int = (n) => [T.Integer, n];
const oct = (hex) => [T.OctetString, Buffer.from(hex, 'hex')];
const ip = (a) => [T.IpAddress, a];
const V = '1.3.6.1.4.1.9.6.1.101';

// The shape .253 made for VLAN 999 (docs/SWITCH-NOTES.md, "Switching
// security"): snooping tables with a row for every VLAN number, and rows in
// the DHCP and ARP tables only for what is configured.
function sample() {
  const v = {};
  const S = sec.SCALARS;
  v[S.igmpEnable] = int(1); v[S.igmpQuerierEnable] = int(1); v[S.mldEnable] = int(2);
  v[S.dhcpEnable] = int(1); v[S.dhcpFile] = int(2); v[S.dhcpVerifyMac] = int(1); v[S.dhcpEntries] = int(1);
  v[S.arpEnable] = int(1); v[S.arpLogInterval] = [T.Gauge, 5]; v[S.arpValidation] = int(2);
  for (const vlan of [1, 999]) v[sec.VLAN_STATUS + '.' + vlan] = int(1);
  // VLAN 1500 is not on the switch: its snooping rows are never asked for.
  for (const vlan of [1, 999, 1500]) {
    for (const f of [1, 2]) {
      const k = f + '.' + vlan;
      v[sec.SNOOP_VLAN + '.3.' + k] = int(vlan === 999 && f === 1 ? 1 : 2);
      v[sec.SNOOP_VLAN + '.4.' + k] = int(1);
      v[sec.SNOOP_VLAN + '.9.' + k] = int(3);
      v[sec.SNOOP_VLAN + '.10.' + k] = oct(vlan === 999 && f === 1 ? '10' : '');
      v[sec.SNOOP_VLAN + '.34.' + k] = int(2);
    }
    v[sec.QUERIER + '.2.' + vlan] = int(vlan === 999 ? 1 : 2);
    v[sec.QUERIER + '.3.' + vlan] = int(vlan === 999 ? 1 : 2);
    v[sec.QUERIER + '.4.' + vlan] = ip('255.255.255.255');
    v[sec.QUERIER + '.5.' + vlan] = ip(vlan === 999 ? '192.0.2.1' : '0.0.0.0');
    v[sec.QUERIER + '.6.' + vlan] = int(2);
    v[sec.QUERIER + '.7.' + vlan] = int(2);
    v[sec.QUERIER + '.8.' + vlan] = int(1);
  }
  // A group 239.1.1.1 from any source on VLAN 999, port 4; and ff02::fb.
  v[sec.GROUPS + '.6.999.1.4.239.1.1.1.1.4.0.0.0.0'] = oct('10');
  v[sec.GROUPS + '.6.999.2.16.255.2.0.0.0.0.0.0.0.0.0.0.0.0.0.251.2.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0'] = oct('10');
  v[sec.DHCP_VLAN + '.2.999'] = int(1);
  v[sec.DHCP_TRUST + '.2.4'] = int(1);
  v[sec.BINDING + '.3.999.2.0.94.16.0.2'] = int(1);
  v[sec.BINDING + '.4.999.2.0.94.16.0.2'] = [T.Gauge, 3600];
  v[sec.BINDING + '.5.999.2.0.94.16.0.2'] = ip('192.0.2.20');
  v[sec.BINDING + '.6.999.2.0.94.16.0.2'] = int(4);
  v[sec.ARP_VLAN + '.2.999'] = [T.OctetString, Buffer.from('sbs-ref-arp')];
  v[sec.ARP_VLAN + '.3.999'] = int(1);
  v[sec.ARP_VLAN + '.4.999'] = [T.Counter, 7];
  v[sec.ARP_VLAN + '.5.999'] = [T.Counter, 1];
  v[sec.ARP_VLAN + '.6.999'] = [T.Counter, 0];
  v[sec.ARP_TRUST + '.2.4'] = int(1);
  const k = sec.listIndex('sbs-ref-arp', '192.0.2.10');
  v[sec.ARP_LIST + '.3.' + k] = oct('02005e100001');
  v[sec.ARP_LIST + '.4.' + k] = int(1);
  return v;
}

test('readSecurity reads every table, the VLAN tables for the switch\'s VLANs only', async () => {
  const s = fakeSession(sample());
  const r = await sec.readSecurity(s);
  assert.deepEqual(r.vlanIds, [1, 999]);
  assert.equal(r.igmp.enabled, true);
  assert.equal(r.igmp.querier, true);
  assert.equal(r.mld.enabled, false);
  assert.deepEqual(r.igmp.vlans.map((x) => [x.vlan, x.enabled, x.routerPorts]), [[1, false, []], [999, true, [4]]]);
  assert.deepEqual(r.mld.vlans.map((x) => [x.vlan, x.enabled]), [[1, false], [999, false]]);
  assert.deepEqual(r.igmp.queriers.find((q) => q.vlan === 999),
    { vlan: 999, enabled: true, active: true, address: '255.255.255.255', activeAddress: '192.0.2.1', version: 2, activeVersion: 2, election: true });
  assert.deepEqual(r.igmp.groups.map((g) => [g.vlan, g.group, g.source, g.ports]), [[999, '239.1.1.1', '0.0.0.0', [4]]]);
  assert.deepEqual(r.mld.groups.map((g) => [g.vlan, g.group, g.source]), [[999, 'ff02::fb', '::']]);
  assert.deepEqual(r.dhcp, { enabled: true, file: false, verifyMac: true, entries: 1, vlans: [999], trusted: [4],
    bindings: [{ vlan: 999, mac: '02:00:5e:10:00:02', type: 'learned', lease: 3600, ip: '192.0.2.20', ifIndex: 4 }] });
  assert.deepEqual(r.arp, { enabled: true, logInterval: 5, validation: false, trusted: [4],
    vlans: [{ vlan: 999, list: 'sbs-ref-arp', forwarded: 7, dropped: 1, mismatched: 0 }],
    lists: [{ name: 'sbs-ref-arp', ip: '192.0.2.10', mac: '02:00:5e:10:00:01' }] });
  assert.ok(!s.asked.some((o) => /\.1500$/.test(o)), 'a VLAN the switch does not have is not read');
  assert.ok(!s.asked.some((o) => o.indexOf('bulk:' + sec.SNOOP_VLAN) === 0 || o.indexOf('bulk:' + sec.QUERIER) === 0), 'the per-VLAN tables are not walked');
});

test('the writes send the columns the switch made', async () => {
  const s = fakeSession(sample());
  await sec.setMulticast(s, { enabled: false, querier: true, mld: true });
  await sec.setSnoopVlan(s, 'ipv6', 999, { enabled: true, immediateLeave: true });
  await sec.setQuerier(s, 999, { enabled: false, address: '192.0.2.5', version: 3, election: false });
  await sec.setQuerier(s, 999, { address: '' });
  await sec.setDhcp(s, { enabled: true, verifyMac: false, file: true });
  await sec.setDhcpVlan(s, 10, true);
  await sec.setDhcpVlan(s, 999, false);
  await sec.setDhcpTrust(s, 5, true);
  await sec.setArp(s, { validation: true, logInterval: 60 });
  await sec.setArpVlan(s, 10, { on: true, list: 'sbs-ref-arp' });
  await sec.setArpVlan(s, 999, { list: '' });
  await sec.setArpVlan(s, 999, { on: false });
  await sec.setArpTrust(s, 4, false);
  await sec.addArpListEntry(s, 'sbs-ref-arp', '192.0.2.11', '02-00-5E-10-00-03');
  await sec.removeArpListEntry(s, 'sbs-ref-arp', '192.0.2.10');
  const L = '11.115.98.115.45.114.101.102.45.97.114.112';
  assert.deepEqual(s.sets.map((vbs) => vbs.map((v) => v.oid.replace(V, 'V') + '=' + (/^[\x20-\x7e]*$/.test(String(v.value)) ? v.value : Buffer.from(v.value, 'binary').toString('hex')))), [
    ['V.55.2.2.0=2'], ['V.55.2.13.0=1'], ['V.55.5.1.0=1'],
    ['V.55.5.5.1.3.2.999=1'], ['V.55.5.5.1.34.2.999=1'],
    ['V.55.2.12.1.2.999=2'], ['V.55.2.12.1.4.999=192.0.2.5'], ['V.55.2.12.1.6.999=3'], ['V.55.2.12.1.8.999=2'],
    ['V.55.2.12.1.4.999=255.255.255.255'],
    ['V.112.1.2.0=1'], ['V.112.1.6.0=2'], ['V.112.1.3.0=1'],
    ['V.112.1.12.1.2.10=4'], ['V.112.1.12.1.2.999=6'], ['V.112.1.13.1.2.5=4'],
    ['V.112.3.4.0=1'], ['V.112.3.3.0=60'],
    ['V.112.3.6.1.3.10=4', 'V.112.3.6.1.2.10=sbs-ref-arp'], ['V.112.3.6.1.2.999='], ['V.112.3.6.1.3.999=6'],
    ['V.112.3.7.1.2.4=6'],
    ['V.112.3.5.1.4.' + L + '.192.0.2.11=4', 'V.112.3.5.1.3.' + L + '.192.0.2.11=02005e100003'],
    ['V.112.3.5.1.4.' + L + '.192.0.2.10=6']
  ]);
});

test('the writes refuse values the switch would not take', async () => {
  const s = fakeSession(sample());
  await assert.rejects(sec.setSnoopVlan(s, 'ipx', 1, { enabled: true }), /family must be/);
  await assert.rejects(sec.setSnoopVlan(s, 'ipv4', 5000, { enabled: true }), /vlan must be/);
  await assert.rejects(sec.setQuerier(s, 1, { version: 1 }), /must be 2 or 3/);
  await assert.rejects(sec.setQuerier(s, 1, { address: '300.1.1.1' }), /must be an IPv4 address/);
  await assert.rejects(sec.setArp(s, { logInterval: 90000 }), /is 0 to 86400/);
  await assert.rejects(sec.setArpVlan(s, 1, {}), /Nothing to change/);
  await assert.rejects(sec.addArpListEntry(s, 'bad name', '192.0.2.1', '02:00:5e:10:00:01'), /list name must be/);
  await assert.rejects(sec.addArpListEntry(s, 'ok', '192.0.2.1', '02:00:5e'), /MAC address must be/);
  await assert.rejects(sec.setMulticast(s, {}), /Nothing to change/);
  assert.equal(s.sets.length, 0);
});

test('a refused setting names itself and what was already set', async () => {
  const s = fakeSession(sample(), { refuse: (vbs) => (vbs[0].oid === sec.SCALARS.mldEnable ? 'NotWritable' : null) });
  await assert.rejects(sec.setMulticast(s, { enabled: true, mld: true }), /NotWritable \(1\.3\.6\.1\.4\.1\.9\.6\.1\.101\.55\.5\.1\.0; already set: 1\.3\.6\.1\.4\.1\.9\.6\.1\.101\.55\.2\.2\.0\)/);
});
