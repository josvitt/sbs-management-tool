'use strict';

// The recording scrubber (scripts/lib/scrub-recording.js): addresses, MACs,
// names and the connecting community are replaced everywhere they appear,
// consistently, in values and in OID indexes.
const test = require('node:test');
const assert = require('node:assert/strict');
const { scrub } = require('../scripts/lib/scrub-recording');

const hex = (s) => ({ $buf: Buffer.from(s, 'latin1').toString('hex') });
const arcs = (s) => Array.from(Buffer.from(s, 'latin1')).join('.');
const IP = 64, OCT = 4, INT = 2;

test('a community, an address and a MAC are replaced in values and indexes alike', () => {
  const comm = 'S3cretComm';
  const vbs = [
    ['1.3.6.1.2.1.1.5.0', OCT, hex('core-sw-01')],                                        // sysName
    ['1.3.6.1.6.3.18.1.1.1.2.' + arcs(comm), OCT, hex(comm)],                           // snmpCommunityName
    ['1.3.6.1.4.1.9.6.1.101.26.1.1.3.192.168.10.253', IP, '255.255.255.0'],             // rsIpAdEntNetMask
    ['1.3.6.1.4.1.9.6.1.101.26.1.1.2.192.168.10.253', INT, 100000],                     // rsIpAdEntIfIndex
    ['1.3.6.1.2.1.17.7.1.2.2.1.2.1.0.17.34.51.68.85', INT, 3],                          // dot1qTpFdbPort fid.mac
    ['1.3.6.1.6.3.12.1.2.1.3.' + arcs('TR-1'), OCT, { $buf: 'c0a80a6500a2' }]            // TAddress 192.168.10.101:162
  ];
  const { varbinds } = scrub(vbs, [comm, '192.168.10.253']);
  const text = JSON.stringify(varbinds);
  assert.ok(!text.includes(Buffer.from(comm).toString('hex')));
  assert.ok(!varbinds.some(([oid]) => oid.includes(arcs(comm))), 'community gone from the index');
  // the same address maps the same way in both rows, the mask is kept
  const ipRows = varbinds.filter(([oid]) => oid.startsWith('1.3.6.1.4.1.9.6.1.101.26.1.1.'));
  const suffixes = ipRows.map(([oid]) => oid.split('.').slice(-4).join('.'));
  assert.equal(suffixes[0], suffixes[1]);
  assert.match(suffixes[0], /^192\.0\.2\.253$/);
  assert.equal(ipRows[0][2], '255.255.255.0');
  // the MAC in the FDB index is a documentation MAC now
  const fdb = varbinds.find(([oid]) => oid.startsWith('1.3.6.1.2.1.17.7.1.2.2.1.2.1.'))[0];
  assert.match(fdb, /\.1\.0\.0\.94\.0\.83\.\d+$/);
  // the trap target address is mapped, the port kept
  const ta = varbinds.find(([oid]) => oid.startsWith('1.3.6.1.6.3.12.1.2.1.3.'))[2].$buf;
  assert.ok(ta.startsWith('c0000265'), ta);   // 192.0.2.101
  assert.ok(ta.endsWith('00a2'));
  // sysName replaced by a token of the same length
  const name = Buffer.from(varbinds[0][2].$buf, 'hex').toString();
  assert.equal(name.length, 'core-sw-01'.length);
  assert.notEqual(name, 'core-sw-01');
});

test('an address inside free text is mapped too', () => {
  const { varbinds } = scrub([['1.3.6.1.2.1.1.1.0', OCT, hex('managed from 10.9.8.7')]], []);
  assert.equal(Buffer.from(varbinds[0][2].$buf, 'hex').toString(), 'managed from 192.0.2.7');
});

test('a community inside a NUL-padded or binary value is replaced byte for byte', () => {
  const comm = 'S3cretComm';
  const padded = { $buf: Buffer.concat([Buffer.from(comm), Buffer.alloc(6)]).toString('hex') };
  const binary = { $buf: Buffer.concat([Buffer.from([0xff, 0x01]), Buffer.from(comm + ' 10.9.8.7')]).toString('hex') };
  const { varbinds } = scrub([['1.3.6.1.4.1.9.6.1.101.1.1.0', OCT, padded], ['1.3.6.1.4.1.9.6.1.101.1.2.0', OCT, binary]], [comm]);
  const a = Buffer.from(varbinds[0][2].$buf, 'hex');
  assert.equal(a.length, comm.length + 6);
  assert.ok(!a.toString('latin1').includes(comm));
  const b = Buffer.from(varbinds[1][2].$buf, 'hex').toString('latin1');
  assert.ok(!b.includes(comm) && b.includes('192.0.2.7'), b);
});

test('an address inside a switch-internal "TR-" name and an LLDP management address are mapped', () => {
  const tr = Buffer.concat([Buffer.from('TR-'), Buffer.from([192, 168, 10, 70])]);
  const idx = tr.length + '.' + Array.from(tr).join('.');
  const vbs = [
    ['1.3.6.1.6.3.16.1.2.1.3.2.' + idx, OCT, { $buf: Buffer.from('v1v2SuperGroup').toString('hex') }],   // vacmGroupName
    ['1.3.6.1.6.3.18.1.1.1.4.' + arcs('x1'), OCT, { $buf: tr.toString('hex') }],
    ['1.0.8802.1.1.2.1.4.2.1.3.0.19.76.1.4.192.168.98.253', INT, 2]                               // lldpRemManAddrIfSubtype
  ];
  const { varbinds } = scrub(vbs, []);
  const s = JSON.stringify(varbinds);
  assert.ok(!/192\.168/.test(varbinds.map((v) => v[0]).join(' ')), s);
  const val = Buffer.from(varbinds[1][2].$buf, 'hex');
  assert.equal(val.slice(0, 3).toString(), 'TR-');
  assert.notEqual(val[4], 168);
  // the same address maps the same way in the index and in the value
  assert.ok(varbinds[0][0].endsWith('.84.82.45.' + Array.from(val.slice(3)).join('.')), varbinds[0][0]);
});

test('a firmware version that looks like an address is left alone', () => {
  const { varbinds } = scrub([
    ['1.3.6.1.4.1.9.6.1.101.2.16.1.1.4.1', OCT, hex('4.1.9.92')],          // rndImage1Version
    ['1.3.6.1.2.1.1.1.0', OCT, hex('reached via 4.1.9.92')]                  // free text still maps
  ], []);
  assert.equal(Buffer.from(varbinds[0][2].$buf, 'hex').toString(), '4.1.9.92');
  assert.notEqual(Buffer.from(varbinds[1][2].$buf, 'hex').toString(), 'reached via 4.1.9.92');
});

test('the switch MAC goes from the LACP system id and from link-local addresses made of it', () => {
  const mac = '0c1122334455';
  const ll = 'fe80000000000000' + '0e1122fffe334455';   // EUI-64: U/L bit flipped, ff:fe inserted
  const llArcs = ll.match(/../g).map((h) => parseInt(h, 16)).join('.');
  const { varbinds } = scrub([
    ['1.2.840.10006.300.43.1.1.1.1.4.1000', OCT, { $buf: mac }],                          // dot3adAggActorSystemID
    ['1.3.6.1.2.1.4.34.1.3.4.20.' + llArcs + '.0.1.134.160', INT, 100000],                  // ipAddressIfIndex, link-local
    ['1.3.6.1.4.1.9.6.1.101.26.36.1.14.4.20.' + llArcs + '.0.1.134.160.5.0', OCT, { $buf: ll }],
    ['1.3.6.1.2.1.4.30.1.3.100000', OCT, { $buf: '0e1122fffe334455' }]                      // ipv6InterfaceIdentifier
  ], []);
  const all = JSON.stringify(varbinds);
  assert.ok(!all.includes('0c1122334455') && !all.includes('0e1122fffe334455'), all);
  assert.ok(!varbinds.some(([oid]) => oid.includes('14.17.34.255.254.51.68.85')), all);
  const to = varbinds[0][2].$buf;
  assert.match(to, /^00005e0053/);
  const eui = (h) => { const b = Buffer.from(h, 'hex'); return Buffer.from([b[0] ^ 2, b[1], b[2], 255, 254, b[3], b[4], b[5]]).toString('hex'); };
  assert.equal(varbinds[2][2].$buf, 'fe80000000000000' + eui(to));
  assert.equal(varbinds[3][2].$buf, eui(to));
  assert.ok(varbinds[1][0].includes(eui(to).match(/../g).map((h) => parseInt(h, 16)).join('.')), varbinds[1][0]);
});

test('a bare number in a name column (a VLAN interface\'s description) is left alone', () => {
  const { varbinds } = scrub([
    ['1.3.6.1.4.1.9.6.1.101.54.43.1.23.100998', OCT, hex('999')],    // rlifPresentName 
    ['1.3.6.1.4.1.9.6.1.101.54.43.1.2.100998', OCT, hex('999')]      // rlifPresentDescr
  ], []);
  assert.deepEqual(varbinds.map((v) => Buffer.from(v[2].$buf, 'hex').toString()), ['999', '999']);
});
