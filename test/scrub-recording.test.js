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
