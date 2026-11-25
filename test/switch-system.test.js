'use strict';
// The System panel's reader (switch-system.js) against a fake SNMP session.
const test = require('node:test');
const assert = require('node:assert/strict');
const snmp = require('net-snmp');
const sys = require('../switch-system');

const T = snmp.ObjectType;

const { fakeSession } = require('./support/fake-snmp');

const S = sys.SCALARS;
const str = (s) => [T.OctetString, Buffer.from(s)];
const int = (n) => [T.Integer, n];

test('readSystem reads the clock, SNTP servers, users and management access', async () => {
  const idx = (s) => s.length + '.' + Array.from(Buffer.from(s)).join('.');
  const values = {
    [S.dateTime]: str('251126143005'), [S.method]: int(2), [S.zoneOffset]: str('+01:00'),
    [S.zoneCode]: str('CET'), [S.dstMode]: int(1), [S.dstOffset]: int(60), [S.clockStatus]: int(3),
    [S.sntpUnicast]: int(1), [S.sntpPoll]: int(1), [S.sntpAuth]: int(2), [S.sntpPort]: int(123),
    [S.localUsers]: int(1), [S.telnet]: int(2), [S.ssh]: int(1), [S.sshPort]: [T.Gauge, 22],
    [S.http]: int(1), [S.httpPort]: int(80), [S.https]: int(1), [S.httpsPort]: int(443),
    [S.mngAcl]: int(2), [S.mngAclActive]: str(''),
    // SNTP servers: one by name (dns 16), one IPv4.
    [sys.SNTP_SERVERS + '.3.16.' + idx('time.example')]: int(1),
    [sys.SNTP_SERVERS + '.6.16.' + idx('time.example')]: int(3),
    [sys.SNTP_SERVERS + '.3.1.4.192.0.2.1']: int(1),
    [sys.SNTP_SERVERS + '.6.1.4.192.0.2.1']: int(4),
    // A user, with a password column that must never be asked for.
    [sys.USERS + '.1.' + idx('admin')]: str('admin'),
    [sys.USERS + '.2.' + idx('admin')]: str('HASH'),
    [sys.USERS + '.3.' + idx('admin')]: int(15),
    [sys.USERS + '.5.' + idx('admin')]: int(1),
    [sys.USERS + '.6.' + idx('admin')]: [T.Counter32, 0],
    // A management ACL rule: list "mgmt", priority 10, ssh permit from 192.0.2.0/24.
    [sys.MNG_RULES + '.4.' + idx('mgmt') + '.10']: int(1),
    [sys.MNG_RULES + '.5.' + idx('mgmt') + '.10']: [T.OctetString, Buffer.from([192, 0, 2, 0])],
    [sys.MNG_RULES + '.6.' + idx('mgmt') + '.10']: [T.IpAddress, '255.255.255.0'],
    [sys.MNG_RULES + '.7.' + idx('mgmt') + '.10']: int(5),
    [sys.MNG_RULES + '.8.' + idx('mgmt') + '.10']: int(0)
  };
  const s = fakeSession(values);
  const r = await sys.readSystem(s);
  assert.equal(r.time.now, '2026-11-25 14:30:05');
  assert.equal(r.time.method, 'sntp');
  assert.equal(r.time.clock, 'synchronizedBySntp');
  assert.equal(r.time.zoneOffset, '+01:00');
  assert.equal(r.time.dst.mode, 'recurring');
  assert.deepEqual(r.time.sntp, { unicast: true, poll: true, auth: false, port: 123, sinceSyncSec: null });
  assert.deepEqual(r.time.servers.map((x) => [x.address, x.kind, x.status]).sort(),
    [['192.0.2.1', 'ipv4', 'down'], ['time.example', 'name', 'up']]);
  assert.deepEqual(r.users, { localEnabled: true, list: [{ name: 'admin', privilege: 15, locked: false, failedLogins: 0 }] });
  assert.equal(r.access.telnet, false);
  assert.equal(r.access.ssh, true);
  assert.equal(r.access.sshPort, 22);
  assert.equal(r.access.https, true);
  assert.deepEqual(r.access.mgmtAcl.rules, [{ list: 'mgmt', priority: 10, service: 'ssh', action: 'permit',
    address: '192.0.2.0', mask: '255.255.255.0', ifIndex: 0, portIfIndex: 0 }]);
  // The password, salt and hash columns are never requested, and the user
  // table is never read in bulk (a GETBULK would run on into them).
  for (const col of [2, 10, 11]) assert.equal(s.asked.some((o) => o.replace(/^\w+:/, '').startsWith(sys.USERS + '.' + col)), false);
  assert.equal(s.asked.some((o) => o.startsWith('bulk:' + sys.USERS)), false);
});

test('readSystem tolerates a switch that answers none of it', async () => {
  const r = await sys.readSystem(fakeSession({}));
  assert.equal(r.time.method, null);
  assert.deepEqual(r.time.servers, []);
  assert.deepEqual(r.users.list, []);
  assert.equal(r.access.ssh, null);
});

test('switchDateTime reads ddmmyyhhmmss', () => {
  assert.equal(sys.switchDateTime('010226235959'), '2026-02-01 23:59:59');
  assert.equal(sys.switchDateTime('junk'), '');
});

const idx = (str) => str.length + '.' + Array.from(Buffer.from(str)).join('.');
const userValues = (users) => {
  const v = {};
  for (const [name, priv] of users) {
    v[sys.USERS + '.1.' + idx(name)] = str(name);
    v[sys.USERS + '.3.' + idx(name)] = int(priv);
    v[sys.USERS + '.4.' + idx(name)] = int(1);
    v[sys.USERS + '.5.' + idx(name)] = int(1);
  }
  return v;
};

test('time zone, SNTP and clock writes', async () => {
  const s = fakeSession({});
  assert.deepEqual(await sys.setTimeZone(s, '-7:00', 'MST'), { zoneOffset: '-07:00', zoneCode: 'MST' });
  assert.deepEqual(s.sets[0], [{ oid: S.zoneOffset, type: T.OctetString, value: '-07:00' }, { oid: S.zoneCode, type: T.OctetString, value: 'MST' }]);
  await assert.rejects(sys.setTimeZone(s, '+15:00'), /between/);
  await assert.rejects(sys.setTimeZone(s, '+05:10'), /15 minutes/);
  await sys.setSntp(s, false);
  assert.deepEqual(s.sets[1], [{ oid: S.sntpUnicast, type: T.Integer, value: 2 }]);
  await sys.setClock(s, '2026-11-25 15:30:05');
  assert.deepEqual(s.sets[2], [{ oid: S.dateTime, type: T.OctetString, value: '251126153005' }]);
  await assert.rejects(sys.setClock(s, 'tomorrow'), /must look like/);
});

test('users: change privilege, delete, and keep the last admin', async () => {
  const s = fakeSession(userValues([['admin', 15], ['tech', 1]]));
  await sys.setUserPrivilege(s, 'tech', 7);
  assert.deepEqual(s.sets[0], [{ oid: sys.USERS + '.3.' + idx('tech'), type: T.Integer, value: 7 }]);
  await assert.rejects(sys.setUserPrivilege(s, 'tech', 5), /privilege/);
  await assert.rejects(sys.deleteUser(s, 'admin'), /only admin/);
  await assert.rejects(sys.setUserPrivilege(s, 'admin', 1), /only admin/);
  await sys.deleteUser(s, 'tech');
  assert.deepEqual(s.sets[1], [{ oid: sys.USERS + '.4.' + idx('tech'), type: T.Integer, value: 6 }]);
  assert.equal(s.sets.length, 2);
  // Two admins: either may go.
  const two = fakeSession(userValues([['admin', 15], ['root', 15]]));
  await sys.deleteUser(two, 'admin');
  assert.deepEqual(two.sets[0], [{ oid: sys.USERS + '.4.' + idx('admin'), type: T.Integer, value: 6 }]);
});

test('a management service can be turned off only while another stays on', async () => {
  const s = fakeSession({ [S.ssh]: int(1), [S.telnet]: int(2), [S.http]: int(2), [S.https]: int(2) });
  await assert.rejects(sys.setService(s, 'ssh', false), /no way to sign in/);
  assert.equal(s.sets.length, 0);
  await sys.setService(s, 'https', true);
  assert.deepEqual(s.sets[0], [{ oid: S.https, type: T.Integer, value: 1 }]);
  await sys.setService(s, 'ssh', false);
  assert.deepEqual(s.sets[1], [{ oid: S.ssh, type: T.Integer, value: 2 }]);
  await assert.rejects(sys.setService(s, 'ftp', true), /service must be/);
});
