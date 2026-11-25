'use strict';

/**
 * System settings over SNMP: clock, time zone, summer time and SNTP
 * servers; local user accounts; and which management services are on.
 * The writes are encoded from the rows the switch itself made, recorded
 * from a C1300 on 4.1.9.92 (MODULE-STANDARD rule 5, docs/SWITCH-NOTES.md).
 * Read-only for now (docs/SWITCH-NOTES.md): summer time, whose 14-byte
 * start and end encoding is not yet known; SNTP servers, since the switch
 * refused every form of adding one over SNMP (so removing one could not be
 * undone); and adding users or setting passwords, refused in every form.
 *
 * Objects (CISCOSB MIBs, vendor root 1.3.6.1.4.1.9.6.1.101):
 *   rlTimeSyncMethodMode 92.1: .4 rndTimeSyncManagedDateTime (ddmmyyhhmmss),
 *     .5 rlTimeSyncMethod, .6 rlTimeZone (+hh:mm), .7 rlTimeZoneCode,
 *     .8-.12 rlDaylightSavingTime{Mode,Start,End,Offset,Code},
 *     .13 rlTZDSTOffset (s), .14 rlTimeZoneName, .16 rlClockStatus
 *   rlSntpConfig 92.2.2: .2 rlSntpUnicastAdminState, .5 rlSntpUnicastPollState,
 *     .8 rlSntpAuthenticationState, .14 rlSntpPort, .20 rlSntpTimeSinceLastSync,
 *     .17 rlSntpConfigServerInetTable (index: address type, length, address)
 *   rlAAALocalUserTable 79.17.1: .1 name, .3 privilege, .5 locked(0)/usable(1),
 *     .6 failed logins. The password (.2), salt (.10) and hash method (.11)
 *     columns are never asked for (see readUsers).
 *   rlAAALocalUserEnabled 79.5
 *   rlTelnetEnable 58.7; rlSshServerPort 78.2.101, rlSshServerEnable 78.2.102,
 *     rlSshServerEnablePublicKeyAuthentication 78.2.103,
 *     rlSshServerEnablePasswordAuthentication 78.2.108;
 *   rlEmWebHttpPort 66.10, rlEmWebHttpEnable 66.11, rlEmWebHttpsPort 66.12,
 *     rlEmWebHttpsEnable 66.13
 *   rlMngInf 89: .2 rlMngInfEnable, .3 rlMngInfActiveListName,
 *     .6 rlMngInfListInetTable (index: list name, priority)
 */

const snmp = require('net-snmp');

const V = '1.3.6.1.4.1.9.6.1.101';
const TIME = V + '.92.1';
const SNTP = V + '.92.2.2';
const SNTP_SERVERS = SNTP + '.17.1';
const USERS = V + '.79.17.1';
const MNG_ACL = V + '.89';
const MNG_RULES = MNG_ACL + '.6.1';

const SCALARS = {
  dateTime: TIME + '.4.0',
  method: TIME + '.5.0',
  zoneOffset: TIME + '.6.0',
  zoneCode: TIME + '.7.0',
  dstMode: TIME + '.8.0',
  dstStart: TIME + '.9.0',
  dstEnd: TIME + '.10.0',
  dstOffset: TIME + '.11.0',
  dstCode: TIME + '.12.0',
  totalOffset: TIME + '.13.0',
  zoneName: TIME + '.14.0',
  clockStatus: TIME + '.16.0',
  sntpUnicast: SNTP + '.2.0',
  sntpPoll: SNTP + '.5.0',
  sntpAuth: SNTP + '.8.0',
  sntpPort: SNTP + '.14.0',
  sntpSinceSync: SNTP + '.20.0',
  localUsers: V + '.79.5.0',
  telnet: V + '.58.7.0',
  sshPort: V + '.78.2.101.0',
  ssh: V + '.78.2.102.0',
  sshPubkey: V + '.78.2.103.0',
  sshPassword: V + '.78.2.108.0',
  httpPort: V + '.66.10.0',
  http: V + '.66.11.0',
  httpsPort: V + '.66.12.0',
  https: V + '.66.13.0',
  mngAcl: MNG_ACL + '.2.0',
  mngAclActive: MNG_ACL + '.3.0'
};

const METHOD = { 1: 'none', 2: 'sntp', 3: 'ntp' };
const DST_MODE = { 1: 'recurring', 2: 'date', 3: 'none' };
const CLOCK = { 1: 'invalid', 2: 'manuallySet', 3: 'synchronizedBySntp', 4: 'setByRtc', 5: 'setByPnP' };
const SERVER_STATUS = { 1: 'unknown', 2: 'inProcess', 3: 'up', 4: 'down' };
const SERVICE = { 0: 'any', 1: 'telnet', 2: 'snmp', 3: 'http', 4: 'https', 5: 'ssh' };

function getChunk(session, oids) {
  return new Promise((resolve, reject) => {
    session.get(oids, (error, varbinds) => (error ? reject(error) : resolve(varbinds)));
  });
}

async function getScalars(session) {
  const names = Object.keys(SCALARS);
  const out = {};
  for (let i = 0; i < names.length; i += 15) {
    const part = names.slice(i, i + 15);
    const vbs = await getChunk(session, part.map((n) => SCALARS[n]));
    part.forEach((n, k) => { const vb = vbs[k]; out[n] = (!vb || snmp.isVarbindError(vb)) ? undefined : vb.value; });
  }
  return out;
}

async function walkSubtree(session, base, mode) {
  const { boundedWalkPromise } = require('./collection');
  const rows = await boundedWalkPromise(session, base, mode || 'getbulk', { maxRows: 400 });
  return rows.filter((vb) => !snmp.isVarbindError(vb) && String(vb.oid).indexOf(base + '.') === 0);
}

const text = (v) => (Buffer.isBuffer(v) ? v.toString('utf8') : (v == null ? '' : String(v))).replace(/\0+$/, '').trim();
const num = (v) => (v == null ? null : Number(v));
const truth = (v) => (v == null ? null : Number(v) === 1);
const enabled = (v) => (v == null ? null : Number(v) === 1);   // enabled(1) | disabled(2)

/** "ddmmyyhhmmss" as "20yy-mm-dd hh:mm:ss", or '' when it does not parse. */
function switchDateTime(s) {
  const m = /^(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)$/.exec(s || '');
  return m ? '20' + m[3] + '-' + m[2] + '-' + m[1] + ' ' + m[4] + ':' + m[5] + ':' + m[6] : '';
}

/** An InetAddress decoded from type and bytes. dns(16) is a host name. */
function inetText(type, bytes) {
  if (type === 1 && bytes.length === 4) return bytes.join('.');
  if (type === 2 && bytes.length === 16) {
    const parts = [];
    for (let i = 0; i < 16; i += 2) parts.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
    return parts.join(':').replace(/(^|:)0(:0)+(:|$)/, '::');
  }
  return Buffer.from(bytes).toString('utf8');
}

/**
 * An InetAddress column's value. The shared walk renders an OCTET STRING as
 * text when it is printable and as spaced hex ("c0 00 02 00") when not, so
 * both are turned back into bytes here.
 */
function inetValue(type, v) {
  if (v == null) return '';
  if (Buffer.isBuffer(v)) return inetText(type, Array.from(v));
  const s = String(v);
  if (/^([0-9a-f]{2})( [0-9a-f]{2})*$/i.test(s) && type !== 16) return inetText(type, s.split(' ').map((h) => parseInt(h, 16)));
  if (type === 1 && /^\d+\.\d+\.\d+\.\d+$/.test(s)) return s;
  return type === 16 ? s : inetText(type, Array.from(Buffer.from(s, 'utf8')));
}

/** Split an index of "type.len.b1...bn" off the front of `tail`. */
function takeInet(tail) {
  const type = tail[0], len = tail[1];
  if (!Number.isFinite(type) || !Number.isFinite(len)) return null;
  const bytes = tail.slice(2, 2 + len);
  if (bytes.length !== len) return null;
  return { type, address: inetText(type, bytes), rest: tail.slice(2 + len) };
}

/** Split a length-prefixed string index off the front of `tail`. */
function takeString(tail) {
  const len = tail[0];
  if (!Number.isFinite(len)) return null;
  const chars = tail.slice(1, 1 + len);
  if (chars.length !== len) return null;
  return { value: Buffer.from(chars).toString('utf8'), rest: tail.slice(1 + len) };
}

function columns(vbs, base) {
  const rows = new Map();
  for (const vb of vbs) {
    const tail = vb.oid.slice(base.length + 1).split('.').map(Number);
    const col = tail.shift();
    const key = tail.join('.');
    if (!rows.has(key)) rows.set(key, { index: tail, cols: {} });
    rows.get(key).cols[col] = vb.value;
  }
  return Array.from(rows.values());
}

async function readServers(session) {
  const out = [];
  for (const r of columns(await walkSubtree(session, SNTP_SERVERS), SNTP_SERVERS)) {
    const a = takeInet(r.index);
    if (!a) continue;
    out.push({
      address: a.address,
      kind: a.type === 16 ? 'name' : (a.type === 2 ? 'ipv6' : 'ipv4'),
      polled: truth(r.cols[3]),
      stratum: num(r.cols[4]),
      status: SERVER_STATUS[Number(r.cols[6])] || (r.cols[6] == null ? '' : String(r.cols[6]))
    });
  }
  return out;
}

async function readUsers(session) {
  // The privilege column is walked one GETNEXT at a time: a GETBULK runs on
  // past the end of a column, and the columns after it are the password
  // hash (.2) and its salt (.10). The step past the last privilege lands on
  // the row status column (.4), which is harmless. The name, lock state and
  // failed logins are then read with a GET per user.
  const privs = await walkSubtree(session, USERS + '.3', 'next');
  const out = [];
  for (const vb of privs) {
    const idx = vb.oid.slice(USERS.length + 3);
    const [nameVb, lockVb, failVb] = await getChunk(session, [1, 5, 6].map((c) => USERS + '.' + c + '.' + idx));
    const ok = (x) => x && !snmp.isVarbindError(x);
    out.push({
      name: ok(nameVb) ? text(nameVb.value) : ((takeString(idx.split('.').map(Number)) || {}).value || idx),
      privilege: num(vb.value),
      locked: ok(lockVb) ? Number(lockVb.value) === 0 : null,
      failedLogins: ok(failVb) ? num(failVb.value) : null
    });
  }
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

async function readAclRules(session) {
  const out = [];
  for (const r of columns(await walkSubtree(session, MNG_RULES), MNG_RULES)) {
    const n = takeString(r.index);
    if (!n) continue;
    const c = r.cols;
    const addr = inetValue(Number(c[4]), c[5]);
    out.push({
      list: n.value,
      priority: n.rest[0],
      service: SERVICE[Number(c[7])] || (c[7] == null ? '' : String(c[7])),
      action: Number(c[8]) === 1 ? 'deny' : 'permit',
      address: addr && addr !== '0.0.0.0' ? addr : '',
      mask: text(c[6]) || '',
      ifIndex: num(c[3]) || 0,
      portIfIndex: num(c[11]) || 0
    });
  }
  return out.sort((a, b) => a.list.localeCompare(b.list) || a.priority - b.priority);
}

/**
 * Everything the System panel shows.
 * Resolves { time, users, access }. A part the switch does not answer is
 * null or empty, never an error for the whole read.
 */
async function readSystem(session) {
  const s = await getScalars(session);
  const [servers, users, rules] = await Promise.all([
    readServers(session).catch(() => []),
    readUsers(session).catch(() => []),
    readAclRules(session).catch(() => [])
  ]);
  const port = (v) => (v == null ? null : Number(v));
  return {
    time: {
      now: switchDateTime(text(s.dateTime)),
      method: METHOD[Number(s.method)] || null,
      clock: CLOCK[Number(s.clockStatus)] || null,
      zoneOffset: s.zoneOffset == null ? null : text(s.zoneOffset),
      zoneCode: s.zoneCode == null ? null : text(s.zoneCode),
      zoneName: s.zoneName == null ? null : text(s.zoneName),
      totalOffsetSec: num(s.totalOffset),
      dst: {
        mode: DST_MODE[Number(s.dstMode)] || null,
        start: s.dstStart == null ? null : text(s.dstStart),
        end: s.dstEnd == null ? null : text(s.dstEnd),
        offsetMin: num(s.dstOffset),
        code: s.dstCode == null ? null : text(s.dstCode)
      },
      sntp: {
        unicast: enabled(s.sntpUnicast),
        poll: truth(s.sntpPoll),
        auth: enabled(s.sntpAuth),
        port: port(s.sntpPort),
        sinceSyncSec: num(s.sntpSinceSync)
      },
      servers
    },
    users: { localEnabled: truth(s.localUsers), list: users },
    access: {
      telnet: truth(s.telnet),
      ssh: enabled(s.ssh), sshPort: port(s.sshPort),
      sshPassword: enabled(s.sshPassword), sshPubkey: enabled(s.sshPubkey),
      http: truth(s.http), httpPort: port(s.httpPort),
      https: truth(s.https), httpsPort: port(s.httpsPort),
      mgmtAcl: { enabled: truth(s.mngAcl), active: s.mngAclActive == null ? null : text(s.mngAclActive), rules }
    }
  };
}

// ---- writes ----------------------------------------------------------------

function setVarbinds(session, varbinds) {
  return new Promise((resolve, reject) => {
    session.set(varbinds, (error, result) => {
      if (error) return reject(error);
      const bad = (result || []).find((vb) => snmp.isVarbindError(vb));
      if (bad) return reject(new Error(snmp.varbindError(bad)));
      resolve(result);
    });
  });
}

const I = (oid, value) => ({ oid, type: snmp.ObjectType.Integer, value });
const OS = (oid, value) => ({ oid, type: snmp.ObjectType.OctetString, value: Buffer.from(String(value), 'utf8') });
const ROW = { destroy: 6 };

/** Arcs for a length-prefixed string index. */
function stringIndex(str) {
  const b = Buffer.from(String(str), 'utf8');
  return b.length + '.' + Array.from(b).join('.');
}

/** "+hh:mm" or "-hh:mm" (the switch also accepts and shows "hh:mm" for +). */
function normaliseOffset(offset) {
  const m = /^([+-]?)(\d{1,2}):?(\d{2})$/.exec(String(offset || '').trim());
  if (!m) throw new Error('The time zone offset must look like +01:00 or -07:00.');
  const h = Number(m[2]), min = Number(m[3]);
  if (h > 14 || min > 59 || (min % 15)) throw new Error('The time zone offset must be between -12:00 and +14:00, in steps of 15 minutes.');
  const sign = m[1] === '-' ? '-' : '+';
  if (sign === '-' && h > 12) throw new Error('The time zone offset must be between -12:00 and +14:00.');
  return sign + String(h).padStart(2, '0') + ':' + String(min).padStart(2, '0');
}

/** Set the UTC offset and, optionally, its short name (up to 4 letters). */
async function setTimeZone(session, offset, code) {
  const off = normaliseOffset(offset);
  const vbs = [OS(SCALARS.zoneOffset, off)];
  if (code != null) {
    const c = String(code).trim();
    if (c && !/^[A-Za-z]{1,4}$/.test(c)) throw new Error('The time zone name must be 1 to 4 letters, such as MST.');
    vbs.push(OS(SCALARS.zoneCode, c));
  }
  await setVarbinds(session, vbs);
  return { zoneOffset: off, zoneCode: code == null ? undefined : String(code).trim() };
}

/** Turn SNTP (unicast) on or off. */
async function setSntp(session, on) {
  await setVarbinds(session, [I(SCALARS.sntpUnicast, on ? 1 : 2)]);
  return { unicast: !!on };
}

/** Set the clock. `local` is the switch's local time as "YYYY-MM-DD hh:mm:ss". */
async function setClock(session, local) {
  const m = /^20(\d\d)-(\d\d)-(\d\d)[ T](\d\d):(\d\d)(?::(\d\d))?$/.exec(String(local || '').trim());
  if (!m) throw new Error('The time must look like 2026-11-25 15:30:00.');
  const v = m[3] + m[2] + m[1] + m[4] + m[5] + (m[6] || '00');
  await setVarbinds(session, [OS(SCALARS.dateTime, v)]);
  return { set: switchDateTime(v) };
}

// ---- local users ----

function checkUserName(name) {
  const n = String(name || '');
  if (!/^[A-Za-z0-9._@-]{1,20}$/.test(n)) throw new Error('A user name is 1 to 20 letters, digits, dots, dashes, underscores or @.');
  return n;
}

function checkPrivilege(priv) {
  const n = Number(priv);
  if (!(n === 1 || n === 7 || n === 15)) throw new Error('The privilege must be 1 (read-only), 7 (limited) or 15 (admin).');
  return n;
}

const userOid = (col, name) => USERS + '.' + col + '.' + stringIndex(name);

// The last admin (privilege 15) cannot be removed or demoted: without one,
// nobody can sign in to the switch's CLI or web pages to manage it.
async function guardLastAdmin(session, name) {
  const admins = (await readUsers(session)).filter((u) => u.privilege === 15);
  if (admins.length === 1 && admins[0].name === name) {
    throw new Error(name + ' is the only admin (privilege 15). Add another admin first.');
  }
}

async function setUserPrivilege(session, name, privilege) {
  const n = checkUserName(name), pr = checkPrivilege(privilege);
  if (pr !== 15) await guardLastAdmin(session, n);
  await setVarbinds(session, [I(userOid(3, n), pr)]);
  return { user: n, privilege: pr };
}

async function deleteUser(session, name) {
  const n = checkUserName(name);
  await guardLastAdmin(session, n);
  await setVarbinds(session, [I(userOid(4, n), ROW.destroy)]);
  return { deleted: n };
}

// ---- management services ----

// value(on) for each service's object: TruthValue true(1)/false(2), or the
// SSH server's enable(1)/disable(2).
const SERVICES = {
  ssh: { oid: SCALARS.ssh, label: 'SSH' },
  telnet: { oid: SCALARS.telnet, label: 'Telnet' },
  https: { oid: SCALARS.https, label: 'HTTPS' },
  http: { oid: SCALARS.http, label: 'HTTP' }
};

/**
 * Turn a management service on or off. Turning off the last of SSH, Telnet,
 * HTTPS and HTTP is refused: the switch could then only be managed from its
 * console port and over SNMP.
 */
async function setService(session, service, on) {
  const svc = SERVICES[service];
  if (!svc) throw new Error('service must be ssh, telnet, https or http.');
  if (!on) {
    const now = await getScalars(session);
    const stillOn = Object.keys(SERVICES).filter((k) => k !== service && Number(now[k]) === 1);
    if (!stillOn.length) throw new Error('Turning off ' + svc.label + ' would leave no way to sign in except the console port. Turn on another service first.');
  }
  await setVarbinds(session, [I(svc.oid, on ? 1 : 2)]);
  return { service, on: !!on };
}

module.exports = { readSystem, setTimeZone, setSntp, setClock,
  setUserPrivilege, deleteUser, setService, normaliseOffset, stringIndex, switchDateTime, takeInet, inetText, SCALARS, SNTP_SERVERS, USERS, MNG_RULES };
