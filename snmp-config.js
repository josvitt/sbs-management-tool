/**
 * SNMP configuration management for Catalyst 1200/1300.
 *
 * The dashboard's other SNMP code reads the switch; this module is the
 * write side and the config-specific reads that go with it: notification
 * recipients, SNMP communities, SNMPv3 groups (VACM) and users (USM),
 * system identity changes, an access check and a target-row integrity check.
 * It is a port of a standalone Python tool, so the hard-won details about this firmware
 * (the "TR-"/"InR-"/"SNR-" internal naming, the address-mask that makes a
 * community pollable, the fact that creating v3 users over SNMP is blocked)
 * live here.
 *
 * It owns no SNMP session. The caller passes a small bundle of primitives
 *   { get(oids)->[{oid,value,type}], walk(baseOid)->[{oid,value,type}],
 *     set([{oid,type,value}])->null|errorString }
 * built from the app's existing net-snmp session, so session lifecycle,
 * v3 crypto and redaction stay in server.js where they already are.
 *
 * Every change-producing call builds a plan of SET steps, and applyPlan runs
 * it in order, stopping at the first required step that fails.
 */

'use strict';

// ---------------------------------------------------------------- OIDs
const TARGET_ADDR = '1.3.6.1.6.3.12.1.2.1';       // snmpTargetAddrEntry
const TARGET_ADDR_EXT = '1.3.6.1.6.3.18.1.2.1';   // snmpTargetAddrExtEntry
const TARGET_PARAMS = '1.3.6.1.6.3.12.1.3.1';     // snmpTargetParamsEntry
const NOTIFY = '1.3.6.1.6.3.13.1.1.1';            // snmpNotifyEntry
const COMMUNITY = '1.3.6.1.6.3.18.1.1.1';         // snmpCommunityEntry
const RND_COMM_INET = '1.3.6.1.4.1.9.6.1.101.98.5.1';
const RND_COMM_V4 = '1.3.6.1.4.1.9.6.1.101.2.7.2.1';
const AUTH_TRAPS = '1.3.6.1.2.1.11.30.0';         // snmpEnableAuthenTraps
const VACM_VIEWS = '1.3.6.1.6.3.16.1.5.2.1';      // vacmViewTreeFamilyEntry
const VACM_S2G = '1.3.6.1.6.3.16.1.2.1';          // vacmSecurityToGroupEntry
const VACM_ACCESS = '1.3.6.1.6.3.16.1.4.1';       // vacmAccessEntry
const USM_USER = '1.3.6.1.6.3.15.1.2.2.1';        // usmUserEntry
const RL_USM_EXT = '1.3.6.1.4.1.9.6.1.101.98.8.1';
const ENGINE_ID = '1.3.6.1.6.3.10.2.1.1.0';       // snmpEngineID
const SYS = {
  name: '1.3.6.1.2.1.1.5.0', descr: '1.3.6.1.2.1.1.1.0',
  uptime: '1.3.6.1.2.1.1.3.0', location: '1.3.6.1.2.1.1.6.0',
  contact: '1.3.6.1.2.1.1.4.0', services: '1.3.6.1.2.1.1.7.0'
};

const AUTH_PROTO_FULL = {
  '1.3.6.1.6.3.10.1.1.1': 'none', '1.3.6.1.6.3.10.1.1.2': 'MD5', '1.3.6.1.6.3.10.1.1.3': 'SHA',
  '1.3.6.1.6.3.10.1.1.4': 'SHA-224', '1.3.6.1.6.3.10.1.1.5': 'SHA-256',
  '1.3.6.1.6.3.10.1.1.6': 'SHA-384', '1.3.6.1.6.3.10.1.1.7': 'SHA-512'
};
const PRIV_PROTO_FULL = {
  '1.3.6.1.6.3.10.1.2.1': 'none', '1.3.6.1.6.3.10.1.2.2': 'DES',
  '1.3.6.1.6.3.10.1.2.3': 'AES-128', '1.3.6.1.6.3.10.1.2.4': 'AES', '1.3.6.1.6.3.10.1.2.5': 'AES-256'
};
const MP_MODEL = { 0: 'v1', 1: 'v2c', 2: 'v2u', 3: 'v3' };
const SEC_LEVEL = { 1: 'noAuthNoPriv', 2: 'authNoPriv', 3: 'authPriv' };
const SEC_LEVEL_SET = { noAuthNoPriv: 1, authNoPriv: 2, authPriv: 3 };
const NOTIFY_TYPE = { 1: 'trap', 2: 'inform' };
const SNMP_UDP_DOMAIN = '1.3.6.1.6.1.1';

// ------------------------------------------------------------- helpers

// A varbind value from net-snmp is a Buffer (OCTET STRING), number, or a
// string (OID). Normalise to the three shapes this module reasons about.
function valBytes(v) {
  if (Buffer.isBuffer(v)) return v;
  if (typeof v === 'number') return Buffer.from(String(v));
  return Buffer.from(String(v == null ? '' : v), 'latin1');
}
function valInt(v) {
  if (typeof v === 'number') return v;
  if (Buffer.isBuffer(v)) return parseInt(v.toString('latin1'), 10);
  const n = parseInt(String(v), 10);
  return Number.isNaN(n) ? null : n;
}
function valOidStr(v) { return String(v == null ? '' : v); }

function bytesToStr(b) {
  const buf = Buffer.isBuffer(b) ? b : valBytes(b);
  return buf.toString('utf8');
}
function hexOf(b) {
  const buf = Buffer.isBuffer(b) ? b : valBytes(b);
  return [...buf].map((x) => x.toString(16).padStart(2, '0').toUpperCase()).join(' ');
}
function isPrintable(buf) { return buf.length > 0 && [...buf].every((c) => c >= 32 && c < 127); }

// Decode a switch-internal name that embeds an IPv4 address: "TR-" + 4
// address bytes + text, and the "InR-"/"SNR-" variants used by the
// community and notify machinery. Falls back to printable text or hex.
function showName(buf) {
  const b = Buffer.isBuffer(buf) ? buf : valBytes(buf);
  const prefixes = ['TR-', 'InR-', 'SNR-', 'InV6R-', 'V_SNR-', 'SSNR-'];
  for (const p of prefixes) {
    const pb = Buffer.from(p, 'latin1');
    if (b.length >= pb.length + 4 && b.slice(0, pb.length).equals(pb)) {
      const addr = b.slice(pb.length, pb.length + 4);
      const ip = [...addr].join('.');
      const rest = b.slice(pb.length + 4).toString('latin1').replace(/\0+$/, '');
      return p + ip + (rest ? ' ' + rest : '');
    }
  }
  if (isPrintable(b)) return b.toString('latin1').replace(/\0+$/, '');
  return '0x' + b.toString('hex');
}

// A walk result -> { indexTuple(as array of ints) : { column : rawValue } }.
// baseOid is the table ENTRY oid; the first sub-id after it is the column,
// the remainder is the row index.
function tableRows(walkResults, baseOid) {
  const base = baseOid.split('.').map(Number);
  const rows = new Map();
  for (const vb of walkResults) {
    if (!vb || vb.error) continue;
    const parts = String(vb.oid).split('.').map(Number);
    if (parts.length <= base.length) continue;
    let match = true;
    for (let i = 0; i < base.length; i++) if (parts[i] !== base[i]) { match = false; break; }
    if (!match) continue;
    const col = parts[base.length];
    const idx = parts.slice(base.length + 1);
    const key = idx.join('.');
    if (!rows.has(key)) rows.set(key, { idx, cols: {} });
    rows.get(key).cols[col] = vb.value;
  }
  return rows;
}

function ipPort6(buf) {
  const b = Buffer.isBuffer(buf) ? buf : valBytes(buf);
  if (b.length === 6) return `${b[0]}.${b[1]}.${b[2]}.${b[3]}:${(b[4] << 8) | b[5]}`;
  return '0x' + b.toString('hex');
}

// ------------------------------------------------------------- reads

const SYS_WRITABLE = { [SYS.name]: 'System name', [SYS.location]: 'Location', [SYS.contact]: 'Contact' };

module.exports = {
  // constants/helpers are exported for tests and for server.js glue
  OIDS: { TARGET_ADDR, TARGET_ADDR_EXT, TARGET_PARAMS, NOTIFY, COMMUNITY, VACM_VIEWS,
    VACM_S2G, VACM_ACCESS, USM_USER, RL_USM_EXT, ENGINE_ID, AUTH_TRAPS, SYS },
  SYS_WRITABLE,
  _helpers: { valBytes, valInt, valOidStr, bytesToStr, hexOf, showName, tableRows, ipPort6 }
  // further functions are attached below
};

// --------------------------------------------------------- recipients

// List notification recipients: the join of snmpTargetAddrTable (where),
// snmpNotifyTable (trap vs inform), snmpTargetParamsTable (version/security)
// and snmpCommunityTable (the community string for v1/v2c). Only "TR-" rows
// that a notify entry selects are real recipients; "nR-"/"InR-" management
// rows on port 161 are not, and are hidden.
async function listRecipients(snmp, opts) {
  opts = opts || {};
  const addrW = await snmp.walk(TARGET_ADDR);
  const paramW = await snmp.walk(TARGET_PARAMS);
  let notifyW = []; try { notifyW = await snmp.walk(NOTIFY); } catch (e) { notifyW = []; }
  let commW = []; try { commW = await snmp.walk(COMMUNITY); } catch (e) { commW = []; }
  let authRaw = null; try { const r = await snmp.get([AUTH_TRAPS]); authRaw = r && r[0] ? valInt(r[0].value) : null; } catch (e) {}

  const addr = tableRows(addrW, TARGET_ADDR);
  const notifyReadable = notifyW.length > 0;

  // params rows keyed by their IMPLIED name bytes (the index IS the name)
  const params = new Map();
  for (const [, row] of tableRows(paramW, TARGET_PARAMS)) {
    params.set(Buffer.from(row.idx).toString('latin1'), row);
  }
  // notify rows grouped by tag bytes (col 2), active rows only (col 5 == 1)
  const tagRows = new Map();
  for (const [, row] of tableRows(notifyW, NOTIFY)) {
    const st = valInt(row.cols[5]);
    if (st != null && st !== 1) continue;
    const tag = row.cols[2] != null ? valBytes(row.cols[2]).toString('latin1') : '';
    if (!tagRows.has(tag)) tagRows.set(tag, []);
    tagRows.get(tag).push(row);
  }
  const comm = tableRows(commW, COMMUNITY);

  const recipients = [];
  for (const [, row] of addr) {
    const nameB = Buffer.from(row.idx);
    const taddr = row.cols[3] != null ? valBytes(row.cols[3]) : Buffer.alloc(0);
    const dest = ipPort6(taddr);
    const ip = dest.split(':')[0];
    const port = dest.includes(':') ? dest.split(':')[1] : '';
    const tagList = row.cols[6] != null ? valBytes(row.cols[6]).toString('latin1') : '';
    const tags = [];
    if (tagList) tags.push(tagList);
    for (const t of tagList.split(/\s+/)) if (t && !tags.includes(t)) tags.push(t);
    const matched = [];
    for (const t of tags) for (const nr of (tagRows.get(t) || [])) matched.push(nr);
    const types = [...new Set(matched.map((nr) => NOTIFY_TYPE[valInt(nr.cols[3])] || 'trap'))].sort();
    if (!types.length && notifyReadable && !opts.all) continue;   // not a recipient

    const pName = row.cols[7] != null ? valBytes(row.cols[7]).toString('latin1') : '';
    const p = params.get(pName) || (pName ? params.get(String.fromCharCode(pName.length) + pName) : null);
    const pCols = p ? p.cols : {};
    const model = valInt(pCols[2]);
    const isCommunity = model === 0 || model === 1;

    // community string for v1/v2c, from the linked snmpCommunityTable row
    let community = '';
    const pSec = pCols[4] != null ? valBytes(pCols[4]).toString('latin1') : null;
    for (const [, cc] of comm) {
      const ttag = cc.cols[6] != null ? valBytes(cc.cols[6]).toString('latin1') : '';
      const csec = cc.cols[3] != null ? valBytes(cc.cols[3]).toString('latin1') : '';
      if ((ttag && tags.includes(ttag)) || (!ttag && pSec != null && csec === pSec)) {
        community = cc.cols[2] != null ? bytesToStr(cc.cols[2]) : '';
        break;
      }
    }
    let secName;
    if (isCommunity) secName = community || showName(valBytes(pCols[4] || Buffer.alloc(0)));
    else secName = pCols[4] != null ? bytesToStr(pCols[4]) : '';

    recipients.push({
      key: { source: 'target', index: row.idx.join('.') },
      source: 'SNMP-TARGET-MIB',
      name: showName(nameB),
      address: ip, port,
      type: types.length ? types.join('/') : (notifyReadable ? 'not a recipient' : '?'),
      version: p ? (MP_MODEL[model] || '?') : '?',
      security_name: secName,
      security_level: p ? (SEC_LEVEL[valInt(pCols[5])] || '?') : '?',
      timeout_s: row.cols[4] != null ? (valInt(row.cols[4]) || 0) / 100 : null,
      retries: valInt(row.cols[5]),
      status: valInt(row.cols[9]) === 1 ? 'active' : (valInt(row.cols[9]) || '')
    });
  }
  return { recipients, auth_failure_traps: authRaw === 1 ? 'enabled' : (authRaw === 2 ? 'disabled' : 'unknown') };
}

module.exports.listRecipients = listRecipients;

// -------------------------------------------------------- communities

const RND_ACCESS = { 1: 'read-only', 2: 'read-write', 3: 'super' };
const RND_TRAP_VER = { 1: 'v1', 2: 'v2c', 3: 'v3', 4: 'disabled' };

function decodeInetAddr(atype, b) {
  const buf = Buffer.isBuffer(b) ? b : valBytes(b);
  if (atype === 1 && buf.length >= 4) return [...buf.slice(0, 4)].join('.');       // ipv4
  if (atype === 2 && buf.length >= 16) return [...buf.slice(0, 16)].map((x) => x.toString(16)).join(':');
  return buf.length ? '0x' + buf.toString('hex') : '0.0.0.0';
}

async function listCommunities(snmp) {
  const rows = [];
  // Cisco private table: community, allowed station, access, traps, status
  let rndW = []; try { rndW = await snmp.walk(RND_COMM_INET); } catch (e) { rndW = []; }
  for (const [, row] of tableRows(rndW, RND_COMM_INET)) {
    const idx = row.idx;
    const atype = idx[0], alen = idx[1], rest = idx.slice(2);
    const addr = decodeInetAddr(atype, Buffer.from(rest.slice(0, alen)));
    const community = Buffer.from(rest.slice(alen)).toString('utf8');
    rows.push({
      source: 'rndCommunityInet', community,
      station: (addr === '0.0.0.0' || addr === '::') ? 'any' : addr,
      access: RND_ACCESS[valInt(row.cols[4])] || String(valInt(row.cols[4]) ?? ''),
      traps: RND_TRAP_VER[valInt(row.cols[5])] || '',
      status: valInt(row.cols[6]) === 1 ? 'enable' : (valInt(row.cols[6]) || ''),
      key: { source: 'rndInet', index: idx.join('.') }
    });
  }

  // Standard SNMP-COMMUNITY-MIB: where the C1300 keeps read-only/read-write
  // communities. Only the GUI-managed user communities are shown: index must
  // be "SSNR-<community>" AND the security name "SNR-<community>". This is the
  // exact filter the original tool uses; it hides the notification community
  // rows (TR-/InR-) and the station-restricted rows whose index is "SNR-..."
  // with an embedded address (e.g. innerFromLinux), which are not plain
  // communities and must not appear here.
  let commW = []; try { commW = await snmp.walk(COMMUNITY); } catch (e) { commW = []; }
  let s2gW = []; try { s2gW = await snmp.walk(VACM_S2G); } catch (e) {}
  let accW = []; try { accW = await snmp.walk(VACM_ACCESS); } catch (e) {}
  const s2g = tableRows(s2gW, VACM_S2G);
  const acc = tableRows(accW, VACM_ACCESS);

  // access mode for a community's security name (SNR-<community>): find its
  // v2c (model 2) group, then that group's access row read/write views.
  // Resolve a community's access mode AND its actual view names from VACM.
  // Returns { access, read, write, notify }.
  function accessModeFor(secBytes) {
    let group = null;
    for (const [, g] of s2g) {
      const raw = Buffer.from(g.idx);
      if (raw.length >= 2 && raw[0] === 2 && raw.slice(2).equals(secBytes) && g.cols[3] != null) {
        group = valBytes(g.cols[3]); break;
      }
    }
    if (!group) return { access: 'unknown', read: '', write: '', notify: '' };
    for (const [, a] of acc) {
      const raw = Buffer.from(a.idx); const glen = raw[0];
      if (raw.slice(1, 1 + glen).equals(group)) {
        const read = a.cols[5] != null ? bytesToStr(a.cols[5]) : '';
        const write = a.cols[6] != null ? bytesToStr(a.cols[6]) : '';
        const notify = a.cols[7] != null ? bytesToStr(a.cols[7]) : '';
        let access = 'unknown';
        if (write) access = (read === 'DefaultSuper') ? 'SNMP Admin' : 'read-write';
        else if (read) access = 'read-only';
        return { access, read, write, notify };
      }
    }
    return { access: 'unknown', read: '', write: '', notify: '' };
  }

  const seen = new Set(rows.map((r) => r.community));
  for (const [, cc] of tableRows(commW, COMMUNITY)) {
    const iname = Buffer.from(cc.idx);                 // the row index bytes
    const name = cc.cols[2] != null ? bytesToStr(cc.cols[2]) : '';
    const sec = cc.cols[3] != null ? valBytes(cc.cols[3]) : Buffer.alloc(0);
    // Show ONLY user communities: index "SSNR-<c>", security name "SNR-<c>".
    if (!(iname.slice(0, 5).toString('latin1') === 'SSNR-' && sec.slice(0, 4).toString('latin1') === 'SNR-')) continue;
    if (seen.has(name)) continue;
    const am = accessModeFor(sec);
    // the view a community uses: its read view (what it can see)
    const view = am.read || '';
    rows.push({
      source: 'snmpCommunity', community: name,
      station: 'any',
      access: am.access,
      view: view,
      traps: '', status: valInt(cc.cols[8]) === 1 ? 'enable' : (valInt(cc.cols[8]) || ''),
      key: { source: 'snmpComm', index: cc.idx.join('.'), community: name }
    });
  }
  return { communities: rows };
}
module.exports.listCommunities = listCommunities;

// ------------------------------------------------------------- groups

async function listGroups(snmp) {
  let s2gW = []; try { s2gW = await snmp.walk(VACM_S2G); } catch (e) {}
  let accW = []; try { accW = await snmp.walk(VACM_ACCESS); } catch (e) {}
  let usmW = []; try { usmW = await snmp.walk(USM_USER); } catch (e) {}
  let commW = []; try { commW = await snmp.walk(COMMUNITY); } catch (e) {}
  const s2g = tableRows(s2gW, VACM_S2G);
  const acc = tableRows(accW, VACM_ACCESS);

  const usmNames = new Set();
  for (const [, u] of tableRows(usmW, USM_USER)) {
    const idx = u.idx; const elen = idx[0]; const rest = idx.slice(1 + elen);
    if (rest.length) {
      const nlen = rest[0];
      const nm = Buffer.from(rest.slice(1, 1 + nlen)).length ? Buffer.from(rest.slice(1, 1 + nlen)) : Buffer.from(rest.slice(1));
      if (nm.length) usmNames.add(nm.toString('latin1'));
    }
  }
  const communityNames = new Set();
  for (const [, c] of tableRows(commW, COMMUNITY)) if (c.cols[2] != null) communityNames.add(bytesToStr(c.cols[2]));

  const groups = new Map();  // internal group name (latin1) -> {group, members:[]}
  for (const [, g] of s2g) {
    const idx = g.idx;
    if (!idx.length || idx[0] !== 3) continue;            // USM model only
    const sec = Buffer.from(idx.slice(2)).toString('latin1');
    const group = g.cols[3] != null ? valBytes(g.cols[3]).toString('latin1') : '';
    if (!group || group.startsWith('V_SNR-')) continue;
    if (!usmNames.has(sec)) continue;
    if (!groups.has(group)) groups.set(group, { group, members: [] });
    groups.get(group).members.push(sec);
  }
  // groups with a USM access row but no member yet (freshly created)
  for (const [, a] of acc) {
    const raw = Buffer.from(a.idx); const glen = raw[0];
    const group = raw.slice(1, 1 + glen).toString('latin1');
    const model = a.idx[a.idx.length - 2];
    if (model !== 3) continue;
    if (groups.has(group)) continue;
    if (group.startsWith('V_SNR-')) continue;
    const bare = group.startsWith('G_') ? group.slice(2) : group;
    if (group.startsWith('G_') && communityNames.has(bare)) continue;
    groups.set(group, { group, members: [] });
  }

  const lvlName = { 1: 'noAuthNoPriv', 2: 'authNoPriv', 3: 'authPriv' };
  const out = [];
  for (const [group, g] of groups) {
    const display = group.startsWith('G_') ? group.slice(2) : group;
    const perLevel = {}; const levels = [];
    for (const [, a] of acc) {
      const raw = Buffer.from(a.idx); const glen = raw[0];
      if (raw.slice(1, 1 + glen).toString('latin1') !== group) continue;
      const level = a.idx[a.idx.length - 1];
      perLevel[lvlName[level] || level] = {
        read: a.cols[5] != null ? bytesToStr(a.cols[5]) : '',
        write: a.cols[6] != null ? bytesToStr(a.cols[6]) : '',
        notify: a.cols[7] != null ? bytesToStr(a.cols[7]) : ''
      };
      if (!levels.includes(level)) levels.push(level);
    }
    out.push({
      group: display, members: g.members.join(', '),
      level: levels.sort().map((l) => lvlName[l] || l).join(', ') || '—',
      views: perLevel,
      key: { group, display, levels: levels.sort() }
    });
  }
  return { groups: out };
}
module.exports.listGroups = listGroups;

// -------------------------------------------------------------- users

// Distinct vacmViewTreeFamily view names on the switch, for the group forms'
// Read/Write/Notify dropdowns.
async function listViewNames(snmp) {
  const names = new Set();
  try {
    for (const [, v] of tableRows(await snmp.walk(VACM_VIEWS), VACM_VIEWS)) {
      const raw = Buffer.from(v.idx); const nlen = raw[0];
      const nm = raw.slice(1, 1 + nlen).toString('latin1');
      if (nm) names.add(nm);
    }
  } catch (e) {}
  return { views: [...names].sort() };
}
module.exports.listViewNames = listViewNames;

async function listUsers(snmp) {
  let usmW = []; try { usmW = await snmp.walk(USM_USER); } catch (e) {}
  let s2gW = []; try { s2gW = await snmp.walk(VACM_S2G); } catch (e) {}
  const s2g = tableRows(s2gW, VACM_S2G);
  const groupFor = new Map();
  for (const [, g] of s2g) {
    if (g.idx[0] !== 3) continue;
    const sec = Buffer.from(g.idx.slice(2)).toString('latin1');
    const grp = g.cols[3] != null ? valBytes(g.cols[3]).toString('latin1') : '';
    groupFor.set(sec, grp.startsWith('G_') ? grp.slice(2) : grp);
  }
  const out = [];
  for (const [, u] of tableRows(usmW, USM_USER)) {
    const idx = u.idx; const elen = idx[0]; const rest = idx.slice(1 + elen);
    const nlen = rest[0]; const nameB = Buffer.from(rest.slice(1, 1 + nlen));
    const name = nameB.toString('utf8');
    if (/^V_SNR-/.test(name)) continue;
    const auth = AUTH_PROTO_FULL[valOidStr(u.cols[5])] || 'none';
    const priv = PRIV_PROTO_FULL[valOidStr(u.cols[8])] || 'none';
    out.push({
      name, auth, priv, group: groupFor.get(name) || '',
      status: valInt(u.cols[13]) === 1 ? 'active' : (valInt(u.cols[13]) || ''),
      key: { index: idx.join('.') }
    });
  }
  return { users: out };
}
module.exports.listUsers = listUsers;

// --------------------------------------------------------------- writes
//
// A SET value is described as { oid, type, value } where type is a net-snmp
// ObjectType *name* the server maps: 'OctetString' (bytes or string),
// 'Integer', 'OID'. Plans are arrays of { title, varbinds:[...], required }.

function vbOctet(oid, bytesOrStr, shown) {
  const buf = Buffer.isBuffer(bytesOrStr) ? bytesOrStr : Buffer.from(String(bytesOrStr), 'latin1');
  return { oid, type: 'OctetString', value: buf, shown: shown != null ? shown : (isPrintable(buf) ? '"' + buf.toString('latin1') + '"' : hexOf(buf)) };
}
function vbInt(oid, n, shown) { return { oid, type: 'Integer', value: n, shown: shown != null ? shown : String(n) }; }
function vbOid(oid, oidStr, shown) { return { oid, type: 'OID', value: oidStr, shown: shown != null ? shown : oidStr }; }

function idxStr(bytes) { return [...bytes].join('.'); }

// ---- status (sysName / sysLocation / sysContact) ----
function planSetSystem(r) {
  const oid = String((r || {}).oid || '');
  const value = String((r || {}).value || '');
  if (!SYS_WRITABLE[oid]) throw new Error('That system value cannot be changed over SNMP.');
  if (Buffer.byteLength(value, 'utf8') > 255) throw new Error('Value is too long (max 255 bytes).');
  return { label: SYS_WRITABLE[oid],
    steps: [{ title: 'Set ' + SYS_WRITABLE[oid], required: true,
      varbinds: [vbOctet(oid, Buffer.from(value, 'utf8'), '"' + value + '"')] }] };
}
module.exports.planSetSystem = planSetSystem;

// ---- community add ----
// Creates the row set the switch itself makes for a working community,
// including the InR-<community> allowed-manager binding and its address
// mask (00 00 00 00 FF FF) that turns 0.0.0.0 into "any station". Without
// the mask the community exists but nobody may poll with it.
async function planAddCommunity(snmp, r) {
  const name = String((r || {}).community || '').trim();
  if (!name || name.length > 32) throw new Error('Community string must be 1 to 32 characters.');
  const access = (r || {}).access || 'read-only';
  let engine = Buffer.alloc(0);
  try { const g = await snmp.get([ENGINE_ID]); if (g && g[0]) engine = valBytes(g[0].value); } catch (e) {}
  const cb = Buffer.from(name, 'latin1');
  // The v1/v2c security name is "SNR-<community>" PADDED WITH 4 NUL BYTES,
  // exactly like the community index ("SSNR-"+c+4) and group ("V_SNR-"+c+4).
  // This padded form is what the switch stores and what the Python tool (which
  // created the working "newcomm") writes, and it must be identical in the
  // snmpCommunityTable security-name column AND in the vacmSecurityToGroupTable
  // index, or the config parser cannot tie them together.
  const sec = Buffer.concat([Buffer.from('SNR-', 'latin1'), cb, Buffer.alloc(4)]);
  const vGroup = Buffer.concat([Buffer.from('V_SNR-', 'latin1'), cb, Buffer.alloc(4)]);
  const commIdx = [...Buffer.concat([Buffer.from('SSNR-', 'latin1'), cb, Buffer.alloc(4)])];
  // The transport tag is "InR-<community>" PADDED TO 48 BYTES with NUL. This
  // exact 48-byte value is what both the snmpCommunityTable transport-tag
  // column AND the snmpTargetAddrTable tag column must carry — the Python tool
  // (which created the working "newcomm") uses the padded form for both, and
  // the switch stores it padded. Writing an UNPADDED tag on the community row
  // makes its binding tag differ from the target row's tag, which the config
  // parser cannot reconcile -> the fatal %SNMP-F-BADTDOMAIN on config save.
  const tagRaw = Buffer.concat([Buffer.from('InR-', 'latin1'), cb]);
  const tag = Buffer.concat([tagRaw, Buffer.alloc(Math.max(0, 48 - tagRaw.length))]).slice(0, 48);

  const steps = [];
  // 1. snmpCommunityTable row
  const ci = idxStr(commIdx);
  // Column set matches the Python tool exactly: name, security name, engine ID
  // (only if known), transport tag (48-byte padded), storage, RowStatus. The
  // empty contextName (col 5) is NOT written — the switch defaults it, and
  // writing an explicit empty string is an extra varbind the working tool omits.
  const cvb = [
    vbOctet(`${COMMUNITY}.2.${ci}`, cb, '"' + name + '"'),
    vbOctet(`${COMMUNITY}.3.${ci}`, sec, showName(sec) + ' (SNR- + community)')
  ];
  if (engine.length) cvb.push(vbOctet(`${COMMUNITY}.4.${ci}`, engine, hexOf(engine) + ' (engine ID)'));
  cvb.push(vbOctet(`${COMMUNITY}.6.${ci}`, tag, 'InR- + community, padded to 48 bytes'));
  cvb.push(vbInt(`${COMMUNITY}.7.${ci}`, 3, '3 (nonVolatile)'));
  cvb.push(vbInt(`${COMMUNITY}.8.${ci}`, 4, '4 (createAndGo)'));
  steps.push({ title: 'Create the community row (snmpCommunityTable)', required: true, varbinds: cvb });

  // 2. v1 and v2c security-to-group rows (model 1 and 2 -> V_SNR group)
  for (const model of [1, 2]) {
    const gi = idxStr([model, sec.length, ...sec]);
    steps.push({ title: `Map security name to group, SNMP ${model === 1 ? 'v1' : 'v2c'} (vacmSecurityToGroupTable)`,
      required: true, varbinds: [
        vbOctet(`${VACM_S2G}.3.${gi}`, vGroup, '"' + showName(vGroup) + '"'),
        vbInt(`${VACM_S2G}.4.${gi}`, 3, '3 (nonVolatile)'),
        vbInt(`${VACM_S2G}.5.${gi}`, 4, '4 (createAndGo)')] });
  }

  // 3. access row granting the V_SNR group its views (may be read-only on some fw).
  // Each access mode has a default view (Default / DefaultSuper); an explicit
  // view (r.view) overrides it, and the writable modes also write that view.
  const MODE = { 'read-only': { def: 'Default', write: false },
                 'read-write': { def: 'Default', write: true },
                 'snmp-admin': { def: 'DefaultSuper', write: true } };
  const mode = MODE[access] || MODE['read-only'];
  const chosen = ((r || {}).view || '').trim() || mode.def;
  const readV = chosen, writeV = mode.write ? chosen : '';
  const ag = idxStr([vGroup.length, ...vGroup, 0, 2, 1]);  // ctxLen 0, model 2 (v2c), level 1
  // Column 6 (write view) is written ONLY when there is a write view, exactly
  // like the Python tool — a read-only community omits it entirely rather than
  // writing an empty string.
  const accVb = [
    vbInt(`${VACM_ACCESS}.4.${ag}`, 1, '1 (contextMatch: exact)'),
    vbOctet(`${VACM_ACCESS}.5.${ag}`, readV, '"' + readV + '" (read view)')
  ];
  if (writeV) accVb.push(vbOctet(`${VACM_ACCESS}.6.${ag}`, writeV, '"' + writeV + '" (write view)'));
  accVb.push(vbOctet(`${VACM_ACCESS}.7.${ag}`, readV, '"' + readV + '" (notify view)'));
  accVb.push(vbInt(`${VACM_ACCESS}.8.${ag}`, 3, '3 (nonVolatile)'));
  accVb.push(vbInt(`${VACM_ACCESS}.9.${ag}`, 4, '4 (createAndGo)'));
  steps.push({ title: 'Grant the group its views (vacmAccessTable) — may be read-only on this switch',
    required: false, varbinds: accVb });

  // 4. allowed-manager binding — the SINGLE IPv4 InR- row, exactly as the
  // working Python tool wrote it. The Python tool created the "newcomm"
  // community on this switch and it did NOT crash: it writes ONLY this one
  // IPv4 snmpTargetAddrTable row (InR- + 4 zero bytes + community), and the
  // switch itself auto-creates the matching IPv6 (InV6R-) companion. Writing
  // the IPv6 row ourselves is wrong — it conflicts with the one the switch
  // generates. Column order: everything except RowStatus first, then the mask
  // (ext col 1) in the SAME PDU, then RowStatus createAndGo last so the row
  // commits with the mask already in place.
  const tag48 = Buffer.concat([tag, Buffer.alloc(Math.max(0, 48 - tag.length))]).slice(0, 48);
  const ai = idxStr([...Buffer.concat([Buffer.from('InR-', 'latin1'), Buffer.alloc(4), cb])]);
  const link = Buffer.concat([Buffer.from('InR-', 'latin1'), Buffer.alloc(4), cb]);
  steps.push({ title: 'Allow management stations to poll with this community (snmpTargetAddrTable InR- + mask)',
    required: true, varbinds: [
      vbOid(`${TARGET_ADDR}.2.${ai}`, SNMP_UDP_DOMAIN, SNMP_UDP_DOMAIN + ' (snmpUDPDomain)'),
      vbOctet(`${TARGET_ADDR}.3.${ai}`, Buffer.from([0, 0, 0, 0, 0, 161]), '0.0.0.0:161 (any manager)'),
      vbInt(`${TARGET_ADDR}.4.${ai}`, 1500, '1500 (timeout)'),
      vbInt(`${TARGET_ADDR}.5.${ai}`, 3, '3 (retries)'),
      vbOctet(`${TARGET_ADDR}.6.${ai}`, tag48, 'InR- + community tag (48 bytes)'),
      vbOctet(`${TARGET_ADDR}.7.${ai}`, link, showName(link) + ' (params link)'),
      vbInt(`${TARGET_ADDR}.8.${ai}`, 3, '3 (nonVolatile)'),
      vbOctet(`${TARGET_ADDR_EXT}.1.${ai}`, Buffer.from([0, 0, 0, 0, 0xFF, 0xFF]), '00 00 00 00 FF FF (mask: match any source IP)'),
      vbInt(`${TARGET_ADDR_EXT}.2.${ai}`, 484, '484 (max message size)'),
      vbInt(`${TARGET_ADDR}.9.${ai}`, 4, '4 (createAndGo)')] });

  return { community: name, steps,
    warnings: ['The access row (vacmAccessTable) may be read-only over SNMP on some firmware; if it is skipped the community still works at the access level the switch assigns.'] };
}
module.exports.planAddCommunity = planAddCommunity;

// Modify an existing community's ACCESS MODE and VIEW only, by rewriting its
// VACM access row (vacmAccessTable) for the V_SNR-<community> group. Everything
// else about the community (its security-name mapping, manager binding) is left
// untouched. This is the only part of a community that is meaningfully editable
// over SNMP.
async function planModifyCommunity(snmp, r) {
  const name = String((r || {}).community || '').trim();
  if (!name || name.length > 32) throw new Error('Community string must be 1 to 32 characters.');
  const access = (r || {}).access || 'read-only';
  const cb = Buffer.from(name, 'latin1');
  // Group name mirrors the add: "V_SNR-" + community + 4 NUL bytes.
  const vGroup = Buffer.concat([Buffer.from('V_SNR-', 'latin1'), cb, Buffer.alloc(4)]);
  const MODE = { 'read-only': { def: 'Default', write: false },
                 'read-write': { def: 'Default', write: true },
                 'snmp-admin': { def: 'DefaultSuper', write: true } };
  const mode = MODE[access] || MODE['read-only'];
  const chosen = ((r || {}).view || '').trim() || mode.def;
  const readV = chosen, writeV = mode.write ? chosen : '';
  const ag = idxStr([vGroup.length, ...vGroup, 0, 2, 1]);  // ctxLen 0, model 2 (v2c), level 1
  const accVb = [
    vbInt(`${VACM_ACCESS}.4.${ag}`, 1, '1 (contextMatch: exact)'),
    vbOctet(`${VACM_ACCESS}.5.${ag}`, readV, '"' + readV + '" (read view)')
  ];
  // Write column 6 to the write view, or clear it for a read-only mode.
  accVb.push(vbOctet(`${VACM_ACCESS}.6.${ag}`, writeV, writeV ? ('"' + writeV + '" (write view)') : '(cleared: read-only)'));
  accVb.push(vbOctet(`${VACM_ACCESS}.7.${ag}`, readV, '"' + readV + '" (notify view)'));
  // Row already exists: set it active rather than createAndGo.
  accVb.push(vbInt(`${VACM_ACCESS}.8.${ag}`, 3, '3 (nonVolatile)'));
  return { community: name, steps: [
    { title: 'Update community access mode and view (vacmAccessTable)', required: false, varbinds: accVb }
  ], warnings: ['The access row (vacmAccessTable) may be read-only over SNMP on some firmware; if the write is skipped the community keeps its current access.'] };
}
module.exports.planModifyCommunity = planModifyCommunity;

// ---- group view modify (the headline feature) ----
async function planModifyGroup(snmp, r) {
  const group = Buffer.from(String((r || {}).group || '').trim(), 'latin1');
  if (!group.length || group.length > 32) throw new Error('Group name must be 1 to 32 characters.');
  const levels = (r || {}).levels || {};
  if (!Object.keys(levels).length) throw new Error('No view changes were provided.');

  // view-name validation against the switch
  let viewNames = new Set();
  try {
    for (const [, v] of tableRows(await snmp.walk(VACM_VIEWS), VACM_VIEWS)) {
      const raw = Buffer.from(v.idx); const nlen = raw[0];
      viewNames.add(raw.slice(1, 1 + nlen).toString('latin1'));
    }
  } catch (e) {}
  const check = (v) => { if (v && viewNames.size && !viewNames.has(v)) throw new Error(`View '${v}' does not exist on the switch.`); };

  const ig = Buffer.concat([Buffer.from('G_', 'latin1'), group]);
  const existing = new Set();
  try {
    for (const [, a] of tableRows(await snmp.walk(VACM_ACCESS), VACM_ACCESS)) {
      const raw = Buffer.from(a.idx); const glen = raw[0];
      if (raw.slice(1, 1 + glen).equals(ig)) existing.add(a.idx[a.idx.length - 1]);
    }
  } catch (e) {}

  const steps = [];
  for (const lvlName of ['noAuthNoPriv', 'authNoPriv', 'authPriv']) {
    const spec = levels[lvlName];
    if (spec == null) continue;
    const read = (spec.read || '').trim(), write = (spec.write || '').trim(), notify = (spec.notify || '').trim();
    check(read); check(write); check(notify);
    const lvl = SEC_LEVEL_SET[lvlName];
    const ai = idxStr([ig.length, ...ig, 0, 3, lvl]);
    const hasRow = existing.has(lvl);
    const anyView = !!(read || write || notify);
    if (hasRow && anyView) {
      steps.push({ title: `Update the ${lvlName} views (vacmAccessTable)`, required: false, varbinds: [
        vbOctet(`${VACM_ACCESS}.5.${ai}`, read, read ? '"' + read + '" (read)' : '(empty)'),
        vbOctet(`${VACM_ACCESS}.6.${ai}`, write, write ? '"' + write + '" (write)' : '(empty)'),
        vbOctet(`${VACM_ACCESS}.7.${ai}`, notify, notify ? '"' + notify + '" (notify)' : '(empty)')] });
    } else if (!hasRow && anyView) {
      steps.push({ title: `Create the ${lvlName} access row (vacmAccessTable)`, required: false, varbinds: [
        vbInt(`${VACM_ACCESS}.4.${ai}`, 1, '1 (contextMatch: exact)'),
        vbOctet(`${VACM_ACCESS}.5.${ai}`, read, read ? '"' + read + '" (read)' : '(empty)'),
        vbOctet(`${VACM_ACCESS}.6.${ai}`, write, write ? '"' + write + '" (write)' : '(empty)'),
        vbOctet(`${VACM_ACCESS}.7.${ai}`, notify, notify ? '"' + notify + '" (notify)' : '(empty)'),
        vbInt(`${VACM_ACCESS}.8.${ai}`, 3, '3 (nonVolatile)'),
        vbInt(`${VACM_ACCESS}.9.${ai}`, 4, '4 (createAndGo)')] });
    } else if (hasRow && !anyView) {
      steps.push({ title: `Remove the ${lvlName} access row (all views cleared)`, required: false,
        varbinds: [vbInt(`${VACM_ACCESS}.9.${ai}`, 6, '6 (destroy)')] });
    }
  }
  if (!steps.length) throw new Error('No changes to apply — the views are unchanged.');
  return { group: group.toString('latin1'), steps,
    warnings: ['vacmAccessTable may be read-only over SNMP on some switches; a write failure is reported.'] };
}
module.exports.planModifyGroup = planModifyGroup;

// ---- generic deletes (destroy the RowStatus column of a row's tables) ----
// Faithful port of the original plan_delete (recipient branch): removes the
// notify rows selected by this target's tag, the community mapping row, the
// target address row, and the security-parameters row — but keeps any row
// that another recipient also uses, with a warning. A row the switch did not
// return is still destroyed on a best-effort basis (not required).
function tagsOf(tagList) {
  const tags = tagList ? [tagList] : [];
  for (const t of tagList.split(/\s+/)) if (t && !tags.includes(t)) tags.push(t);
  return tags;
}
async function planDeleteRecipient(snmp, key) {
  const idx = String((key || {}).index || '');
  if (!idx) throw new Error('Invalid recipient reference.');

  const addr = tableRows(await snmp.walk(TARGET_ADDR), TARGET_ADDR);
  const row = addr.get(idx);
  if (!row) throw new Error('This recipient no longer exists on the switch. List the recipients again.');

  const steps = [], warnings = [];
  const nameB = Buffer.from(row.idx);
  const taddr = row.cols[3] != null ? valBytes(row.cols[3]) : Buffer.alloc(0);
  const ip = taddr.length >= 4 ? [...taddr.slice(0, 4)].join('.') : '';
  const wholeTag = row.cols[6] != null ? valBytes(row.cols[6]).toString('latin1') : '';
  const tags = tagsOf(wholeTag);

  // other target rows (to detect shared rows we must keep)
  const others = [];
  for (const [k, cc] of addr) if (k !== idx) others.push(cc);
  const otherUsesTag = (tag) => others.some((cc) => cc.cols[6] != null && tagsOf(valBytes(cc.cols[6]).toString('latin1')).includes(tag));

  let paramRows = new Map(); try { paramRows = tableRows(await snmp.walk(TARGET_PARAMS), TARGET_PARAMS); } catch (e) {}
  let notifyRows = new Map(); try { notifyRows = tableRows(await snmp.walk(NOTIFY), NOTIFY); } catch (e) {}
  let commRows = new Map(); try { commRows = tableRows(await snmp.walk(COMMUNITY), COMMUNITY); } catch (e) {}

  // 1. notify rows selected by this target's tag (unless shared)
  for (const [, nc] of notifyRows) {
    const ntag = nc.cols[2] != null ? valBytes(nc.cols[2]).toString('latin1') : '';
    if (!tags.includes(ntag)) continue;
    if (otherUsesTag(ntag)) { warnings.push('A notification row is also used by another recipient; it is kept.'); continue; }
    steps.push({ title: 'Remove the notification row (snmpNotifyTable)', required: true,
      varbinds: [vbInt(`${NOTIFY}.5.${nc.idx.join('.')}`, 6, '6 (destroy)')] });
  }
  if (!notifyRows.size) {
    // notify table not readable: try the row that shares this recipient's name
    steps.push({ title: 'Remove the notification row with the same name (snmpNotifyTable)', required: false,
      varbinds: [vbInt(`${NOTIFY}.5.${idx}`, 6, '6 (destroy)')] });
  }

  // 2. community mapping row (by whole tag, unless shared)
  for (const [, cc] of commRows) {
    const ttag = cc.cols[6] != null ? valBytes(cc.cols[6]).toString('latin1') : '';
    if (!ttag || ttag !== wholeTag) continue;
    if (otherUsesTag(ttag)) { warnings.push('A community mapping row is also used by another recipient; it is kept.'); continue; }
    steps.push({ title: 'Remove the community mapping row (snmpCommunityTable)', required: true,
      varbinds: [vbInt(`${COMMUNITY}.8.${cc.idx.join('.')}`, 6, '6 (destroy)')] });
  }

  // 3. the target address row itself
  steps.push({ title: 'Remove the target address row (snmpTargetAddrTable)', required: true,
    varbinds: [vbInt(`${TARGET_ADDR}.9.${idx}`, 6, '6 (destroy)')] });

  // 4. the security-parameters row (by its name, unless shared)
  const pName = row.cols[7] != null ? valBytes(row.cols[7]) : Buffer.alloc(0);
  if (pName.length) {
    let pIdx = [...pName].join('.');
    if (!paramRows.get(pIdx) && paramRows.get([pName.length, ...pName].join('.'))) pIdx = [pName.length, ...pName].join('.');
    const shared = others.some((cc) => cc.cols[7] != null && valBytes(cc.cols[7]).equals(pName));
    if (shared) {
      warnings.push(`The security parameters row ${showName(pName)} is also used by another recipient; it is kept.`);
    } else {
      const present = !!paramRows.get(pIdx);
      steps.push({ title: 'Remove the security parameters row (snmpTargetParamsTable)', required: present,
        varbinds: [vbInt(`${TARGET_PARAMS}.7.${pIdx}`, 6, '6 (destroy)')] });
      if (!present) warnings.push(`The switch did not return the parameters row ${showName(pName)}; deleting it is attempted, and a failure there is not treated as an error.`);
    }
  }

  return { title: `recipient ${ip || showName(nameB)}`, steps, warnings };
}
module.exports.planDeleteRecipient = planDeleteRecipient;

// Apply a plan: run each step's varbinds as one SET. Returns {ok, log}.
async function applyPlan(snmp, plan) {
  const log = [];
  for (const step of plan.steps || []) {
    const err = await snmp.set(step.varbinds.map((v) => ({ oid: v.oid, type: v.type, value: v.value })));
    if (err == null) { log.push({ title: step.title, ok: true, detail: 'SET accepted' }); continue; }
    if (step.required === false) { log.push({ title: step.title, ok: true, detail: 'Skipped (' + err + '). Not required; continuing.' }); continue; }
    if (/authorizationError|notWritable|noAccess/.test(err)) {
      log.push({ title: step.title, ok: false,
        detail: err + '. The credential has no write view — connect with an SNMP Admin / read-write credential (a DefaultSuper write view).' });
      return { ok: false, log };
    }
    log.push({ title: step.title, ok: false, detail: 'SET failed: ' + err });
    return { ok: false, log };
  }
  return { ok: true, log };
}
module.exports.applyPlan = applyPlan;

// -------------------------------------------------------- access check
//
// The app already proves reachability (its ping probe and the "not
// answering SNMP" state), so this does NOT re-check that. It answers the
// one question specific to configuration: does the connected credential
// have SNMP-Admin (DefaultSuper) access? Without the DefaultSuper read view
// the config tables are hidden; without a DefaultSuper write view, adds and
// deletes are refused. The module uses this to tell the user up front which
// features are available rather than letting them fail mid-action.
//
// Returns { level, readable, writable, group, summary } where level is
// 'full' (read+write, everything works), 'readonly' (can view but not
// change), or 'limited' (config tables hidden — little to show).
async function accessCheck(snmp, meta) {
  let readable = false, writable = null, group = null, detail = '';
  try {
    const rows = tableRows(await snmp.walk(COMMUNITY), COMMUNITY);
    readable = rows.size > 0;
  } catch (e) { readable = false; }

  if (readable) {
    try {
      const [ok, d] = await writeViewFor(snmp, meta);
      writable = ok; detail = d;
      const m = /group '([^']+)'/.exec(d || '');
      if (m) group = m[1];
    } catch (e) { writable = null; detail = e.message; }
  }

  const who = (meta && meta.version && meta.version !== '3') ? 'community' : 'user';
  let level, summary;
  if (!readable) {
    level = 'limited';
    summary = `This ${who} is not an SNMP Admin (DefaultSuper): the SNMP configuration tables are hidden from it, so recipients, communities, groups and users cannot be shown. Connect with a DefaultSuper ${who} to use these features.`;
  } else if (writable === false) {
    level = 'readonly';
    summary = `This ${who} can view SNMP configuration but is not an SNMP Admin (no DefaultSuper write view), so adding, editing and deleting are unavailable. Connect with a DefaultSuper ${who} to make changes.`;
  } else {
    level = 'full';
    summary = writable
      ? `This ${who} has SNMP Admin (DefaultSuper) access — all configuration features are available.`
      : `This ${who} can view SNMP configuration; making changes needs a DefaultSuper write view.`;
  }
  return { level, readable, writable, group, detail, summary };
}
module.exports.accessCheck = accessCheck;

async function writeViewFor(snmp, meta) {
  const s2g = tableRows(await snmp.walk(VACM_S2G), VACM_S2G);
  const acc = tableRows(await snmp.walk(VACM_ACCESS), VACM_ACCESS);
  const candidates = [];
  if (meta && meta.version && meta.version !== '3') {
    const want = Buffer.from('SNR-' + (meta.community || ''), 'latin1');
    for (const [, g] of s2g) {
      const raw = Buffer.from(g.idx);
      if (raw.length >= 2 && raw.slice(2, 2 + want.length).equals(want) && g.cols[3] != null) candidates.push(valBytes(g.cols[3]));
    }
  } else {
    const uname = Buffer.from((meta && meta.user) || '', 'latin1');
    for (const [, g] of s2g) {
      const raw = Buffer.from(g.idx);
      if (raw.length >= 2 && raw[0] === 3 && raw.slice(2).equals(uname) && g.cols[3] != null) candidates.push(valBytes(g.cols[3]));
    }
  }
  if (!candidates.length) return [null, 'could not resolve this credential\u2019s group'];
  for (const grp of candidates) {
    for (const [, a] of acc) {
      const raw = Buffer.from(a.idx); const glen = raw[0];
      if (raw.slice(1, 1 + glen).equals(grp)) {
        const wv = a.cols[6] != null ? valBytes(a.cols[6]) : Buffer.alloc(0);
        if (wv.length) return [true, `group '${showName(grp)}' has write view '${wv.toString('latin1')}'`];
      }
    }
  }
  return [false, `group '${showName(candidates[0])}' has an empty write view — reads work but writes fail`];
}

// Check snmpTargetAddrTable for rows the switch cannot turn into a UDP
// address. A row with a transport domain (col 2) but a TAddress (col 3) that
// is not exactly 6 bytes for snmpUDPDomain (or 18 for UDP/IPv6) is malformed:
// the switch's own TDomainAndTAddress2UdpAddress conversion fails on it, which
// is logged as %SNMP-F-BADTDOMAIN and can destabilise config processing. Such
// rows are usually the debris of a write that was interrupted (e.g. by an
// earlier crash). Returns a list of { name, index, domain, taddrLen, reason }.
async function checkTargetRows(snmp) {
  const bad = [];
  let rows;
  try { rows = tableRows(await snmp.walk(TARGET_ADDR), TARGET_ADDR); }
  catch (e) { return { bad, error: e.message }; }
  const UDP4 = '1.3.6.1.6.1.1', UDP4B = '1.3.6.1.2.1.100.1.1';
  const UDP6 = '1.3.6.1.2.1.100.1.2', UDP6Z = '1.3.6.1.2.1.100.1.4';
  for (const [, row] of rows) {
    const nameB = Buffer.from(row.idx);
    const name = showName(nameB);
    const domain = row.cols[2] != null ? valOidStr(row.cols[2]) : '';
    const taddr = row.cols[3] != null ? valBytes(row.cols[3]) : Buffer.alloc(0);
    const status = row.cols[9] != null ? valInt(row.cols[9]) : null;
    let reason = '';
    if (domain && (domain === UDP4 || domain === UDP4B)) {
      if (taddr.length !== 6) reason = `IPv4 transport domain but TAddress is ${taddr.length} byte(s), not 6`;
    } else if (domain && (domain === UDP6 || domain === UDP6Z)) {
      if (taddr.length !== 18 && taddr.length !== 20) reason = `IPv6 transport domain but TAddress is ${taddr.length} byte(s)`;
    } else if (domain) {
      reason = `unrecognised transport domain ${domain}`;
    } else if (taddr.length) {
      reason = 'TAddress set but transport domain missing';
    }
    if (reason) {
      bad.push({ name, index: row.idx.join('.'), domain, taddrLen: taddr.length, status, reason,
        destroyOid: `${TARGET_ADDR}.9.${row.idx.join('.')}` });
    }
  }
  return { bad };
}
module.exports.checkTargetRows = checkTargetRows;

module.exports.writeViewFor = writeViewFor;

// ============================================================ more writes
// Ports of the original tool's recipient-add, community-delete,
// group-add and user-delete. Kept faithful to the firmware-specific
// formats the original discovered (the "TR-" name, the 8-byte-per-octet
// tag, the SSNR-/SNR-/InR- community rows).

const ADD_VERSIONS = { '1': [0, 1], '2c': [1, 2], '3': [3, 3] };  // -> [MPModel, SecModel]
const NATIVE_PREFIX = Buffer.from('TR-', 'latin1');

function ipv4Packed(ip) {
  const parts = String(ip).trim().split('.').map((x) => parseInt(x, 10));
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) throw new Error('Enter a valid IPv4 address for the recipient.');
  return Buffer.from(parts);
}
function recipientName(ipBuf) { return Buffer.concat([NATIVE_PREFIX, ipBuf]); }
// tag = "TR-" + 8 zero bytes + each IP octet as 8 big-endian bytes + community
function nativeTag(ipBuf, secName) {
  const octets = Buffer.concat([...ipBuf].map((o) => { const b = Buffer.alloc(8); b[7] = o; return b; }));
  return Buffer.concat([NATIVE_PREFIX, Buffer.alloc(8), octets, secName]);
}

// ---- recipient add ----
async function planAddRecipient(snmp, r) {
  const ipBuf = ipv4Packed((r || {}).ip);
  const ip = [...ipBuf].join('.');
  const port = parseInt((r || {}).port || 162, 10);
  if (!(port >= 1 && port <= 65535)) throw new Error('UDP port must be 1-65535.');
  const ntype = (r || {}).ntype || 'trap';
  const ver = (r || {}).version || '2c';
  if (!ADD_VERSIONS[ver]) throw new Error('Unknown SNMP version.');
  if (ntype === 'inform' && ver === '1') throw new Error('SNMPv1 cannot send informs. Choose traps or SNMPv2c/v3.');

  let secName, level;
  if (ver === '1' || ver === '2c') {
    secName = Buffer.from((r.community || ''), 'latin1');
    level = 1;
    if (!secName.length) throw new Error('Enter the community string the switch should use in notifications.');
  } else {
    secName = Buffer.from(((r.user || '').trim()), 'latin1');
    level = SEC_LEVEL_SET[(r.level || 'authPriv')] || 3;
    if (!secName.length) throw new Error('Enter the SNMPv3 user the switch should use (it must already exist on the switch).');
  }
  let timeout = 0, retries = 0;
  if (ntype === 'inform') { timeout = Math.round(parseFloat(r.timeout || 15) * 100); retries = parseInt(r.retries || 3, 10); }

  const name = recipientName(ipBuf);
  const idx = idxStr([...name]);                 // IMPLIED index: the name bytes, no length prefix
  const tag = nativeTag(ipBuf, secName);
  const [mp, sm] = ADD_VERSIONS[ver];

  // refuse if the recipient already exists (any of the three rows)
  for (const [base, col] of [[TARGET_ADDR, 9], [TARGET_PARAMS, 7], [NOTIFY, 5]]) {
    try {
      const g = await snmp.get([`${base}.${col}.${idx}`]);
      if (g && g[0] && g[0].value != null && valInt(g[0].value) != null) {
        throw new Error(`A recipient row for ${ip} already exists. Remove it first.`);
      }
    } catch (e) { if (/already exists/.test(e.message)) throw e; }
  }
  // also refuse if any target row already points at this address
  try {
    for (const [, row] of tableRows(await snmp.walk(TARGET_ADDR), TARGET_ADDR)) {
      if (row.cols[3] != null && valBytes(row.cols[3]).slice(0, 4).equals(ipBuf)) {
        const p = (valBytes(row.cols[3])[4] << 8) | valBytes(row.cols[3])[5];
        throw new Error(`The switch already has a target row for ${ip} (port ${p}). Remove it first.`);
      }
    }
  } catch (e) { if (/already has a target/.test(e.message)) throw e; }

  const taddr = Buffer.concat([ipBuf, Buffer.from([(port >> 8) & 0xFF, port & 0xFF])]);
  const pSec = (ver === '1' || ver === '2c') ? name : secName;   // params security name = "TR-"+IP for v1/v2c

  const steps = [
    { title: 'Create the security parameters row (snmpTargetParamsTable)', required: true, varbinds: [
      vbInt(`${TARGET_PARAMS}.2.${idx}`, mp, `${mp} (${MP_MODEL[mp]})`),
      vbInt(`${TARGET_PARAMS}.3.${idx}`, sm, `${sm} (secModel)`),
      vbOctet(`${TARGET_PARAMS}.4.${idx}`, pSec, (ver === '1' || ver === '2c') ? showName(pSec) + ' (links to the community row)' : '"' + secName.toString('latin1') + '"'),
      vbInt(`${TARGET_PARAMS}.5.${idx}`, level, `${level} (${SEC_LEVEL[level]})`),
      vbInt(`${TARGET_PARAMS}.6.${idx}`, 3, '3 (nonVolatile)'),
      vbInt(`${TARGET_PARAMS}.7.${idx}`, 4, '4 (createAndGo)')] },
    { title: 'Create the target address row (snmpTargetAddrTable)', required: true, varbinds: [
      vbOid(`${TARGET_ADDR}.2.${idx}`, SNMP_UDP_DOMAIN, SNMP_UDP_DOMAIN + ' (snmpUDPDomain)'),
      vbOctet(`${TARGET_ADDR}.3.${idx}`, taddr, `${ip} port ${port}`),
      vbInt(`${TARGET_ADDR}.4.${idx}`, timeout, `${timeout} (${timeout / 100} s)`),
      vbInt(`${TARGET_ADDR}.5.${idx}`, retries),
      vbOctet(`${TARGET_ADDR}.6.${idx}`, tag, 'tag'),
      vbOctet(`${TARGET_ADDR}.7.${idx}`, name, showName(name)),
      vbInt(`${TARGET_ADDR}.8.${idx}`, 3, '3 (nonVolatile)'),
      vbInt(`${TARGET_ADDR}.9.${idx}`, 4, '4 (createAndGo)')] },
    { title: 'Create the notification row (snmpNotifyTable)', required: true, varbinds: [
      vbOctet(`${NOTIFY}.2.${idx}`, tag, 'tag'),
      vbInt(`${NOTIFY}.3.${idx}`, ntype === 'trap' ? 1 : 2, `${ntype === 'trap' ? 1 : 2} (${ntype})`),
      vbInt(`${NOTIFY}.4.${idx}`, 3, '3 (nonVolatile)'),
      vbInt(`${NOTIFY}.5.${idx}`, 4, '4 (createAndGo)')] }
  ];

  const warnings = [];
  if (ver === '1' || ver === '2c') {
    // community-mapping row (snmpCommunityTable): index = name = "TR-"+IP,
    // snmpCommunityName = community, security name = "TR-"+IP (= params sec),
    // engine ID = local snmpEngineID, tag = the target's tag.
    let engine = Buffer.alloc(0);
    try { const g = await snmp.get([ENGINE_ID]); if (g && g[0] && g[0].value != null) engine = valBytes(g[0].value); } catch (e) {}
    const ci = idxStr([...name]);
    const cvb = [
      vbOctet(`${COMMUNITY}.2.${ci}`, secName, `<community, ${secName.length} chars>`),
      vbOctet(`${COMMUNITY}.3.${ci}`, pSec, showName(pSec) + ' (same as snmpTargetParamsSecurityName)')
    ];
    if (engine.length) cvb.push(vbOctet(`${COMMUNITY}.4.${ci}`, engine, hexOf(engine) + ' (snmpEngineID)'));
    cvb.push(vbOctet(`${COMMUNITY}.5.${ci}`, Buffer.alloc(0), '(empty)'));
    cvb.push(vbOctet(`${COMMUNITY}.6.${ci}`, tag, "the recipient's tag"));
    cvb.push(vbInt(`${COMMUNITY}.7.${ci}`, 3, '3 (nonVolatile)'));
    cvb.push(vbInt(`${COMMUNITY}.8.${ci}`, 4, '4 (createAndGo)'));
    steps.push({ title: 'Create the community mapping row (snmpCommunityTable)', required: true, varbinds: cvb });
  }
  if (ver === '3') warnings.push(`SNMPv3 notifications use the user '${secName.toString('latin1')}'; it must already exist on the switch.`);

  return { ip, port, name: showName(name), steps, warnings };
}
module.exports.planAddRecipient = planAddRecipient;

// ---- community delete ----
async function planDeleteCommunity(snmp, key) {
  const src = (key || {}).source;
  const idx = String((key || {}).index || '');
  if (!idx) throw new Error('Invalid row reference.');
  const idxArr = idx.split('.').map(Number);
  const steps = [], warnings = [];

  if (src === 'snmpComm') {
    const rows = tableRows(await snmp.walk(COMMUNITY), COMMUNITY);
    const row = rows.get(idx);
    if (!row) throw new Error('This community no longer exists on the switch. List the communities again.');
    const name = row.cols[2] != null ? valBytes(row.cols[2]) : Buffer.alloc(0);
    const sec = row.cols[3] != null ? valBytes(row.cols[3]) : Buffer.alloc(0);
    const secs = [sec, name].filter((b) => b.length);

    let s2g = new Map(); try { s2g = tableRows(await snmp.walk(VACM_S2G), VACM_S2G); } catch (e) {}
    let access = new Map(); try { access = tableRows(await snmp.walk(VACM_ACCESS), VACM_ACCESS); } catch (e) {}

    const groups = new Set(); const s2gToDel = [];
    for (const [giKey, gc] of s2g) {
      const giBytes = Buffer.from(gc.idx);
      if (secs.some((sn) => giBytes.includes(sn))) {
        s2gToDel.push(gc.idx);
        if (gc.cols[3] != null) groups.add(valBytes(gc.cols[3]).toString('latin1'));
      }
    }
    const shared = new Set();
    for (const [, gc] of s2g) {
      if (s2gToDel.some((d) => d.join('.') === gc.idx.join('.'))) continue;
      if (gc.cols[3] != null && groups.has(valBytes(gc.cols[3]).toString('latin1'))) shared.add(valBytes(gc.cols[3]).toString('latin1'));
    }
    for (const [, ac] of access) {
      const raw = Buffer.from(ac.idx); const glen = raw[0];
      const g = raw.slice(1, 1 + glen).toString('latin1');
      if (groups.has(g) && !shared.has(g)) {
        steps.push({ title: `Remove group access (vacmAccessTable, ${g})`, required: false,
          varbinds: [vbInt(`${VACM_ACCESS}.9.${ac.idx.join('.')}`, 6, '6 (destroy)')] });
      }
    }
    for (const gi of s2gToDel) {
      steps.push({ title: 'Remove security-to-group mapping (vacmSecurityToGroupTable)', required: false,
        varbinds: [vbInt(`${VACM_S2G}.5.${gi.join('.')}`, 6, '6 (destroy)')] });
    }
    // allowed-manager binding rows: BOTH the IPv4 "InR-<4 bytes><community>"
    // and the IPv6 "InV6R-<4 bytes><community>" rows (the matched pair the
    // switch creates). Match either prefix, then confirm the trailing bytes
    // are exactly the community name.
    try {
      for (const [, ar] of tableRows(await snmp.walk(TARGET_ADDR), TARGET_ADDR)) {
        const nm = Buffer.from(ar.idx);
        let pfx = null;
        if (nm.slice(0, 4).toString('latin1') === 'InR-') pfx = 4;
        else if (nm.slice(0, 6).toString('latin1') === 'InV6R-') pfx = 6;
        if (pfx !== null && nm.slice(pfx + 4).equals(name)) {   // prefix + 4 addr bytes + name
          steps.push({ title: `Remove the manager binding (snmpTargetAddrTable, ${showName(nm)})`, required: false,
            varbinds: [vbInt(`${TARGET_ADDR}.9.${ar.idx.join('.')}`, 6, '6 (destroy)')] });
        }
      }
    } catch (e) {}
    steps.push({ title: 'Remove the community row (snmpCommunityTable)', required: true,
      varbinds: [vbInt(`${COMMUNITY}.8.${idx}`, 6, '6 (destroy)')] });
    return { title: `community '${name.toString('latin1')}'`, steps, warnings };
  }

  // Cisco private tables: invalidate the row (status -> 2)
  const base = src === 'rndInet' ? RND_COMM_INET : RND_COMM_V4;
  const col = src === 'rndInet' ? 6 : 5;
  const rows = tableRows(await snmp.walk(base), base);
  if (!rows.get(idx)) throw new Error('This community no longer exists on the switch. List the communities again.');
  steps.push({ title: 'Invalidate the community row', required: true,
    varbinds: [vbInt(`${base}.${col}.${idx}`, 2, '2 (invalid: deletes the row)')] });
  warnings.push("Deleting this row removes that community's SNMP access for the station.");
  return { title: 'community row', steps, warnings };
}
module.exports.planDeleteCommunity = planDeleteCommunity;

// ---- v3 group add ----
async function planAddGroup(snmp, r) {
  const group = Buffer.from(((r || {}).group || '').trim(), 'latin1');
  if (!(group.length >= 1 && group.length <= 32)) throw new Error('Group name must be 1 to 32 characters.');
  const levels = (r || {}).levels || {};
  if (!Object.keys(levels).length) throw new Error('Enter at least one view for at least one security level.');

  let viewNames = new Set();
  try {
    for (const [, v] of tableRows(await snmp.walk(VACM_VIEWS), VACM_VIEWS)) {
      const raw = Buffer.from(v.idx); const nlen = raw[0];
      viewNames.add(raw.slice(1, 1 + nlen).toString('latin1'));
    }
  } catch (e) {}
  const check = (v) => { if (v && viewNames.size && !viewNames.has(v)) throw new Error(`View '${v}' does not exist on the switch.`); };

  const ig = Buffer.concat([Buffer.from('G_', 'latin1'), group]);
  const steps = []; const configured = [];
  for (const lvlName of ['noAuthNoPriv', 'authNoPriv', 'authPriv']) {
    const spec = levels[lvlName];
    if (!spec) continue;
    const read = (spec.read || '').trim(), write = (spec.write || '').trim(), notify = (spec.notify || '').trim();
    if (!(read || write || notify)) continue;
    check(read); check(write); check(notify);
    const lvl = SEC_LEVEL_SET[lvlName];
    const ai = idxStr([ig.length, ...ig, 0, 3, lvl]);
    steps.push({ title: `Create the ${lvlName} access row (vacmAccessTable)`, required: false, varbinds: [
      vbInt(`${VACM_ACCESS}.4.${ai}`, 1, '1 (contextMatch: exact)'),
      vbOctet(`${VACM_ACCESS}.5.${ai}`, read, read ? '"' + read + '" (read)' : '(empty)'),
      vbOctet(`${VACM_ACCESS}.6.${ai}`, write, write ? '"' + write + '" (write)' : '(empty)'),
      vbOctet(`${VACM_ACCESS}.7.${ai}`, notify, notify ? '"' + notify + '" (notify)' : '(empty)'),
      vbInt(`${VACM_ACCESS}.8.${ai}`, 3, '3 (nonVolatile)'),
      vbInt(`${VACM_ACCESS}.9.${ai}`, 4, '4 (createAndGo)')] });
    configured.push(lvlName);
  }
  if (!steps.length) throw new Error('Enter at least one view (Read, Write or Notify) for at least one security level.');
  return { group: group.toString('latin1'), levels: configured, steps,
    warnings: ['vacmAccessTable may be read-only over SNMP on some switches; a failed row is skipped. A group becomes usable once a user is mapped to it.'] };
}
module.exports.planAddGroup = planAddGroup;

// ---- v3 user delete ----
async function planDeleteUser(snmp, key) {
  const idx = String((key || {}).index || '');
  if (!idx) throw new Error('Invalid user reference.');
  const idxArr = idx.split('.').map(Number);
  const users = tableRows(await snmp.walk(USM_USER), USM_USER);
  if (!users.get(idx)) throw new Error('This user no longer exists on the switch.');
  const elen = idxArr[0];
  const name = Buffer.from(idxArr.slice(1 + elen + 1));  // after engineLen, engine, nameLen
  const steps = [{ title: 'Remove the user row (usmUserTable)', required: true,
    varbinds: [vbInt(`${USM_USER}.13.${idx}`, 6, '6 (destroy)')] }];
  // remove its security-to-group mapping (model 3, name)
  try {
    const s2g = tableRows(await snmp.walk(VACM_S2G), VACM_S2G);
    const gi = [3, name.length, ...name];
    if (s2g.get(gi.join('.'))) {
      steps.unshift({ title: "Remove the user's group mapping (vacmSecurityToGroupTable)", required: false,
        varbinds: [vbInt(`${VACM_S2G}.5.${gi.join('.')}`, 6, '6 (destroy)')] });
    }
  } catch (e) {}
  return { title: `user '${name.toString('latin1')}'`, steps, warnings: [] };
}
module.exports.planDeleteUser = planDeleteUser;

// Flag the community or SNMPv3 user this app is connected with, so the panel
// can leave out its Delete: the switch refuses to delete the credential in use.
function markInUse(result, listKey, field, current) {
  if (current && result && Array.isArray(result[listKey])) {
    for (const row of result[listKey]) if (row && row[field] === current) row.inUse = true;
  }
  return result;
}
module.exports.markInUse = markInUse;

/**
 * Everything the SNMP configuration panel shows, in one pass: the access check
 * and the six lists, in the shape the panel keeps (`{ access, recips, comms,
 * groups, users, tcheck, views }`, each `{ ok, ... }` as its route answers).
 * The lists share tables (the community table is read by four of them, the
 * VACM tables by three), so each table is walked ONCE and the walk reused:
 * 9 walks instead of 19. Read by the server collector on a settings change
 * (SERVER-STANDARD §3); the per-list routes stay for a write's targeted re-read.
 * `meta` is { version, community, user } of the credential in use.
 */
async function readAll(snmp, meta) {
  const walks = new Map();
  const S = Object.assign({}, snmp, {
    walk: (base) => {
      if (!walks.has(base)) walks.set(base, Promise.resolve(snmp.walk(base)));
      return walks.get(base).then((rows) => (Array.isArray(rows) ? rows.slice() : rows));
    }
  });
  const run = async (fn) => {
    try { return { ok: true, ...(await fn()) }; } catch (e) { return { ok: false, error: e.message }; }
  };
  const v3 = meta && meta.version === '3';
  const d = { access: await run(() => accessCheck(S, meta)) };
  // A credential that cannot read the config tables gets only the banner.
  if (d.access.ok && d.access.level === 'limited') return d;
  d.recips = await run(() => listRecipients(S, {}));
  d.comms = await run(async () => markInUse(await listCommunities(S), 'communities', 'community', !v3 && meta && meta.community));
  d.groups = await run(() => listGroups(S));
  d.users = await run(async () => markInUse(await listUsers(S), 'users', 'name', v3 && meta && meta.user));
  d.tcheck = await run(() => checkTargetRows(S));
  d.views = await run(() => listViewNames(S));
  return d;
}
module.exports.readAll = readAll;
