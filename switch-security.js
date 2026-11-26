'use strict';

/**
 * Switching security over SNMP: IGMP and MLD snooping, the IGMP snooping
 * querier, DHCP snooping and ARP inspection. Each write is encoded from the
 * rows the switch itself made (docs/SWITCH-NOTES.md, "Switching security");
 * nothing here saves the configuration.
 *
 * Objects (vendor root V = 1.3.6.1.4.1.9.6.1.101):
 *   rlIgmpSnoop V.55.2: .2 Enable, .3 HostAgingTime, .4 RouterAgingTime,
 *     .13 QuerierEnable; .12.1 querier per VLAN (VLAN; .2 AdminEnable,
 *     .3 OperEnable, .4 AdminAddr, .5 OperAddr, .6 AdminVersion,
 *     .7 OperVersion, .8 ElectionEnable)
 *   rlIgmpMldSnoop V.55.5: .1 MldEnable; .5.1 VLAN table (address type 1
 *     IPv4 / 2 IPv6, VLAN; .3 Enable, .4 RouterLearn, .9 Version,
 *     .10 RouterPortlist, .34 ImmediateLeave); .4.1 groups (VLAN, type,
 *     group, type, source; .6 IncPortlist, .7 ExcPortlist, .8 ExpiryTime,
 *     .9 CompatibilityMode)
 *   rlIpDhcpSnoop V.112.1: .2 Enable, .3 FileEnable, .6 VerifyMacAddress,
 *     .7 CurrentEntiresNumber; .12.1 VLANs (VLAN; .2 RowStatus); .13.1
 *     trusted ports (ifIndex; .2 RowStatus); .11.1 bindings (VLAN, MAC;
 *     .3 Type, .4 LeaseTime, .5 IPAddress, .6 PortInterface, .7 RowStatus)
 *   rlIpArpInspect V.112.3: .2 Enable, .3 LogInterval, .4 Validation;
 *     .6.1 VLANs (VLAN; .2 AssignedListName, .3 RowStatus, .4 Forwarded,
 *     .5 Dropped, .6 Mismatched); .7.1 trusted ports (ifIndex; .2 RowStatus);
 *     .5.1 lists (name as length + bytes, IP; .3 MAC, .4 RowStatus)
 *
 * The querier and snooping VLAN tables hold a row for every VLAN number,
 * 1 to 4094, so they are read by GET for the VLANs the switch has
 * (dot1qVlanStaticRowStatus), never walked.
 */

const snmp = require('net-snmp');
const { walkColumns, getRows } = require('./switch-ports');

const V = '1.3.6.1.4.1.9.6.1.101';
const IGMP = V + '.55.2';
const MLD = V + '.55.5';
const DHCP = V + '.112.1';
const ARP = V + '.112.3';
const QUERIER = IGMP + '.12.1';
const SNOOP_VLAN = MLD + '.5.1';
const GROUPS = MLD + '.4.1';
const DHCP_VLAN = DHCP + '.12.1';
const DHCP_TRUST = DHCP + '.13.1';
const BINDING = DHCP + '.11.1';
const ARP_LIST = ARP + '.5.1';
const ARP_VLAN = ARP + '.6.1';
const ARP_TRUST = ARP + '.7.1';
const VLAN_STATUS = '1.3.6.1.2.1.17.7.1.4.3.1.5';   // dot1qVlanStaticRowStatus

const SCALARS = {
  igmpEnable: IGMP + '.2.0',
  igmpHostAging: IGMP + '.3.0',
  igmpRouterAging: IGMP + '.4.0',
  igmpQuerierEnable: IGMP + '.13.0',
  mldEnable: MLD + '.1.0',
  dhcpEnable: DHCP + '.2.0',
  dhcpFile: DHCP + '.3.0',
  dhcpVerifyMac: DHCP + '.6.0',
  dhcpEntries: DHCP + '.7.0',
  arpEnable: ARP + '.2.0',
  arpLogInterval: ARP + '.3.0',
  arpValidation: ARP + '.4.0'
};

const FAMILY = { ipv4: 1, ipv6: 2 };
const BINDING_TYPE = { 1: 'learned', 2: 'expired', 3: 'static' };

const num = (v) => (v == null ? null : Number(v));
const truth = (v) => (v == null ? null : Number(v) === 1);
const text = (v) => (Buffer.isBuffer(v) ? v.toString('utf8') : (v == null ? '' : String(v))).replace(/\0+$/, '').trim();
const ipOf = (v) => (Buffer.isBuffer(v) && v.length === 4 ? Array.from(v).join('.') : (v == null ? null : String(v)));

// The bytes of an octet string: a Buffer from a GET, or the hex text a walk
// gives for one that is not printable ("10 00 00 00", "00:00:5E:00:53:23").
function bytesOf(v) {
  if (Buffer.isBuffer(v)) return v;
  if (typeof v !== 'string' || !/^[0-9a-f]{2}([ :-]?[0-9a-f]{2})*$/i.test(v.trim())) return null;
  return Buffer.from(v.trim().replace(/[ :-]/g, ''), 'hex');
}
const macOf = (v) => { const b = Array.isArray(v) ? v : bytesOf(v); return b && b.length === 6 ? Array.from(b).map((x) => Number(x).toString(16).padStart(2, '0')).join(':') : null; };

// Ports in a PortList (bit 1 of byte 0 is port 1).
function portList(raw) {
  const v = bytesOf(raw);
  if (!v) return [];
  const out = [];
  for (let i = 0; i < v.length; i++) for (let b = 0; b < 8; b++) if (v[i] & (0x80 >> b)) out.push(i * 8 + b + 1);
  return out;
}

// An InetAddress as an index part: [length, ...bytes]. Resolves
// { addr, next } where next is the index of the arc after it.
function inetAt(arcs, at) {
  const len = arcs[at];
  const bytes = arcs.slice(at + 1, at + 1 + len);
  let addr = '';
  if (len === 4) addr = bytes.join('.');
  else if (len === 16) {
    const words = [];
    for (let i = 0; i < 16; i += 2) words.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
    // The longest run of two or more zero words becomes '::'.
    let best = -1, bestLen = 1;
    for (let i = 0; i < 8;) {
      if (words[i] !== '0') { i++; continue; }
      let j = i; while (j < 8 && words[j] === '0') j++;
      if (j - i > bestLen) { best = i; bestLen = j - i; }
      i = j;
    }
    addr = best < 0 ? words.join(':') : words.slice(0, best).join(':') + '::' + words.slice(best + bestLen).join(':');
  } else addr = bytes.join('.');
  return { addr, next: at + 1 + len };
}

function getChunk(session, oids) {
  return new Promise((resolve, reject) => {
    session.get(oids, (error, varbinds) => (error ? reject(error) : resolve(varbinds)));
  });
}

async function getScalars(session) {
  const names = Object.keys(SCALARS);
  const vbs = await getChunk(session, names.map((n) => SCALARS[n]));
  const out = {};
  names.forEach((n, k) => { const vb = vbs[k]; out[n] = (!vb || snmp.isVarbindError(vb)) ? undefined : vb.value; });
  return out;
}

/** The VLAN numbers the switch has, in order. */
async function switchVlans(session) {
  const rows = await walkColumns(session, VLAN_STATUS.replace(/\.5$/, ''), [5]);
  return rows.map((r) => r.index[0]).filter((n) => n >= 1 && n <= 4094).sort((a, b) => a - b);
}

/**
 * Everything the panel shows. Resolves { vlanIds, igmp, mld, dhcp, arp }; a
 * table the switch does not answer comes back empty.
 */
async function readSecurity(session) {
  const s = await getScalars(session);
  const safe = async (fn) => { try { return await fn(); } catch (e) { return []; } };
  const vlanIds = await safe(() => switchVlans(session));

  const snoop = await safe(() => getRows(session, SNOOP_VLAN, [3, 4, 9, 10, 34],
    vlanIds.flatMap((v) => [FAMILY.ipv4 + '.' + v, FAMILY.ipv6 + '.' + v])));
  const snoopRow = (r) => ({
    vlan: r.index[1], enabled: truth(r.cols[3]), routerLearn: truth(r.cols[4]), version: num(r.cols[9]),
    routerPorts: portList(r.cols[10]), immediateLeave: truth(r.cols[34])
  });
  const igmpVlans = snoop.filter((r) => r.index[0] === FAMILY.ipv4).map(snoopRow);
  const mldVlans = snoop.filter((r) => r.index[0] === FAMILY.ipv6).map(snoopRow);

  const queriers = (await safe(() => getRows(session, QUERIER, [2, 3, 4, 5, 6, 7, 8], vlanIds))).map((r) => ({
    vlan: r.index[0], enabled: truth(r.cols[2]), active: truth(r.cols[3]), address: ipOf(r.cols[4]),
    activeAddress: ipOf(r.cols[5]), version: num(r.cols[6]), activeVersion: num(r.cols[7]), election: truth(r.cols[8])
  }));

  const groups = (await safe(() => walkColumns(session, GROUPS, [6, 7, 8, 9]))).map((r) => {
    const a = r.index;
    const g = inetAt(a, 2);
    const src = inetAt(a, g.next + 1);
    return {
      vlan: a[0], family: a[1] === FAMILY.ipv6 ? 'ipv6' : 'ipv4', group: g.addr, source: src.addr,
      ports: portList(r.cols[6]), excluded: portList(r.cols[7]), expires: num(r.cols[8]), mode: num(r.cols[9])
    };
  });

  const dhcpVlans = (await safe(() => walkColumns(session, DHCP_VLAN, [2]))).map((r) => r.index[0]);
  const dhcpTrusted = (await safe(() => walkColumns(session, DHCP_TRUST, [2]))).map((r) => r.index[0]);
  const bindings = (await safe(() => walkColumns(session, BINDING, [3, 4, 5, 6]))).map((r) => ({
    vlan: r.index[0], mac: macOf(r.index.slice(1, 7)),
    type: BINDING_TYPE[num(r.cols[3])] || String(r.cols[3]), lease: num(r.cols[4]), ip: ipOf(r.cols[5]), ifIndex: num(r.cols[6])
  }));

  const arpVlans = (await safe(() => walkColumns(session, ARP_VLAN, [2, 4, 5, 6]))).map((r) => ({
    vlan: r.index[0], list: text(r.cols[2]),
    forwarded: num(r.cols[4]), dropped: num(r.cols[5]), mismatched: num(r.cols[6])
  }));
  const arpTrusted = (await safe(() => walkColumns(session, ARP_TRUST, [2]))).map((r) => r.index[0]);
  const arpLists = (await safe(() => walkColumns(session, ARP_LIST, [3]))).map((r) => {
    const a = r.index;
    const len = a[0];
    return {
      name: Buffer.from(a.slice(1, 1 + len)).toString('utf8'), ip: a.slice(1 + len, 5 + len).join('.'),
      mac: macOf(r.cols[3])
    };
  });

  return {
    vlanIds,
    igmp: { enabled: truth(s.igmpEnable), querier: truth(s.igmpQuerierEnable), hostAging: num(s.igmpHostAging),
      routerAging: num(s.igmpRouterAging), vlans: igmpVlans, queriers, groups: groups.filter((g) => g.family === 'ipv4') },
    mld: { enabled: truth(s.mldEnable), vlans: mldVlans, groups: groups.filter((g) => g.family === 'ipv6') },
    dhcp: { enabled: truth(s.dhcpEnable), file: s.dhcpFile == null ? null : Number(s.dhcpFile) === 1,
      verifyMac: s.dhcpVerifyMac == null ? null : Number(s.dhcpVerifyMac) === 1,
      entries: num(s.dhcpEntries), vlans: dhcpVlans, trusted: dhcpTrusted, bindings },
    arp: { enabled: truth(s.arpEnable), logInterval: num(s.arpLogInterval),
      validation: s.arpValidation == null ? null : Number(s.arpValidation) === 1,
      vlans: arpVlans, trusted: arpTrusted, lists: arpLists }
  };
}

module.exports = {
  readSecurity, switchVlans, inetAt, portList, bytesOf, macOf, SCALARS, FAMILY, IGMP, MLD, DHCP, ARP,
  QUERIER, SNOOP_VLAN, GROUPS, DHCP_VLAN, DHCP_TRUST, BINDING, ARP_LIST, ARP_VLAN, ARP_TRUST, VLAN_STATUS
};
