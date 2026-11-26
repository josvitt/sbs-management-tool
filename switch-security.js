'use strict';

/**
 * Switching security over SNMP: IGMP and MLD snooping, DHCP snooping and ARP
 * inspection. This first part reads; the writes follow once a recording of a
 * switch shows which of these tables the C1300 fills (docs/MODULE-STANDARD
 * rule 5: read a switch-made row before encoding a write).
 *
 * Objects (vendor root V = 1.3.6.1.4.1.9.6.1.101):
 *   rlIgmpSnoop V.55.2: .2 Enable, .3 HostAgingTime, .4 RouterAgingTime,
 *     .13 QuerierEnable; .7.1 VLAN table (VLAN; .2 Enable, .3 RouterLearn,
 *     .4 HostTimeOut, .5 QuerierTimeOut, .6 RouterTimeOut, .7 LeaveTimeOut,
 *     .8 IgmpVersion, .9 RouterPortlist); .11.1 groups (VLAN, group, source;
 *     .4 IncPortlist, .5 ExcPortlist, .6 ExpiryTime, .7 CompatibilityMode);
 *     .12.1 querier per VLAN (.2 AdminEnable, .3 OperEnable, .4 AdminAddr,
 *     .5 OperAddr, .6 AdminVersion, .7 OperVersion, .8 ElectionEnable)
 *   rlIgmpMldSnoop V.55.5: .1 MldEnable; .5.1 VLAN table (address type,
 *     VLAN; .3 Enable, .4 RouterLearn, .9 IgmpVersion, .10 RouterPortlist,
 *     .34 IsImmediateLeave); .4.1 groups (VLAN, type, group, type, source;
 *     .6 IncPortlist, .7 ExcPortlist, .8 ExpiryTime)
 *   rlIpDhcpSnoop V.112.1: .2 Enable, .3 FileEnable, .6 VerifyMacAddress,
 *     .7 CurrentEntiresNumber; .12.1 VLANs (VLAN; .2 RowStatus); .13.1
 *     trusted ports (ifIndex; .2 RowStatus); .11.1 bindings (VLAN, MAC;
 *     .3 Type, .4 LeaseTime, .5 IPAddress, .6 PortInterface, .7 RowStatus)
 *   rlIpArpInspect V.112.3: .2 Enable, .3 LogInterval, .4 Validation;
 *     .6.1 VLANs (VLAN; .2 AssignedListName, .3 RowStatus, .4 Forwarded,
 *     .5 Dropped, .6 Mismatched); .7.1 trusted ports (ifIndex; .2 RowStatus);
 *     .5.1 lists (name, IP; .3 MAC, .4 RowStatus)
 */

const snmp = require('net-snmp');
const { walkColumns } = require('./switch-ports');

const V = '1.3.6.1.4.1.9.6.1.101';
const IGMP = V + '.55.2';
const MLD = V + '.55.5';
const DHCP = V + '.112.1';
const ARP = V + '.112.3';

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

const num = (v) => (v == null ? null : Number(v));
const truth = (v) => (v == null ? null : Number(v) === 1);
const hex = (v) => (Buffer.isBuffer(v) ? v.toString('hex') : (v == null ? null : String(v)));
const text = (v) => (Buffer.isBuffer(v) ? v.toString('utf8') : (v == null ? '' : String(v))).replace(/\0+$/, '').trim();
const ipOf = (v) => (Buffer.isBuffer(v) && v.length === 4 ? Array.from(v).join('.') : (v == null ? null : String(v)));

// Ports in a PortList (bit 1 of byte 0 is port 1).
function portList(v) {
  if (!Buffer.isBuffer(v)) return [];
  const out = [];
  for (let i = 0; i < v.length; i++) for (let b = 0; b < 8; b++) if (v[i] & (0x80 >> b)) out.push(i * 8 + b + 1);
  return out;
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

/**
 * Everything the panel shows. Resolves { igmp, mld, dhcp, arp }; a table the
 * switch does not answer comes back empty.
 */
async function readSecurity(session) {
  const s = await getScalars(session);
  const safe = async (table, cols) => { try { return await walkColumns(session, table, cols); } catch (e) { return []; } };

  const igmpVlans = (await safe(IGMP + '.7.1', [2, 3, 4, 5, 6, 7, 8, 9])).map((r) => ({
    vlan: r.index[0], enabled: truth(r.cols[2]), routerLearn: truth(r.cols[3]),
    hostTimeout: num(r.cols[4]), querierTimeout: num(r.cols[5]), routerTimeout: num(r.cols[6]),
    leaveTimeout: num(r.cols[7]), version: num(r.cols[8]), routerPorts: portList(r.cols[9])
  }));
  const mldVlans = (await safe(MLD + '.5.1', [3, 4, 9, 10, 34])).map((r) => ({
    family: r.index[0] === 2 ? 'ipv6' : 'ipv4', vlan: r.index[1], enabled: truth(r.cols[3]), routerLearn: truth(r.cols[4]),
    version: num(r.cols[9]), routerPorts: portList(r.cols[10]), immediateLeave: truth(r.cols[34])
  }));
  const queriers = (await safe(IGMP + '.12.1', [2, 3, 4, 5, 6, 7, 8])).map((r) => ({
    vlan: r.index[0], admin: truth(r.cols[2]), oper: truth(r.cols[3]), adminAddr: ipOf(r.cols[4]),
    operAddr: ipOf(r.cols[5]), adminVersion: num(r.cols[6]), operVersion: num(r.cols[7]), election: truth(r.cols[8])
  }));
  const groups = (await safe(IGMP + '.11.1', [4, 5, 6, 7])).map((r) => ({
    vlan: r.index[0], group: r.index.slice(1, 5).join('.'), source: r.index.slice(5, 9).join('.'),
    ports: portList(r.cols[4]), excluded: portList(r.cols[5]), expires: num(r.cols[6]), mode: num(r.cols[7])
  }));

  const dhcpVlans = (await safe(DHCP + '.12.1', [2])).map((r) => r.index[0]);
  const dhcpTrusted = (await safe(DHCP + '.13.1', [2])).map((r) => r.index[0]);
  const bindings = (await safe(DHCP + '.11.1', [3, 4, 5, 6])).map((r) => ({
    vlan: r.index[0], mac: r.index.slice(1, 7).map((b) => b.toString(16).padStart(2, '0')).join(':'),
    type: num(r.cols[3]), lease: num(r.cols[4]), ip: ipOf(r.cols[5]), ifIndex: num(r.cols[6])
  }));

  const arpVlans = (await safe(ARP + '.6.1', [2, 3, 4, 5, 6])).map((r) => ({
    vlan: r.index[0], list: text(r.cols[2]), rowStatus: num(r.cols[3]),
    forwarded: num(r.cols[4]), dropped: num(r.cols[5]), mismatched: num(r.cols[6])
  }));
  const arpTrusted = (await safe(ARP + '.7.1', [2])).map((r) => r.index[0]);
  const arpLists = (await safe(ARP + '.5.1', [3, 4])).map((r) => ({
    index: r.key, mac: hex(r.cols[3]), rowStatus: num(r.cols[4])
  }));

  return {
    igmp: { enabled: truth(s.igmpEnable), querier: truth(s.igmpQuerierEnable), hostAging: num(s.igmpHostAging),
      routerAging: num(s.igmpRouterAging), vlans: igmpVlans, mldVlans, queriers, groups },
    mld: { enabled: truth(s.mldEnable) },
    dhcp: { enabled: truth(s.dhcpEnable), file: truth(s.dhcpFile), verifyMac: truth(s.dhcpVerifyMac),
      entries: num(s.dhcpEntries), vlans: dhcpVlans, trusted: dhcpTrusted, bindings },
    arp: { enabled: truth(s.arpEnable), logInterval: num(s.arpLogInterval), validation: truth(s.arpValidation),
      vlans: arpVlans, trusted: arpTrusted, lists: arpLists }
  };
}

module.exports = { readSecurity, SCALARS, IGMP, MLD, DHCP, ARP, portList };
