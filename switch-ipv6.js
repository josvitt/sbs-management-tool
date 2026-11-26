'use strict';

/**
 * IPv6 addressing over SNMP. This first part reads; the writes follow once a
 * recording shows which of these tables a C1300 fills for an IPv6 address,
 * a static route and a DNS server (docs/MODULE-STANDARD rule 5: read a
 * switch-made row before encoding a write).
 *
 * Objects (vendor root V = 1.3.6.1.4.1.9.6.1.101):
 *   ipv6IpForwarding 1.3.6.1.2.1.4.25, ipv6IpDefaultHopLimit .26
 *   ipv6InterfaceTable 1.3.6.1.2.1.4.30.1 (ifIndex; .3 Identifier,
 *     .5 EnableStatus, .8 Forwarding)
 *   rlipv6InterfaceTable V.26.20.1 (ifIndex; .1 NdDadAttemps, .2 AutoconfigEnable,
 *     .3 IcmpUnreachSendEnable, .4 LinkMTU, .5 MLDVersion, .6 RetransmitTime,
 *     .7 IcmpRedirectSendEnable)
 *   ipAddressTable 1.3.6.1.2.1.4.34.1 (type, address; .3 IfIndex, .4 Type,
 *     .5 Prefix, .6 Origin, .7 Status, .10 RowStatus)
 *   rlIpAddressTable V.26.36.1 (type, address, ...; .5 IfIndex, .6 ExtdType,
 *     .8 Status, .11 RowStatus, .13 ExtdPrefixLength, .14 CompleteAddr,
 *     .15 OperStatus)
 *   ipAddressPrefixTable 1.3.6.1.2.1.4.32.1 (ifIndex, type, prefix, length;
 *     .5 Origin, .6 OnLink, .7 Autonomous)
 *   inetCidrRouteTable 1.3.6.1.2.1.4.24.7.1 (type, dest, length, policy,
 *     type, next hop; .7 IfIndex, .8 Type, .9 Proto, .12 Metric1, .17 Status)
 *   rlInetStaticRouteTable V.26.28.1 (.7 PathCost, .8 Type, .10 RowStatus,
 *     .11 ForwardingStatus)
 *   ipDefaultRouterTable 1.3.6.1.2.1.4.37.1 (type, address, ifIndex;
 *     .4 Lifetime, .5 Preference)
 *   rlIpv6RouterAdvertPrefixTable V.129.6.1, rlDhcpv6ClientTable V.214.2.3.1
 *   rlDnsClv2ServersTable V.93.15.1 (.8 RowStatus)
 */

const snmp = require('net-snmp');
const { walkColumns } = require('./switch-ports');

const V = '1.3.6.1.4.1.9.6.1.101';
const MIB2_IP = '1.3.6.1.2.1.4';
const T = {
  iface: MIB2_IP + '.30.1',
  rlIface: V + '.26.20.1',
  addr: MIB2_IP + '.34.1',
  rlAddr: V + '.26.36.1',
  prefix: MIB2_IP + '.32.1',
  route: MIB2_IP + '.24.7.1',
  rlStatic: V + '.26.28.1',
  defRouter: MIB2_IP + '.37.1',
  raPrefix: V + '.129.6.1',
  dhcp6: V + '.214.2.3.1',
  dns: V + '.93.15.1'
};
const SCALARS = { forwarding: MIB2_IP + '.25.0', hopLimit: MIB2_IP + '.26.0' };
const ORIGIN = { 1: 'other', 2: 'manual', 4: 'dhcp', 5: 'linklayer', 6: 'random' };
const ADDR_TYPE = { 1: 'unicast', 2: 'anycast', 3: 'broadcast' };
const ADDR_STATUS = { 1: 'preferred', 2: 'deprecated', 3: 'invalid', 4: 'inaccessible', 5: 'unknown', 6: 'tentative', 7: 'duplicate', 8: 'optimistic' };
const ROUTE_PROTO = { 1: 'other', 2: 'local', 3: 'static', 8: 'rip', 13: 'ospf' };
const ROUTE_TYPE = { 1: 'other', 2: 'reject', 3: 'local', 4: 'remote', 5: 'blackhole' };

// A walked value comes as display text ("down (2)", "1,500"); a GET as a number.
const num = (v) => {
  if (v == null || v === '') return null;
  const m = /\((-?\d+)\)\s*$/.exec(String(v));
  return Number(m ? m[1] : String(v).replace(/,/g, ''));
};
const word = (map, v) => (v == null ? null : (map[num(v)] || String(v)));

/** IPv6 text from 16 numbers, the longest run of zero words as '::'. */
function v6Text(bytes) {
  const words = [];
  for (let i = 0; i < 16; i += 2) words.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
  let best = -1, bestLen = 1;
  for (let i = 0; i < 8;) {
    if (words[i] !== '0') { i++; continue; }
    let j = i; while (j < 8 && words[j] === '0') j++;
    if (j - i > bestLen) { best = i; bestLen = j - i; }
    i = j;
  }
  return best < 0 ? words.join(':') : words.slice(0, best).join(':') + '::' + words.slice(best + bestLen).join(':');
}

// An InetAddress in an index: [type?, length, ...bytes]. at points at the
// length. Resolves { addr, next }.
function inetAt(arcs, at) {
  const len = arcs[at];
  const bytes = arcs.slice(at + 1, at + 1 + len);
  let addr;
  if (len === 16 || len === 20) addr = v6Text(bytes.slice(0, 16)) + (len === 20 ? '%' + ((bytes[16] << 24) | (bytes[17] << 16) | (bytes[18] << 8) | bytes[19]) : '');
  else addr = bytes.join('.');
  return { addr, next: at + 1 + len };
}
const isV6Type = (t) => t === 2 || t === 4;

async function getScalars(session) {
  const names = Object.keys(SCALARS);
  const vbs = await new Promise((resolve, reject) => session.get(names.map((n) => SCALARS[n]), (e, v) => (e ? reject(e) : resolve(v))));
  const out = {};
  names.forEach((n, k) => { const vb = vbs[k]; out[n] = (!vb || snmp.isVarbindError(vb)) ? undefined : vb.value; });
  return out;
}

/** Everything the IPv6 Addressing panel shows; a table the switch does not answer comes back empty. */
async function readIpv6(session) {
  const s = await getScalars(session).catch(() => ({}));
  const safe = async (table, cols) => { try { return await walkColumns(session, table, cols); } catch (e) { return []; } };

  const interfaces = (await safe(T.iface, [3, 5, 8])).map((r) => ({
    ifIndex: r.index[0], identifier: r.cols[3] == null ? null : String(r.cols[3]),
    enabled: num(r.cols[5]) === 1, forwarding: num(r.cols[8]) === 1
  }));

  const rlInterfaces = (await safe(T.rlIface, [1, 2, 3, 4, 5, 6, 7])).map((r) => ({
    ifIndex: r.index[0], dad: num(r.cols[1]), autoconfig: r.cols[2] == null ? null : num(r.cols[2]) === 1,
    unreachables: r.cols[3] == null ? null : num(r.cols[3]) === 1, mtu: num(r.cols[4]), mld: num(r.cols[5]),
    retransmit: num(r.cols[6]), redirects: r.cols[7] == null ? null : num(r.cols[7]) === 1
  }));

  const addresses = (await safe(T.addr, [3, 4, 5, 6, 7, 10])).filter((r) => isV6Type(r.index[0])).map((r) => ({
    address: inetAt(r.index, 1).addr, ifIndex: num(r.cols[3]), type: word(ADDR_TYPE, r.cols[4]),
    prefix: r.cols[5] == null ? null : String(r.cols[5]), origin: word(ORIGIN, r.cols[6]),
    status: word(ADDR_STATUS, r.cols[7]), rowStatus: num(r.cols[10])
  }));

  const rlAddresses = (await safe(T.rlAddr, [5, 6, 8, 11, 13, 14, 15])).filter((r) => isV6Type(r.index[0])).map((r) => {
    const a = inetAt(r.index, 1);
    return {
      index: r.key, address: a.addr, rest: r.index.slice(a.next).join('.'), ifIndex: num(r.cols[5]), extdType: num(r.cols[6]),
      status: num(r.cols[8]), rowStatus: num(r.cols[11]), prefixLength: num(r.cols[13]),
      complete: r.cols[14] == null ? null : String(r.cols[14]), oper: num(r.cols[15])
    };
  });

  const prefixes = (await safe(T.prefix, [5, 6, 7])).filter((r) => isV6Type(r.index[1])).map((r) => {
    const a = inetAt(r.index, 2);
    return { ifIndex: r.index[0], prefix: a.addr + '/' + r.index[a.next], origin: num(r.cols[5]), onLink: num(r.cols[6]) === 1, autonomous: num(r.cols[7]) === 1 };
  });

  const routes = (await safe(T.route, [7, 8, 9, 12, 17])).filter((r) => isV6Type(r.index[0])).map((r) => {
    const d = inetAt(r.index, 1);
    const len = r.index[d.next];
    // The policy is an OID: its length, then its arcs.
    const polLen = r.index[d.next + 1];
    const nhAt = d.next + 2 + polLen;
    const nh = inetAt(r.index, nhAt + 1);
    return {
      dest: d.addr + '/' + len, nextHop: nh.addr, ifIndex: num(r.cols[7]), type: word(ROUTE_TYPE, r.cols[8]),
      proto: word(ROUTE_PROTO, r.cols[9]), metric: num(r.cols[12]), rowStatus: num(r.cols[17]), index: r.key
    };
  });

  const staticRoutes = (await safe(T.rlStatic, [7, 8, 10, 11])).map((r) => ({
    index: r.key, cost: num(r.cols[7]), type: num(r.cols[8]), rowStatus: num(r.cols[10]), forwarding: num(r.cols[11])
  }));

  const defaultRouters = (await safe(T.defRouter, [4, 5])).filter((r) => isV6Type(r.index[0])).map((r) => {
    const a = inetAt(r.index, 1);
    return { address: a.addr, ifIndex: r.index[a.next], lifetime: num(r.cols[4]), preference: num(r.cols[5]) };
  });

  const raPrefixes = (await safe(T.raPrefix, [6, 7, 8, 9, 10, 11, 12])).map((r) => ({ index: r.key, cols: r.cols }));
  const dhcpClients = (await safe(T.dhcp6, [2, 3, 4])).map((r) => ({ ifIndex: r.index[0], pd: num(r.cols[2]), stateless: num(r.cols[3]), reconfigure: num(r.cols[4]) }));

  const dnsServers = (await safe(T.dns, [8])).filter((r) => r.index.some((x, i) => i < 4 && x === 2)).map((r) => ({ index: r.key, rowStatus: num(r.cols[8]) }));

  return {
    forwarding: s.forwarding == null ? null : num(s.forwarding) === 1,
    hopLimit: s.hopLimit == null ? null : num(s.hopLimit),
    interfaces, rlInterfaces, addresses, rlAddresses, prefixes, routes, staticRoutes, defaultRouters, raPrefixes, dhcpClients, dnsServers
  };
}

module.exports = { readIpv6, inetAt, v6Text, T, SCALARS };
