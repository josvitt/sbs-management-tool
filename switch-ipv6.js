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
const { setVarbinds, tryForms, getInt, getBytes, rowStatusIs, I, G, OCT, ROW } = require('./snmp-write');

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
const DNS_SOURCE = { 1: 'static', 3: 'dhcpv6', 4: 'dhcpv4' };
const DHCP6_MODE = { 1: 'dhcp', 2: 'off', 3: 'autoconfig', 4: 'both' };

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

  // The IPv4 static routes share this table (type 1); only IPv6 rows here.
  const staticRoutes = (await safe(T.rlStatic, [7, 8, 10, 11])).filter((r) => r.index[0] === 2).map((r) => {
    const d = inetAt(r.index, 1);
    const len = r.index[d.next];
    const nh = inetAt(r.index, d.next + 2);
    return {
      index: r.key, dest: d.addr + '/' + len, nextHop: nh.addr, ifIndex: r.index[nh.next] || null,
      cost: num(r.cols[7]), type: word(ROUTE_TYPE, r.cols[8]), rowStatus: num(r.cols[10]), active: num(r.cols[11]) === 1
    };
  });

  const defaultRouters = (await safe(T.defRouter, [4, 5])).filter((r) => isV6Type(r.index[0])).map((r) => {
    const a = inetAt(r.index, 1);
    return { address: a.addr, ifIndex: r.index[a.next], lifetime: num(r.cols[4]), preference: num(r.cols[5]) };
  });

  const raPrefixes = (await safe(T.raPrefix, [6, 7, 8, 9, 10, 11, 12])).map((r) => ({ index: r.key, cols: r.cols }));
  const dhcpClients = (await safe(T.dhcp6, [2, 3, 4])).map((r) => ({ ifIndex: r.index[0], pd: num(r.cols[2]), stateless: num(r.cols[3]), reconfigure: num(r.cols[4]) }));

  // rlDnsClv2ServersTable index: source, ifIndex, preference, then the address.
  const dnsServers = (await safe(T.dns, [8])).filter((r) => r.index[3] === 2).map((r) => ({
    index: r.key, address: inetAt(r.index, 4).addr, source: word(DNS_SOURCE, r.index[0]), ifIndex: r.index[1] || null,
    preference: r.index[2], rowStatus: num(r.cols[8])
  }));

  // One line per interface for the panel: IPv6 is on where the interface has
  // a link-local address (ipv6InterfaceEnableStatus reads down on .253 even
  // with "ipv6 enable"; docs/SWITCH-NOTES.md).
  const ifs = new Set([].concat(rlInterfaces.map((x) => x.ifIndex), rlAddresses.map((x) => x.ifIndex)).filter(Boolean));
  const summary = Array.from(ifs).sort((a, b) => a - b).map((ifIndex) => {
    const rl = rlInterfaces.find((x) => x.ifIndex === ifIndex) || {};
    const mine = rlAddresses.filter((x) => x.ifIndex === ifIndex);
    const dh = dhcpClients.find((x) => x.ifIndex === ifIndex) || {};
    return {
      ifIndex,
      on: mine.some((x) => /^fe80/i.test(x.address)),
      linkLocal: (mine.find((x) => /^fe80/i.test(x.address)) || {}).address || null,
      global: mine.filter((x) => !/^fe80/i.test(x.address)).map((x) => ({ address: x.address, prefixLength: x.prefixLength, origin: x.rest.split('.')[0] === '2' ? 'manual' : 'auto' })),
      autoconfig: rl.autoconfig == null ? null : rl.autoconfig,
      dhcp: dh.stateless == null ? null : (DHCP6_MODE[dh.stateless] || String(dh.stateless)),
      mtu: rl.mtu == null ? null : rl.mtu
    };
  });

  return {
    forwarding: s.forwarding == null ? null : num(s.forwarding) === 1,
    hopLimit: s.hopLimit == null ? null : num(s.hopLimit),
    summary, interfaces, rlInterfaces, addresses, rlAddresses, prefixes, routes, staticRoutes, defaultRouters, raPrefixes, dhcpClients, dnsServers
  };
}

// ---- writes ----------------------------------------------------------------
// Each is encoded from the rows .253 made for VLAN 999 from the CLI
// (docs/SWITCH-NOTES.md, "IPv6 addressing"). Nothing here saves the
// configuration.

/** Parse IPv6 text into 16 bytes, or null. Takes '::' and an IPv4 tail. */
function v6Bytes(text) {
  let t = String(text || '').trim().toLowerCase();
  if (!t || /[^0-9a-f:.]/.test(t) || (t.match(/::/g) || []).length > 1) return null;
  let tail = [];
  const m = /^(.*:)(\d+\.\d+\.\d+\.\d+)$/.exec(t);
  if (m) {
    const o = m[2].split('.').map(Number);
    if (o.some((x) => x > 255)) return null;
    tail = [((o[0] << 8) | o[1]).toString(16), ((o[2] << 8) | o[3]).toString(16)];
    t = m[1].endsWith('::') ? m[1] : m[1].slice(0, -1);
  }
  const [head, rest] = t.split('::');
  const hw = head ? head.split(':') : [];
  const rw = (rest != null && rest !== '' ? rest.split(':') : []).concat(tail);
  if (rest == null && tail.length) hw.push(...tail.splice(0));
  const fill = 8 - hw.length - (rest == null ? 0 : rw.length);
  if (rest == null ? hw.length !== 8 : fill < 1) return null;
  const words = rest == null ? hw : hw.concat(Array(fill).fill('0'), rw);
  if (words.length !== 8 || words.some((w) => !/^[0-9a-f]{1,4}$/.test(w))) return null;
  const out = [];
  for (const w of words) { const n = parseInt(w, 16); out.push(n >> 8, n & 255); }
  return out;
}
function checkV6(text, what) {
  const b = v6Bytes(text);
  if (!b) throw new Error('The ' + what + ' must be an IPv6 address like 2001:db8::1.');
  return b;
}
function checkLen(len, what) {
  const n = Number(len);
  if (!Number.isInteger(n) || n < 0 || n > 128) throw new Error('The ' + what + ' prefix length must be 0 to 128.');
  return n;
}
function checkIf(ifIndex) {
  const n = Number(ifIndex);
  if (!Number.isInteger(n) || n < 1) throw new Error('ifIndex must be an interface number.');
  return n;
}
const isLinkLocal = (b) => b[0] === 0xfe && (b[1] & 0xc0) === 0x80;
const isMulticast = (b) => b[0] === 0xff;
const inetIdx = (b) => '2.16.' + b.join('.');

// rlIpAddressTable row for a manual global address: type, address, origin
// manual(2), empty general-prefix name (length 0), as the switch made.
const addrIndex = (b) => inetIdx(b) + '.2.0';

/**
 * Add a global IPv6 address to an interface: rlIpAddressTable createAndGo
 * with the interface, the prefix length and unicast(1).
 */
async function addAddress(session, ifIndex, address, prefixLength) {
  const ifx = checkIf(ifIndex);
  const b = checkV6(address, 'address');
  if (isLinkLocal(b) || isMulticast(b)) throw new Error('The address must be a global address, not link-local or multicast.');
  const len = checkLen(prefixLength == null ? 64 : prefixLength, 'address');
  if (len < 1) throw new Error('The address prefix length must be 1 to 128.');
  const k = addrIndex(b);
  const st = T.rlAddr + '.11.' + k;
  const cols = [I(T.rlAddr + '.5.' + k, ifx), G(T.rlAddr + '.13.' + k, len)];
  const r = await tryForms(session, [
    ['createAndGo with ifIndex, prefix length and unicast', [[I(st, ROW.createAndGo)].concat(cols, [I(T.rlAddr + '.6.' + k, 1)])]],
    ['createAndGo with ifIndex and prefix length', [[I(st, ROW.createAndGo)].concat(cols)]],
    ['createAndWait, columns, then active', [[I(st, ROW.createAndWait)], cols, [I(st, ROW.active)]]]
  ], () => rowStatusIs(session, st, ROW.active), [I(st, ROW.destroy)]);
  return Object.assign({ ifIndex: ifx, address: v6Text(b), prefixLength: len }, r);
}

/** Remove a global IPv6 address the user added. */
async function removeAddress(session, address) {
  const b = checkV6(address, 'address');
  await setVarbinds(session, [I(T.rlAddr + '.11.' + addrIndex(b), ROW.destroy)]);
  return { address: v6Text(b) };
}

/**
 * IPv6 on or off for an interface. ipv6InterfaceEnableStatus reads down(2)
 * on .253 even where "ipv6 enable" is set, and refuses down with WrongValue
 * (switch test, v1.15.0), so a change is checked by the link-local address
 * coming or going, and the link-local row itself is the next form: made
 * from fe80:: and the interface identifier, or destroyed.
 */
async function setEnabled(session, ifIndex, on) {
  const ifx = checkIf(ifIndex);
  const lls = async () => (await walkColumns(session, T.rlAddr, [5])).filter((r) => r.index[0] === 4 && num(r.cols[5]) === ifx);
  const forms = [['ipv6InterfaceEnableStatus ' + (on ? 'up' : 'down'), [[I(T.iface + '.5.' + ifx, on ? 1 : 2)]]]];
  let undo = [I(T.iface + '.5.' + ifx, on ? 2 : 1)];
  if (on) {
    const id = await getBytes(session, T.iface + '.3.' + ifx);
    if (id && id.length === 8) {
      const k = linkLocalIndex(id, ifx);
      forms.push(['a link-local row from the interface identifier', [[I(T.rlAddr + '.11.' + k, ROW.createAndGo), I(T.rlAddr + '.5.' + k, ifx), G(T.rlAddr + '.13.' + k, 64)]]]);
      undo = [I(T.rlAddr + '.11.' + k, ROW.destroy)];
    }
    // Autoconfig turns IPv6 on by itself, as "ipv6 address autoconfig" does.
    forms.push(['autoconfig on', [[I(T.rlIface + '.2.' + ifx, 1)]]]);
  } else {
    const rows = await lls();
    const destroyLl = rows.map((r) => I(T.rlAddr + '.11.' + r.key, ROW.destroy));
    if (rows.length) forms.push(['destroy the link-local row', [destroyLl]]);
    // With autoconfig on, the switch keeps IPv6 on: autoconfig goes off
    // first, and is put back if IPv6 still will not go off.
    const auto = await getInt(session, T.rlIface + '.2.' + ifx);
    if (auto === 1) {
      const off = [I(T.rlIface + '.2.' + ifx, 2)];
      forms.push(['autoconfig off, then ipv6InterfaceEnableStatus down', [off, [I(T.iface + '.5.' + ifx, 2)]]]);
      if (rows.length) forms.push(['autoconfig off, then destroy the link-local row', [off, destroyLl]]);
      undo = [I(T.rlIface + '.2.' + ifx, 1)];
    } else undo = [];
  }
  const r = await tryForms(session, forms, async () => ((await lls()).length > 0) === !!on, undo);
  return Object.assign({ ifIndex: ifx, on: !!on }, r);
}

// rlIpAddressTable index of a link-local address: type 4, length 20, fe80::
// and the 8-byte interface identifier, the zone (the ifIndex, 4 bytes), then
// origin link-layer(5) and an empty prefix name, as the switch made it.
function linkLocalIndex(id, ifx) {
  const zone = [(ifx >>> 24) & 255, (ifx >>> 16) & 255, (ifx >>> 8) & 255, ifx & 255];
  return '4.20.' + [254, 128, 0, 0, 0, 0, 0, 0].concat(Array.from(id), zone).join('.') + '.5.0';
}
/** Stateless autoconfig on or off for an interface (rlipv6InterfaceAutoconfigEnable 1 / 2). */
async function setAutoconfig(session, ifIndex, on) {
  const ifx = checkIf(ifIndex);
  await setVarbinds(session, [I(T.rlIface + '.2.' + ifx, on ? 1 : 2)]);
  return { ifIndex: ifx, on: !!on };
}

// rlInetStaticRouteTable index: destination type and address, prefix
// length, next-hop type and address, then the interface (as the switch made
// for 2001:db8:998::/48 via 2001:db8:999::fe on VLAN 999).
const routeIndex = (dest, len, nh, ifx) => inetIdx(dest) + '.' + len + '.' + inetIdx(nh) + '.' + ifx;

/**
 * Add a static IPv6 route (::/0 is the default route). The switch keeps the
 * interface the next hop is reached through in the index, so ifIndex is
 * required: the interface whose prefix holds the next hop, or for a
 * link-local next hop the interface it is on.
 */
async function addRoute(session, dest, prefixLength, nextHop, ifIndex, cost) {
  const d = checkV6(dest, 'destination');
  const len = checkLen(prefixLength, 'destination');
  const nh = checkV6(nextHop, 'next hop');
  const ifx = checkIf(ifIndex);
  const c = cost == null || cost === '' ? 1 : Number(cost);
  if (!Number.isInteger(c) || c < 1 || c > 255) throw new Error('The metric is 1 to 255.');
  const k = routeIndex(d, len, nh, ifx);
  const st = T.rlStatic + '.10.' + k;
  const cols = [I(T.rlStatic + '.8.' + k, 4), G(T.rlStatic + '.7.' + k, c)];   // remote, the metric
  const r = await tryForms(session, [
    ['createAndGo with type remote and the metric', [[I(st, ROW.createAndGo)].concat(cols)]],
    ['createAndGo alone', [[I(st, ROW.createAndGo)]]],
    ['createAndWait, columns, then active', [[I(st, ROW.createAndWait)], cols, [I(st, ROW.active)]]]
  ], () => rowStatusIs(session, st, ROW.active), [I(st, ROW.destroy)]);
  return Object.assign({ dest: v6Text(d) + '/' + len, nextHop: v6Text(nh), ifIndex: ifx, cost: c }, r);
}

/** Remove a static route by its row index, as the reader gives it. */
async function removeRoute(session, index) {
  if (!/^2\.16(\.\d+)+$/.test(String(index || ''))) throw new Error('index must be an IPv6 static route index.');
  await setVarbinds(session, [I(T.rlStatic + '.10.' + index, ROW.destroy)]);
  return { index };
}

// DNS servers: added through the sbelt table (93.9, as the IPv4 panel does,
// root subtree 0, class IN 1) and removed through rlDnsClv2ServersTable.
const SBELT = V + '.93.9.1';
async function addDnsServer(session, address) {
  const b = checkV6(address, 'DNS server');
  if (isMulticast(b)) throw new Error('The DNS server must be a unicast address.');
  const k = inetIdx(b) + '.0.1';
  const want = v6Text(b);
  const listed = async () => (await walkColumns(session, T.dns, [8])).some((x) => x.index[3] === 2 && inetAt(x.index, 4).addr === want);
  const r = await tryForms(session, [
    ['name, preference and createAndGo, as the IPv4 panel adds one', [[OCT(SBELT + '.3.' + k, '.'), I(SBELT + '.5.' + k, 0), I(SBELT + '.8.' + k, ROW.createAndGo)]]],
    ['createAndGo first, then name and preference', [[I(SBELT + '.8.' + k, ROW.createAndGo), OCT(SBELT + '.3.' + k, '.'), I(SBELT + '.5.' + k, 0)]]],
    ['createAndGo alone', [[I(SBELT + '.8.' + k, ROW.createAndGo)]]]
  ], listed, [I(SBELT + '.8.' + k, ROW.destroy)]);
  return Object.assign({ address: want }, r);
}
async function removeDnsServer(session, index) {
  if (!/^(\d+\.){3}2\.16(\.\d+)+$/.test(String(index || ''))) throw new Error('index must be an IPv6 DNS server index.');
  await setVarbinds(session, [I(T.dns + '.8.' + index, ROW.destroy)]);
  return { index };
}

module.exports = {
  readIpv6, addAddress, removeAddress, setEnabled, setAutoconfig, addRoute, removeRoute, addDnsServer, removeDnsServer,
  inetAt, v6Text, v6Bytes, routeIndex, addrIndex, linkLocalIndex, T, SCALARS, SBELT
};
