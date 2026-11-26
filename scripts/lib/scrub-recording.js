'use strict';

/**
 * Scrub a switch recording (snmp-recording.js) before it goes in the repo.
 *
 *  - IPv4 host addresses (first octet 1-223, not 127, not already a
 *    documentation range) become documentation or benchmark addresses, the
 *    same /24 always to the same new /24 and the last octet kept, so subnets
 *    and masks still line up. Applied to IpAddress values, 4-byte InetAddress
 *    values, dotted text inside strings and runs of four arcs in OID indexes.
 *    Masks (255.x, 0.x) are left alone.
 *  - MAC addresses (MAC, PhysAddress, chassis, bridge-id and LACP system-id
 *    columns, the MAC in the index of the forwarding and 802.1X host tables,
 *    the EUI-64 interface identifiers and link-local addresses made from a
 *    MAC, and a known MAC inside other bytes such as an SNMP engine ID)
 *    become
 *    00:00:5E:00:53:xx (RFC 7042 documentation range).
 *  - Names and secrets (system name, location and contact, communities,
 *    security and user names, keys, descriptions and aliases, neighbour and
 *    host names, domain names, file names) are replaced by a token of the
 *    same length, everywhere they appear: values, other strings, and OID
 *    indexes (where a name is a run of character-code arcs).
 *
 * `secrets` are strings the caller knows must not survive (the community it
 * connected with, the switch's address). scrub() throws if any remain, or if
 * any private IPv4 address is left in text.
 */

const snmp = require('net-snmp');
const mib = require('../../mibdb');

const SENSITIVE = /sysName|sysLocation|sysContact|Community|SecurityName|UserName|usmUser|Key|Password|Secret|Alias|lldpRemSys|lldpRemPortDesc|lldpLocSys(Name|Desc)|cdpCache(DeviceId|Platform|Version|DevicePort)|cdpGlobalDeviceId|HostName|Hostname|DomainName|DnsCl.*Name|Description|Descr$|FileName|ContactInfo|Location|rlFile/i;
const NOT_SENSITIVE = /^(sysDescr|entPhysical|ifDescr|rlifPresentName|rlPhdUnitGenParam|rlCopy)/;
// Firmware and boot versions are dotted numbers ("4.1.9.92") that look like
// addresses, and image file names are the vendor's; neither identifies a
// network, and mapping them would make the fixture lie.
const VERSION_COL = /^(rndImage\d(Internal)?Version|rndImage\dName|rndBrgVersion|rndBaseBootVersion|entPhysical(Hardware|Firmware|Software)Rev)$/;
const MAC_COL = /Mac(Address)?|PhysAddress|ChassisId|BridgeAddress|DesignatedRoot|DesignatedBridge|BridgeId|RootId|SystemID/i;
// An IPv6 link-local address made from a MAC (EUI-64: fe80::, the MAC with
// the universal/local bit flipped and ff:fe in the middle).
const LINK_LOCAL = [254, 128, 0, 0, 0, 0, 0, 0];
const eui64 = (hex) => { const b = Buffer.from(hex, 'hex'); return Buffer.from([b[0] ^ 2, b[1], b[2], 0xff, 0xfe, b[3], b[4], b[5]]).toString('hex'); };
const macOfEui = (b) => (b.length === 8 && b[3] === 0xff && b[4] === 0xfe ? Buffer.from([b[0] ^ 2, b[1], b[2], b[5], b[6], b[7]]).toString('hex') : null);
const linkLocalMacs = (arcs) => {
  const found = [];
  for (let i = 0; i + 16 <= arcs.length; i++) {
    if (LINK_LOCAL.every((n, j) => arcs[i + j] === n)) { const m = macOfEui(Buffer.from(arcs.slice(i + 8, i + 16))); if (m) found.push(m); }
  }
  return found;
};
// Tables with a MAC in the index: [entry OID prefix, arc position of the MAC
// from the end of the suffix (0 = the last six arcs)].
const MAC_INDEXED = [
  ['1.3.6.1.2.1.17.7.1.2.2.1', 0],          // dot1qTpFdbEntry: fid.mac
  ['1.3.6.1.2.1.17.4.3.1', 0],              // dot1dTpFdbEntry: mac
  ['1.3.6.1.2.1.17.7.1.3.1.1', 1],          // dot1qStaticUnicastEntry: fid.mac.port
  ['1.3.6.1.4.1.9.6.1.101.95', null]        // rldot1x host tables: MAC anywhere in the suffix
];
// Tables with an IPv4 address in the index: [entry OID, where each address
// starts among the index arcs (after the column number)].
const IP_INDEXED = [
  ['1.3.6.1.4.1.9.6.1.101.26.1.1', () => [0]],              // rsIpAddrEntry: ip
  ['1.3.6.1.2.1.4.20.1', () => [0]],                        // ipAddrEntry: ip
  ['1.3.6.1.2.1.4.24.4.1', () => [0, 9]],                   // ipCidrRouteEntry: dest.mask.tos.nexthop
  ['1.3.6.1.4.1.9.6.1.101.26.17.1.1', () => [0, 9]],        // rlIpStaticRouteEntry: same
  ['1.3.6.1.2.1.4.22.1', (a) => [a.length - 4]],            // ipNetToMediaEntry: ifIndex.ip
  ['1.3.6.1.2.1.4.35.1', (a) => (a[1] === '1' && a[2] === '4' ? [3] : [])],   // ipNetToPhysicalEntry: ifIndex.type.len.ip
  ['1.3.6.1.2.1.4.34.1', (a) => (a[0] === '1' && a[1] === '4' ? [2] : [])],   // ipAddressEntry: type.len.ip
  ['1.3.6.1.4.1.9.6.1.101.80.8.1', (a) => (a[0] === '1' && a[1] === '4' ? [2] : [])],   // RADIUS: type.len.ip.ports
  ['1.3.6.1.4.1.9.6.1.101.79.40.9.1', (a) => (a[0] === '1' && a[1] === '4' ? [2] : [])],  // TACACS+: type.len.ip
  ['1.3.6.1.4.1.9.6.1.101.92.2.2.17.1', (a) => (a[0] === '1' && a[1] === '4' ? [2] : [])], // SNTP server: type.len.ip
  ['1.3.6.1.2.1.32.2.1.1.4.1', () => [0]],                  // dnsResConfigSbeltEntry: ip.subtree.class
  ['1.0.8802.1.1.2.1.4.2.1', (a) => (a[3] === '1' && a[4] === '4' ? [5] : [])]   // lldpRemManAddrEntry: time.port.rem.type.len.ip
];
// Switch-internal names that embed an IPv4 address as 4 raw bytes after a
// prefix ("TR-" + 4 bytes, snmp-config.js), in values and in indexes.
const INTERNAL_PREFIXES = ['TR-', 'InR-', 'SNR-', 'V_SNR-', 'SSNR-'].map((p) => Buffer.from(p, 'latin1'));
const internalIp = (buf) => {
  for (const p of INTERNAL_PREFIXES) if (buf.length === p.length + 4 && buf.slice(0, p.length).equals(p)) return p.length;
  return -1;
};
const DOC_NETS = ['192.0.2', '198.51.100', '203.0.113'];

const isPrintable = (b) => b.length > 0 && b.every((c) => c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127));
const isHostIp = (ip) => {
  const o = ip.split('.').map(Number);
  if (o.length !== 4 || o.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  if (o[0] < 1 || o[0] > 223 || o[0] === 127) return false;
  if (DOC_NETS.includes(o.slice(0, 3).join('.')) || (o[0] === 198 && (o[1] === 18 || o[1] === 19))) return false;
  return true;
};

function scrub(varbinds, secrets) {
  const nets = new Map();          // a.b.c -> new a.b.c
  const ips = new Map();           // a.b.c.d -> new
  const macs = new Map();          // hex12 -> new hex12
  const names = new Map();         // string -> same-length token
  const mapNet = (p) => {
    if (!nets.has(p)) {
      const n = nets.size;
      nets.set(p, n < DOC_NETS.length ? DOC_NETS[n] : '198.18.' + (n - DOC_NETS.length));
    }
    return nets.get(p);
  };
  const mapIp = (ip) => {
    if (!isHostIp(ip)) return ip;
    if (!ips.has(ip)) { const o = ip.split('.'); ips.set(ip, mapNet(o.slice(0, 3).join('.')) + '.' + o[3]); }
    return ips.get(ip);
  };
  const mapMac = (hex) => {
    hex = hex.toLowerCase();
    if (/^0+$/.test(hex) || /^f+$/.test(hex) || hex.startsWith('00005e0053')) return hex;
    if (!macs.has(hex)) { const n = macs.size; macs.set(hex, '00005e00' + (0x53 + (n >> 8)).toString(16).padStart(2, '0') + (n & 255).toString(16).padStart(2, '0')); }
    return macs.get(hex);
  };
  const mapName = (str) => {
    // A bare number (a VLAN interface's description is its VLAN number)
    // names nothing, and swapping it would rename the VLAN everywhere.
    if (!str.trim() || /^\d+$/.test(str.trim())) return str;
    if (!names.has(str)) {
      const tok = 'R' + (names.size + 1).toString(36);
      names.set(str, (tok + 'x'.repeat(Math.max(0, str.length - tok.length))).slice(0, Math.max(1, str.length)));
    }
    return names.get(str);
  };
  for (const s of (secrets || [])) if (s) { if (isHostIp(s)) mapIp(s); else mapName(String(s)); }

  const colOf = (oid) => { const e = mib.entryForOid(oid); return e ? { name: e.entry.name, syntax: e.entry.syntax || '', index: e.index } : { name: '', syntax: '', index: '' }; };

  // Pass 1: learn every address, MAC and name.
  for (const [oid, type, value] of varbinds) {
    const c = colOf(oid);
    const buf = value && value.$buf !== undefined ? Buffer.from(value.$buf, 'hex') : null;
    if (type === snmp.ObjectType.IpAddress && typeof value === 'string') mapIp(value);
    if (buf && buf.length === 4 && /InetAddress|IpAddress/i.test(c.syntax + c.name)) mapIp(Array.from(buf).join('.'));
    if (buf && MAC_COL.test(c.name) && !isPrintable(buf)) {
      if (buf.length === 6) mapMac(buf.toString('hex'));
      if (buf.length === 8) mapMac(buf.slice(2).toString('hex'));
    }
    for (const [prefix, pos] of MAC_INDEXED) {
      if (!oid.startsWith(prefix + '.')) continue;
      const arcs = oid.slice(prefix.length + 1).split('.').map(Number);
      if (pos === null) {
        // 802.1X host tables: the MAC is the six arcs after the ifIndex where present
        if (arcs.length >= 8) mapMac(arcs.slice(-6).map((n) => n.toString(16).padStart(2, '0')).join(''));
      } else {
        const end = arcs.length - pos;
        if (end >= 6) mapMac(arcs.slice(end - 6, end).map((n) => n.toString(16).padStart(2, '0')).join(''));
      }
    }
    for (const [prefix, starts] of IP_INDEXED) {
      if (!oid.startsWith(prefix + '.')) continue;
      const arcs = oid.slice(prefix.length + 1).split('.').slice(1);   // drop the column number
      for (const i of starts(arcs)) if (i >= 0 && i + 4 <= arcs.length) mapIp(arcs.slice(i, i + 4).join('.'));
    }
    if (buf && !isPrintable(buf)) for (const m of linkLocalMacs(Array.from(buf))) mapMac(m);
    // An interface identifier on its own (ipv6InterfaceIdentifier): 8 bytes, EUI-64.
    if (buf && buf.length === 8 && macOfEui(buf)) mapMac(macOfEui(buf));
    if (c.index) for (const m of linkLocalMacs(c.index.split('.').map(Number))) mapMac(m);
    if (buf && buf.length === 6 && /TAddress/i.test(c.syntax + c.name)) mapIp(Array.from(buf.slice(0, 4)).join('.'));
    if (buf && internalIp(buf) > 0) mapIp(Array.from(buf.slice(internalIp(buf))).join('.'));
    if (c.index) {
      const ia = c.index.split('.').map(Number);
      for (const p of INTERNAL_PREFIXES) {
        for (let i = 0; i + p.length + 4 <= ia.length; i++) {
          if (Array.from(p).every((b, j) => ia[i + j] === b)) mapIp(ia.slice(i + p.length, i + p.length + 4).join('.'));
        }
      }
    }
    if (buf && isPrintable(buf) && SENSITIVE.test(c.name) && !NOT_SENSITIVE.test(c.name)) {
      const str = buf.toString('latin1');
      // IP-looking names are handled as addresses, not names
      if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(str)) mapName(str);
    }
    if (typeof value === 'string' && SENSITIVE.test(c.name) && !NOT_SENSITIVE.test(c.name) && type === snmp.ObjectType.OctetString) mapName(value);
  }

  // Replacement helpers.
  const ipRe = /\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g;
  const fixText = (t) => {
    let out = t.replace(ipRe, (m) => mapIpKnown(m));
    for (const [from, to] of names) if (from.length >= 3) out = out.split(from).join(to);
    for (const [from, to] of macs) {
      const colon = from.match(/../g).join(':');
      out = out.split(colon).join(to.match(/../g).join(':')).split(colon.toUpperCase()).join(to.match(/../g).join(':').toUpperCase());
    }
    return out;
  };
  const mapIpKnown = (ip) => (isHostIp(ip) ? mapIp(ip) : ip);
  const arcRuns = [];   // [fromArcs, toArcs]
  for (const [from, to] of ips) arcRuns.push([from.split('.'), to.split('.')]);
  const hexArcs = (hex) => hex.match(/../g).map((h) => String(parseInt(h, 16)));
  for (const [from, to] of macs) {
    arcRuns.push([hexArcs(from), hexArcs(to)]);
    arcRuns.push([hexArcs(eui64(from)), hexArcs(eui64(to))]);
  }
  for (const [from, to] of names) {
    if (from.length < 2) continue;
    arcRuns.push([Array.from(Buffer.from(from, 'latin1')).map(String), Array.from(Buffer.from(to, 'latin1')).map(String)]);
  }
  arcRuns.sort((a, b) => b[0].length - a[0].length);
  const fixOid = (oid) => {
    const c = colOf(oid);
    const base = c.index ? oid.slice(0, oid.length - c.index.length - 1) : oid;
    if (!c.index) return oid;
    const arcs = c.index.split('.');
    for (const [from, to] of arcRuns) {
      for (let i = 0; i + from.length <= arcs.length; i++) {
        let hit = true;
        for (let j = 0; j < from.length; j++) if (arcs[i + j] !== from[j]) { hit = false; break; }
        if (hit) { arcs.splice(i, from.length, ...to); i += to.length - 1; }
      }
    }
    return base + '.' + arcs.join('.');
  };

  // Pass 2: rewrite.
  const out = varbinds.map(([oid, type, value]) => {
    const c = colOf(oid);
    let v = value;
    if (type === snmp.ObjectType.IpAddress && typeof v === 'string') v = mapIpKnown(v);
    else if (v && v.$buf !== undefined) {
      let buf = Buffer.from(v.$buf, 'hex');
      if (buf.length === 4 && /InetAddress|IpAddress/i.test(c.syntax + c.name)) {
        buf = Buffer.from(mapIpKnown(Array.from(buf).join('.')).split('.').map(Number));
      } else if (buf.length === 6 && /TAddress/i.test(c.syntax + c.name)) {
        buf = Buffer.concat([Buffer.from(mapIpKnown(Array.from(buf.slice(0, 4)).join('.')).split('.').map(Number)), buf.slice(4)]);
      } else if (internalIp(buf) > 0) {
        const at = internalIp(buf);
        buf = Buffer.concat([buf.slice(0, at), Buffer.from(mapIpKnown(Array.from(buf.slice(at)).join('.')).split('.').map(Number))]);
      } else if (MAC_COL.test(c.name) && !isPrintable(buf) && (buf.length === 6 || buf.length === 8)) {
        const head = buf.length === 8 ? buf.slice(0, 2).toString('hex') : '';
        const mac = macs.get((buf.length === 8 ? buf.slice(2) : buf).toString('hex'));
        if (mac) buf = Buffer.from(head + mac, 'hex');
      } else if (isPrintable(buf) && VERSION_COL.test(c.name)) {
        // a version string: left as it is
      } else if (isPrintable(buf)) {
        const str = buf.toString('latin1');
        const swapped = names.has(str) ? names.get(str) : fixText(str);
        buf = Buffer.from(swapped, 'latin1');
      } else {
        // Binary or padded text (a NUL-padded string, a UTF-8 description):
        // names are swapped byte for byte (same length, so the layout holds),
        // and an address written as text is mapped like any other text.
        const str = buf.toString('latin1');
        const fixed = fixText(str);
        if (fixed !== str) buf = Buffer.from(fixed, 'latin1');
        // A link-local address carries the MAC it was made from.
        let hex = buf.toString('hex');
        for (const [from, to] of macs) hex = hex.split('fe80000000000000' + eui64(from)).join('fe80000000000000' + eui64(to));
        if (buf.length === 8) for (const [from, to] of macs) if (hex === eui64(from)) hex = eui64(to);
        // A MAC inside other bytes, such as an SNMP engine ID (80 00 00 09 03 + MAC).
        for (const [from, to] of macs) {
          for (let i = hex.indexOf(from); i >= 0; i = hex.indexOf(from, i + 1)) if (i % 2 === 0) hex = hex.slice(0, i) + to + hex.slice(i + to.length);
        }
        buf = Buffer.from(hex, 'hex');
      }
      v = { $buf: buf.toString('hex') };
    } else if (typeof v === 'string') {
      v = names.has(v) ? names.get(v) : fixText(v);
    }
    return [fixOid(oid), type, v];
  });

  // Check: nothing the caller named, and no private address in text.
  // (Values only: an OID index is a run of numbers, so an address-shaped run
  // can turn up there by chance; names in indexes were swapped above.)
  // The error names the columns (never the value), so a miss can be fixed.
  const texts = out.map(([oid, , v]) => [oid, v && v.$buf ? Buffer.from(v.$buf, 'hex').toString('latin1') : (typeof v === 'string' ? v : '')]);
  const where = (hit) => Array.from(new Set(texts.filter(([, t]) => hit(t)).map(([oid]) => colOf(oid).name || oid))).slice(0, 8).join(', ');
  for (const s of (secrets || [])) {
    if (s && String(s).length >= 3 && texts.some(([, t]) => t.includes(String(s)))) throw new Error('A secret survived scrubbing in ' + where((t) => t.includes(String(s))) + '.');
  }
  const PRIV = /(^|[^.\d])(10\.\d{1,3}|172\.(1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}(?![.\d])/;
  if (texts.some(([, t]) => PRIV.test(t))) throw new Error('A private address survived scrubbing in ' + where((t) => PRIV.test(t)) + '.');
  // In indexes only the unmistakable ranges are checked (a 10.x run of arcs
  // turns up by chance; 192.168 and 172.16-31 runs do not).
  const PRIV_ARCS = /(^|\.)(192\.168|172\.(1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}(\.|$)/;
  const leaked = out.filter(([oid]) => { const c = colOf(oid); return c.index && PRIV_ARCS.test(c.index); });
  if (leaked.length) throw new Error('A private address survived scrubbing in the index of ' + Array.from(new Set(leaked.map(([oid]) => colOf(oid).name))).slice(0, 8).join(', ') + '.');
  return { varbinds: out, counts: { ips: ips.size, macs: macs.size, names: names.size } };
}

module.exports = { scrub };
