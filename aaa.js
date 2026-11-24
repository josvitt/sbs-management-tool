'use strict';

// Create / edit / delete RADIUS and TACACS+ servers over SNMP, via the CISCOSB
// AAA Inet tables. Both are standard RowStatus tables (unlike the OPC action
// table), so a server is created with its columns + RowStatus createAndGo and
// removed with RowStatus destroy.
//
// INDEX ENCODING (the fiddly part):
//   RADIUS rlRadiusServerInetTable (…80.8.1):
//     INDEX { AddressType, Address, AuthPort, AcctPort }
//     -> <type>.<addrLen>.<addr bytes>.<authPort>.<acctPort>
//   TACACS rlTacacsServerInetTable (…79.40.9.1):
//     INDEX { AddressType, Address }
//     -> <type>.<addrLen>.<addr bytes>
// InetAddressType: ipv4(1), ipv6(2). InetAddress in an index is
// length-prefixed (the implied-length form used when it is not the last/only
// variable component), so the length byte precedes the address octets.

const RADIUS = '1.3.6.1.4.1.9.6.1.101.80.8.1';
const TACACS = '1.3.6.1.4.1.9.6.1.101.79.40.9.1';

// Column numbers.
const RCOL = {
  addressType: 1, address: 2, authPort: 3, acctPort: 4, timeout: 5, retries: 6,
  deadtime: 7, useGlobalKey: 8, key: 9, sourceType: 10, source: 11, priority: 12,
  rowStatus: 13, usage: 14
};
const TCOL = {
  addressType: 1, address: 2, port: 3, connType: 4, connStatus: 5, timeout: 6,
  useGlobalKey: 7, key: 8, sourceType: 9, source: 10, priority: 11, rowStatus: 12
};

const ROW = { active: 1, createAndGo: 4, createAndWait: 5, destroy: 6 };
const INET_IPV4 = 1, INET_IPV6 = 2;

// Parse an IPv4 dotted string to its 4 octets, or return null.
function ipv4Octets(ip) {
  const m = String(ip).trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  const o = m.slice(1).map(Number);
  if (o.some((n) => n < 0 || n > 255)) return null;
  return o;
}

// Build the length-prefixed address portion of an index for an IPv4 address.
function inetIndexV4(ip) {
  const o = ipv4Octets(ip);
  if (!o) throw new Error('Only IPv4 server addresses are supported here: ' + ip);
  return '4.' + o.join('.');   // length 4, then the four octets
}

// Full index for a RADIUS row.
function radiusIndex(ip, authPort, acctPort) {
  return INET_IPV4 + '.' + inetIndexV4(ip) + '.' + Number(authPort) + '.' + Number(acctPort);
}
// Full index for a TACACS row.
function tacacsIndex(ip) {
  return INET_IPV4 + '.' + inetIndexV4(ip);
}

// Varbind builders: {oid, type, value|valueHex} as /api/snmp/set expects.
const I = (oid, v) => ({ oid, type: 'Integer', value: v });
const S = (oid, v) => ({ oid, type: 'OctetString', value: v });
// InetAddress columns are written as the raw address bytes (OctetString), hex.
const A = (oid, ip) => {
  const o = ipv4Octets(ip);
  if (!o) throw new Error('Invalid IPv4 address: ' + ip);
  return { oid, type: 'OctetString', valueHex: o.map((n) => n.toString(16).padStart(2, '0')).join('') };
};
const USAGE = { login: 1, '802.1x': 2, all: 3, wireless: 4 };

// Create or edit a RADIUS server. cfg:
//  { address, authPort=1812, acctPort=1813, key, useGlobalKey, timeout,
//    retries, deadtime, priority, usage, edit }
function planRadius(cfg) {
  const authPort = Number(cfg.authPort) || 1812;
  const acctPort = Number(cfg.acctPort) || 1813;
  const i = radiusIndex(cfg.address, authPort, acctPort);
  const col = (c) => RADIUS + '.' + c + '.' + i;
  const vbs = [];
  // The index columns are set implicitly by the OID; the switch still wants the
  // address + type columns supplied on create.
  if (!cfg.edit) {
    vbs.push(I(col(RCOL.addressType), INET_IPV4));
    vbs.push(A(col(RCOL.address), cfg.address));
  }
  if (Number.isFinite(Number(cfg.timeout))) vbs.push(I(col(RCOL.timeout), Number(cfg.timeout)));
  if (Number.isFinite(Number(cfg.retries))) vbs.push(I(col(RCOL.retries), Number(cfg.retries)));
  if (Number.isFinite(Number(cfg.deadtime))) vbs.push(I(col(RCOL.deadtime), Number(cfg.deadtime)));
  if (Number.isFinite(Number(cfg.priority))) vbs.push(I(col(RCOL.priority), Number(cfg.priority)));
  if (cfg.usage && USAGE[String(cfg.usage).toLowerCase()]) vbs.push(I(col(RCOL.usage), USAGE[String(cfg.usage).toLowerCase()]));
  // Key handling: either use the global default, or set a per-server key.
  if (cfg.useGlobalKey) {
    vbs.push(I(col(RCOL.useGlobalKey), 1));
  } else if (cfg.key !== undefined && cfg.key !== null && cfg.key !== '') {
    vbs.push(I(col(RCOL.useGlobalKey), 2));   // TruthValue false(2) = not global
    vbs.push(S(col(RCOL.key), cfg.key));
  }
  // RowStatus last: createAndGo for a new row, active to commit an edit.
  vbs.push(I(col(RCOL.rowStatus), cfg.edit ? ROW.active : ROW.createAndGo));
  return { varbinds: vbs, index: i };
}

function planRadiusDelete(address, authPort, acctPort) {
  const i = radiusIndex(address, Number(authPort) || 1812, Number(acctPort) || 1813);
  return [I(RADIUS + '.' + RCOL.rowStatus + '.' + i, ROW.destroy)];
}

// Create or edit a TACACS server. cfg:
//  { address, port=49, key, useGlobalKey, timeout, priority, edit }
function planTacacs(cfg) {
  const i = tacacsIndex(cfg.address);
  const col = (c) => TACACS + '.' + c + '.' + i;
  const vbs = [];
  if (!cfg.edit) {
    vbs.push(I(col(TCOL.addressType), INET_IPV4));
    vbs.push(A(col(TCOL.address), cfg.address));
  }
  if (Number.isFinite(Number(cfg.port))) vbs.push(I(col(TCOL.port), Number(cfg.port)));
  if (Number.isFinite(Number(cfg.timeout))) vbs.push(I(col(TCOL.timeout), Number(cfg.timeout)));
  if (Number.isFinite(Number(cfg.priority))) vbs.push(I(col(TCOL.priority), Number(cfg.priority)));
  if (cfg.useGlobalKey) {
    vbs.push(I(col(TCOL.useGlobalKey), 1));
  } else if (cfg.key !== undefined && cfg.key !== null && cfg.key !== '') {
    vbs.push(I(col(TCOL.useGlobalKey), 2));
    vbs.push(S(col(TCOL.key), cfg.key));
  }
  vbs.push(I(col(TCOL.rowStatus), cfg.edit ? ROW.active : ROW.createAndGo));
  return { varbinds: vbs, index: i };
}

function planTacacsDelete(address) {
  const i = tacacsIndex(address);
  return [I(TACACS + '.' + TCOL.rowStatus + '.' + i, ROW.destroy)];
}

module.exports = {
  RADIUS, TACACS, RCOL, TCOL, ROW,
  ipv4Octets, radiusIndex, tacacsIndex,
  planRadius, planRadiusDelete, planTacacs, planTacacsDelete
};
