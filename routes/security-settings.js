'use strict';

/**
 * Switching security settings (switch-security.js): IGMP and MLD snooping,
 * the IGMP snooping querier, DHCP snooping and ARP inspection. Every route
 * that changes the switch passes writeHold(), so the collector is not
 * reading while it writes.
 */

const sec = require('../switch-security');
const R = require('./lib/settings-route');
const pick = R.pick;
const writeRoute = (app, path, what, fn) => R.writeRoute(app, 'security', path, what, fn);

module.exports = function register(app) {
  // Body: { target }
  R.readRoute(app, '/api/security/status', (s) => sec.readSecurity(s));

  // { enabled?, querier?, mld? }
  writeRoute(app, '/api/security/multicast', 'Multicast snooping changed', (s, b) =>
    sec.setMulticast(s, pick(b, ['enabled', 'querier', 'mld'])));
  // { family: 'ipv4'|'ipv6', vlan, enabled?, routerLearn?, immediateLeave? }
  writeRoute(app, '/api/security/snoop-vlan', 'Snooping on a VLAN changed', (s, b) =>
    sec.setSnoopVlan(s, b.family, b.vlan, pick(b, ['enabled', 'routerLearn', 'immediateLeave'])));
  // { vlan, enabled?, address?, version?, election? }
  writeRoute(app, '/api/security/querier', 'IGMP snooping querier changed', (s, b) =>
    sec.setQuerier(s, b.vlan, pick(b, ['enabled', 'address', 'version', 'election'])));
  // { enabled?, verifyMac?, file? }
  writeRoute(app, '/api/security/dhcp', 'DHCP snooping changed', (s, b) =>
    sec.setDhcp(s, pick(b, ['enabled', 'verifyMac', 'file'])));
  // { vlan, on }
  writeRoute(app, '/api/security/dhcp-vlan', 'DHCP snooping on a VLAN changed', (s, b) => sec.setDhcpVlan(s, b.vlan, !!b.on));
  // { ifIndex, on }
  writeRoute(app, '/api/security/dhcp-trust', 'DHCP snooping trusted port changed', (s, b) => sec.setDhcpTrust(s, b.ifIndex, !!b.on));
  // { enabled?, validation?, logInterval? }
  writeRoute(app, '/api/security/arp', 'ARP inspection changed', (s, b) =>
    sec.setArp(s, pick(b, ['enabled', 'validation', 'logInterval'])));
  // { vlan, on?, list? }
  writeRoute(app, '/api/security/arp-vlan', 'ARP inspection on a VLAN changed', (s, b) =>
    sec.setArpVlan(s, b.vlan, { on: b.on == null ? null : !!b.on, list: b.list }));
  // { ifIndex, on }
  writeRoute(app, '/api/security/arp-trust', 'ARP inspection trusted port changed', (s, b) => sec.setArpTrust(s, b.ifIndex, !!b.on));
  // { name, ip, mac }
  writeRoute(app, '/api/security/arp-list/add', 'ARP inspection list entry added', (s, b) => sec.addArpListEntry(s, b.name, b.ip, b.mac));
  // { name, ip }
  writeRoute(app, '/api/security/arp-list/remove', 'ARP inspection list entry removed', (s, b) => sec.removeArpListEntry(s, b.name, b.ip));
};
