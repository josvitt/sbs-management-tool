'use strict';

/**
 * IPv6 addressing settings (switch-ipv6.js): IPv6 and stateless autoconfig
 * per interface, global addresses, static routes and DNS servers. Writes
 * pass the write hold (routes/lib/settings-route.js).
 */

const v6 = require('../switch-ipv6');
const R = require('./lib/settings-route');
const writeRoute = (app, path, what, fn) => R.writeRoute(app, 'ipv6', path, what, fn);

module.exports = function register(app) {
  // Body: { target }
  R.readRoute(app, '/api/ipv6/status', (s) => v6.readIpv6(s));

  // { ifIndex, on }
  writeRoute(app, '/api/ipv6/enabled', 'IPv6 on an interface turned on or off', (s, b) => v6.setEnabled(s, b.ifIndex, !!b.on));
  // { ifIndex, on }
  writeRoute(app, '/api/ipv6/autoconfig', 'IPv6 autoconfig changed', (s, b) => v6.setAutoconfig(s, b.ifIndex, !!b.on));
  // { ifIndex, address, prefixLength }
  writeRoute(app, '/api/ipv6/address/add', 'IPv6 address added', (s, b) => v6.addAddress(s, b.ifIndex, b.address, b.prefixLength));
  // { address }
  writeRoute(app, '/api/ipv6/address/remove', 'IPv6 address removed', (s, b) => v6.removeAddress(s, b.address));
  // { dest, prefixLength, nextHop, ifIndex, cost? }
  writeRoute(app, '/api/ipv6/route/add', 'IPv6 static route added', (s, b) => v6.addRoute(s, b.dest, b.prefixLength, b.nextHop, b.ifIndex, b.cost));
  // { index }
  writeRoute(app, '/api/ipv6/route/remove', 'IPv6 static route removed', (s, b) => v6.removeRoute(s, b.index));
  // { address }
  writeRoute(app, '/api/ipv6/dns/add', 'IPv6 DNS server added', (s, b) => v6.addDnsServer(s, b.address));
  // { index }
  writeRoute(app, '/api/ipv6/dns/remove', 'IPv6 DNS server removed', (s, b) => v6.removeDnsServer(s, b.index));
};
