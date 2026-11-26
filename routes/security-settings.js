'use strict';

/**
 * Switching security settings (switch-security.js): IGMP and MLD snooping,
 * the IGMP snooping querier, DHCP snooping and ARP inspection. Every route
 * that changes the switch passes writeHold(), so the collector is not
 * reading while it writes.
 */

const { writeHold } = require('../write-hold');
const log = require('../logger');
const { buildSnmpSession, redactTarget } = require('../snmp-core');
const sec = require('../switch-security');

function needTarget(req, res) {
  const t = req.body && req.body.target;
  if (!t || !t.host) { res.status(400).json({ error: 'target.host is required.' }); return null; }
  return t;
}

async function withSession(target, fn) {
  const session = buildSnmpSession(target);
  try { return await fn(session); }
  finally { try { session.close(); } catch (e) {} }
}

const USER_ERROR = /must|is required|Nothing to change|is 0 to|is 1 to/;
const pick = (b, keys) => { const o = {}; for (const k of keys) if (b[k] != null) o[k] = b[k]; return o; };

function writeRoute(app, path, what, fn) {
  app.post(path, writeHold(), async (req, res) => {
    const target = needTarget(req, res); if (!target) return;
    try {
      const r = await withSession(target, (s) => fn(s, req.body || {}));
      log.info('security', what, Object.assign({ host: target.host }, r));
      res.json(Object.assign({ ok: true }, r));
    } catch (e) {
      log.error('security', what + ' failed', { target: redactTarget(target), message: e.message });
      res.status(USER_ERROR.test(e.message) ? 400 : 502).json({ error: e.message });
    }
  });
}

module.exports = function register(app) {
  // Body: { target }
  app.post('/api/security/status', async (req, res) => {
    const target = needTarget(req, res); if (!target) return;
    try {
      res.json(await withSession(target, (s) => sec.readSecurity(s)));
    } catch (e) {
      res.status(502).json({ error: e.message });
    }
  });

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
