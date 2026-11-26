'use strict';

/**
 * Supervised write test for the Switching security settings
 * (switch-security.js, routes/security-settings.js) on a test switch. Every
 * change is put back, and nothing is saved to startup.
 *
 *   SBS_COMM=<community> node scripts/switch-test-security.js <address> [port ifIndex] [--vlan=999] [--cleanup] [results folder]
 *
 * It works on a test VLAN (default 999) that must already exist, and a port
 * (default 4) with nothing plugged in. Snooping, DHCP snooping and ARP
 * inspection then only touch traffic on that VLAN and that port.
 *
 *   1. Reads everything.
 *   2. Multicast on the VLAN: IGMP snooping, immediate leave, MLD snooping
 *      and the querier (on, address, version, election), each changed and
 *      put back. The switch-wide MLD setting is turned on and back off only
 *      when no VLAN has MLD snooping on.
 *   3. DHCP snooping: the VLAN off and on, the port's trust, the MAC check.
 *   4. ARP inspection: the VLAN off and on with its list, the list cleared
 *      and put back, the port's trust, the packet check, the log interval,
 *      and an entry added to a new list and removed again.
 *   5. The switch-wide on/off of DHCP snooping and ARP inspection, only when
 *      the test VLAN is the only VLAN using them.
 *
 * With --cleanup it instead removes the sample settings made for the
 * recording on the test VLAN: DHCP snooping and ARP inspection off on the
 * VLAN, the port no longer trusted, the sbs-ref-arp list removed, IGMP
 * snooping and the querier off on the VLAN, and DHCP snooping and ARP
 * inspection off for the switch when no other VLAN uses them. IGMP
 * snooping for the switch is left as it is. The VLAN itself is not deleted.
 *
 * The app's own routes run on 127.0.0.1, so this tests what the panel sends.
 * No community is written to the results file.
 */

process.env.SNMP_MAX_RPS = process.env.SNMP_MAX_RPS || '20';
const fs = require('fs');
const path = require('path');
const http = require('http');

const flags = process.argv.slice(2).filter((a) => a.startsWith('--'));
const args = process.argv.slice(2).filter((a) => !a.startsWith('--'));
const host = args[0];
const ifx = /^\d+$/.test(args[1] || '') ? Number(args[1]) : 4;
const outDir = /^\d+$/.test(args[1] || '') ? (args[2] || null) : (args[1] || null);
const vlanFlag = flags.find((f) => f.startsWith('--vlan='));
const VLAN = vlanFlag ? Number(vlanFlag.slice(7)) : 999;
const cleanup = flags.includes('--cleanup');
const community = process.env.SBS_COMM;
if (!host || !community || !(VLAN >= 2 && VLAN <= 4094)) {
  console.error('Usage: SBS_COMM=<community> node scripts/switch-test-security.js <address> [port ifIndex] [--vlan=999] [--cleanup] [results folder]');
  process.exit(2);
}
const TEST_LIST = 'sbs-test-arp';
const REF_LIST = 'sbs-ref-arp';

const lines = [];
function say(msg) {
  const l = '[' + new Date().toISOString().slice(11, 19) + '] ' + msg;
  lines.push(l);
  console.log(l);
}
const results = [];
function check(name, ok, detail) {
  results.push({ name, ok: !!ok, detail: detail || '' });
  say((ok ? 'PASS ' : 'FAIL ') + name + (detail ? ': ' + detail : ''));
  return !!ok;
}

async function startApp() {
  const out = console.log;
  console.log = (...a) => { if (typeof a[0] === 'string' && /^\[[0-9T:.\-Z]+\] \[INFO\]/.test(a[0])) return; out(...a); };
  const app = require('../web');
  require('../routes/security-settings')(app);
  const server = http.createServer(app);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return server;
}

// What the test VLAN and port look like, as one comparable line.
function view(d) {
  const v4 = (d.igmp.vlans || []).find((x) => x.vlan === VLAN) || {};
  const v6 = (d.mld.vlans || []).find((x) => x.vlan === VLAN) || {};
  const q = (d.igmp.queriers || []).find((x) => x.vlan === VLAN) || {};
  const a = (d.arp.vlans || []).find((x) => x.vlan === VLAN);
  return JSON.stringify({
    igmp: v4.enabled, leave: v4.immediateLeave, mld: v6.enabled, q: q.enabled, qAddr: q.address, qVer: q.version, qElect: q.election,
    dhcp: d.dhcp.vlans.includes(VLAN), dhcpTrust: d.dhcp.trusted.includes(ifx), verifyMac: d.dhcp.verifyMac,
    arp: !!a, arpList: a ? a.list : null, arpTrust: d.arp.trusted.includes(ifx), validation: d.arp.validation, logInterval: d.arp.logInterval,
    lists: d.arp.lists.map((r) => r.name + '/' + r.ip + '/' + r.mac).sort(),
    on: [d.igmp.enabled, d.igmp.querier, d.mld.enabled, d.dhcp.enabled, d.arp.enabled]
  });
}

async function main() {
  const server = await startApp();
  const base = 'http://127.0.0.1:' + server.address().port;
  const target = { host, port: 161, version: '2c', community, timeout: 8000, retries: 1 };
  const post = async (p, body) => {
    const r = await fetch(base + p, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(Object.assign({ target }, body || {})) });
    const b = await r.json().catch(() => ({ error: 'HTTP ' + r.status }));
    return Object.assign({ httpOk: r.ok }, b);
  };
  const status = () => post('/api/security/status');

  // ---- 1. read ----------------------------------------------------------------
  const d0 = await status();
  if (!check('read the switching security settings', d0.httpOk && d0.igmp && d0.dhcp && d0.arp, d0.error || '')) return finish(server);
  if (!check('VLAN ' + VLAN + ' is on the switch', d0.vlanIds.includes(VLAN), 'VLANs: ' + d0.vlanIds.join(','))) return finish(server);
  say('  switch: IGMP snooping ' + d0.igmp.enabled + ', querier ' + d0.igmp.querier + ', MLD snooping ' + d0.mld.enabled +
    ', DHCP snooping ' + d0.dhcp.enabled + ' on VLANs ' + d0.dhcp.vlans.join(',') + ', ARP inspection ' + d0.arp.enabled +
    ' on VLANs ' + d0.arp.vlans.map((a) => a.vlan + (a.list ? '/' + a.list : '')).join(','));
  say('  IGMP snooping on VLANs ' + d0.igmp.vlans.filter((v) => v.enabled).map((v) => v.vlan).join(',') +
    '; MLD snooping on VLANs ' + d0.mld.vlans.filter((v) => v.enabled).map((v) => v.vlan).join(',') +
    '; trusted ports DHCP ' + d0.dhcp.trusted.join(',') + ', ARP ' + d0.arp.trusted.join(','));
  say('  VLAN ' + VLAN + ' and port ' + ifx + ': ' + view(d0));
  const otherDhcp = d0.dhcp.vlans.filter((v) => v !== VLAN);
  const otherArp = d0.arp.vlans.map((a) => a.vlan).filter((v) => v !== VLAN);

  const step = async (label, url, body, test) => {
    const r = await post(url, body);
    const d = await status();
    const ok = r.httpOk && test(d);
    return check(label, ok, r.error || (ok ? '' : view(d)));
  };
  const v4 = (d) => d.igmp.vlans.find((x) => x.vlan === VLAN) || {};
  const v6 = (d) => d.mld.vlans.find((x) => x.vlan === VLAN) || {};
  const qr = (d) => d.igmp.queriers.find((x) => x.vlan === VLAN) || {};
  const av = (d) => d.arp.vlans.find((x) => x.vlan === VLAN);

  if (cleanup) {
    if (d0.dhcp.vlans.includes(VLAN)) await step('DHCP snooping off on VLAN ' + VLAN, '/api/security/dhcp-vlan', { vlan: VLAN, on: false }, (d) => !d.dhcp.vlans.includes(VLAN));
    if (av(d0)) await step('ARP inspection off on VLAN ' + VLAN, '/api/security/arp-vlan', { vlan: VLAN, on: false }, (d) => !av(d));
    if (d0.dhcp.trusted.includes(ifx)) await step('port ' + ifx + ' not trusted for DHCP snooping', '/api/security/dhcp-trust', { ifIndex: ifx, on: false }, (d) => !d.dhcp.trusted.includes(ifx));
    if (d0.arp.trusted.includes(ifx)) await step('port ' + ifx + ' not trusted for ARP inspection', '/api/security/arp-trust', { ifIndex: ifx, on: false }, (d) => !d.arp.trusted.includes(ifx));
    for (const r of d0.arp.lists.filter((x) => x.name === REF_LIST || x.name === TEST_LIST)) {
      await step('removed ' + r.name + ' ' + r.ip, '/api/security/arp-list/remove', { name: r.name, ip: r.ip }, (d) => !d.arp.lists.some((x) => x.name === r.name && x.ip === r.ip));
    }
    if (qr(d0).enabled) await step('querier off on VLAN ' + VLAN, '/api/security/querier', { vlan: VLAN, enabled: false }, (d) => qr(d).enabled === false);
    if (v4(d0).enabled) await step('IGMP snooping off on VLAN ' + VLAN, '/api/security/snoop-vlan', { family: 'ipv4', vlan: VLAN, enabled: false }, (d) => v4(d).enabled === false);
    if (d0.dhcp.enabled && !otherDhcp.length) await step('DHCP snooping off for the switch', '/api/security/dhcp', { enabled: false }, (d) => d.dhcp.enabled === false);
    if (d0.arp.enabled && !otherArp.length) await step('ARP inspection off for the switch', '/api/security/arp', { enabled: false }, (d) => d.arp.enabled === false);
    const d = await status();
    say('  now: ' + view(d));
    return finish(server);
  }

  // ---- 2. multicast on the test VLAN ---------------------------------------------
  {
    const a = v4(d0), b = v6(d0), q = qr(d0);
    await step('IGMP snooping ' + (a.enabled ? 'off' : 'on') + ' on VLAN ' + VLAN, '/api/security/snoop-vlan', { family: 'ipv4', vlan: VLAN, enabled: !a.enabled }, (d) => v4(d).enabled === !a.enabled);
    await step('IGMP snooping back ' + (a.enabled ? 'on' : 'off'), '/api/security/snoop-vlan', { family: 'ipv4', vlan: VLAN, enabled: !!a.enabled }, (d) => v4(d).enabled === !!a.enabled);
    await step('immediate leave ' + (a.immediateLeave ? 'off' : 'on'), '/api/security/snoop-vlan', { family: 'ipv4', vlan: VLAN, immediateLeave: !a.immediateLeave }, (d) => v4(d).immediateLeave === !a.immediateLeave);
    await step('immediate leave back ' + (a.immediateLeave ? 'on' : 'off'), '/api/security/snoop-vlan', { family: 'ipv4', vlan: VLAN, immediateLeave: !!a.immediateLeave }, (d) => v4(d).immediateLeave === !!a.immediateLeave);
    if (b.enabled != null) {
      await step('MLD snooping ' + (b.enabled ? 'off' : 'on') + ' on VLAN ' + VLAN, '/api/security/snoop-vlan', { family: 'ipv6', vlan: VLAN, enabled: !b.enabled }, (d) => v6(d).enabled === !b.enabled);
      await step('MLD snooping back ' + (b.enabled ? 'on' : 'off'), '/api/security/snoop-vlan', { family: 'ipv6', vlan: VLAN, enabled: !!b.enabled }, (d) => v6(d).enabled === !!b.enabled);
    } else say('SKIP MLD snooping on the VLAN: not reported');
    if (!d0.mld.enabled && !d0.mld.vlans.some((v) => v.enabled)) {
      await step('MLD snooping on for the switch', '/api/security/multicast', { mld: true }, (d) => d.mld.enabled === true);
      await step('MLD snooping off again for the switch', '/api/security/multicast', { mld: false }, (d) => d.mld.enabled === false);
    } else say('SKIP MLD snooping for the switch: it is on, or a VLAN uses it');
    if (q.enabled != null) {
      await step('querier ' + (q.enabled ? 'off' : 'on') + ' on VLAN ' + VLAN, '/api/security/querier', { vlan: VLAN, enabled: !q.enabled }, (d) => qr(d).enabled === !q.enabled);
      await step('querier back ' + (q.enabled ? 'on' : 'off'), '/api/security/querier', { vlan: VLAN, enabled: !!q.enabled }, (d) => qr(d).enabled === !!q.enabled);
      await step('querier address 192.0.2.1', '/api/security/querier', { vlan: VLAN, address: '192.0.2.1' }, (d) => qr(d).address === '192.0.2.1');
      const back = q.address && q.address !== '255.255.255.255' ? q.address : '';
      await step('querier address back to ' + (back || 'automatic'), '/api/security/querier', { vlan: VLAN, address: back }, (d) => qr(d).address === q.address);
      const ver = q.version === 3 ? 2 : 3;
      await step('querier version ' + ver, '/api/security/querier', { vlan: VLAN, version: ver }, (d) => qr(d).version === ver);
      await step('querier version back to ' + q.version, '/api/security/querier', { vlan: VLAN, version: q.version }, (d) => qr(d).version === q.version);
      await step('querier election ' + (q.election ? 'off' : 'on'), '/api/security/querier', { vlan: VLAN, election: !q.election }, (d) => qr(d).election === !q.election);
      await step('querier election back ' + (q.election ? 'on' : 'off'), '/api/security/querier', { vlan: VLAN, election: !!q.election }, (d) => qr(d).election === !!q.election);
    } else say('SKIP the querier: not reported for the VLAN');
  }

  // ---- 3. DHCP snooping ------------------------------------------------------------
  {
    const on = d0.dhcp.vlans.includes(VLAN);
    await step('DHCP snooping ' + (on ? 'off' : 'on') + ' on VLAN ' + VLAN, '/api/security/dhcp-vlan', { vlan: VLAN, on: !on }, (d) => d.dhcp.vlans.includes(VLAN) === !on);
    await step('DHCP snooping back ' + (on ? 'on' : 'off'), '/api/security/dhcp-vlan', { vlan: VLAN, on }, (d) => d.dhcp.vlans.includes(VLAN) === on);
    const t = d0.dhcp.trusted.includes(ifx);
    await step('port ' + ifx + (t ? ' not' : '') + ' trusted for DHCP snooping', '/api/security/dhcp-trust', { ifIndex: ifx, on: !t }, (d) => d.dhcp.trusted.includes(ifx) === !t);
    await step('port ' + ifx + ' trust for DHCP snooping put back', '/api/security/dhcp-trust', { ifIndex: ifx, on: t }, (d) => d.dhcp.trusted.includes(ifx) === t);
    const m = !!d0.dhcp.verifyMac;
    await step('MAC check ' + (m ? 'off' : 'on'), '/api/security/dhcp', { verifyMac: !m }, (d) => d.dhcp.verifyMac === !m);
    await step('MAC check back ' + (m ? 'on' : 'off'), '/api/security/dhcp', { verifyMac: m }, (d) => d.dhcp.verifyMac === m);
  }

  // ---- 4. ARP inspection ----------------------------------------------------------
  {
    const a = av(d0);
    if (a) {
      await step('ARP inspection off on VLAN ' + VLAN, '/api/security/arp-vlan', { vlan: VLAN, on: false }, (d) => !av(d));
      await step('ARP inspection back on' + (a.list ? ' with ' + a.list : ''), '/api/security/arp-vlan', { vlan: VLAN, on: true, list: a.list || undefined }, (d) => av(d) && av(d).list === a.list);
      if (a.list) {
        await step('ARP list cleared on VLAN ' + VLAN, '/api/security/arp-vlan', { vlan: VLAN, list: '' }, (d) => av(d) && av(d).list === '');
        await step('ARP list ' + a.list + ' put back', '/api/security/arp-vlan', { vlan: VLAN, list: a.list }, (d) => av(d) && av(d).list === a.list);
      }
    } else {
      await step('ARP inspection on for VLAN ' + VLAN, '/api/security/arp-vlan', { vlan: VLAN, on: true }, (d) => !!av(d));
      await step('ARP inspection off again on VLAN ' + VLAN, '/api/security/arp-vlan', { vlan: VLAN, on: false }, (d) => !av(d));
    }
    const t = d0.arp.trusted.includes(ifx);
    await step('port ' + ifx + (t ? ' not' : '') + ' trusted for ARP inspection', '/api/security/arp-trust', { ifIndex: ifx, on: !t }, (d) => d.arp.trusted.includes(ifx) === !t);
    await step('port ' + ifx + ' trust for ARP inspection put back', '/api/security/arp-trust', { ifIndex: ifx, on: t }, (d) => d.arp.trusted.includes(ifx) === t);
    const val = !!d0.arp.validation;
    await step('packet check ' + (val ? 'off' : 'on'), '/api/security/arp', { validation: !val }, (d) => d.arp.validation === !val);
    await step('packet check back ' + (val ? 'on' : 'off'), '/api/security/arp', { validation: val }, (d) => d.arp.validation === val);
    if (d0.arp.logInterval != null && d0.arp.logInterval <= 86400) {
      const li = d0.arp.logInterval === 60 ? 120 : 60;
      await step('log interval ' + li, '/api/security/arp', { logInterval: li }, (d) => d.arp.logInterval === li);
      await step('log interval back to ' + d0.arp.logInterval, '/api/security/arp', { logInterval: d0.arp.logInterval }, (d) => d.arp.logInterval === d0.arp.logInterval);
    }
    for (const r of d0.arp.lists.filter((x) => x.name === TEST_LIST)) {
      await step('removed ' + TEST_LIST + ' ' + r.ip + ' left by an earlier run', '/api/security/arp-list/remove', { name: TEST_LIST, ip: r.ip }, (d) => !d.arp.lists.some((x) => x.name === TEST_LIST && x.ip === r.ip));
    }
    const has = (d, ip, mac) => d.arp.lists.some((x) => x.name === TEST_LIST && x.ip === ip && (!mac || x.mac === mac));
    await step('new list ' + TEST_LIST + ' with 192.0.2.30', '/api/security/arp-list/add', { name: TEST_LIST, ip: '192.0.2.30', mac: '02:00:5e:10:00:30' }, (d) => has(d, '192.0.2.30', '02:00:5e:10:00:30'));
    await step('a second entry 192.0.2.31', '/api/security/arp-list/add', { name: TEST_LIST, ip: '192.0.2.31', mac: '02:00:5e:10:00:31' }, (d) => has(d, '192.0.2.31', '02:00:5e:10:00:31'));
    await step('192.0.2.30 removed', '/api/security/arp-list/remove', { name: TEST_LIST, ip: '192.0.2.30' }, (d) => !has(d, '192.0.2.30') && has(d, '192.0.2.31'));
    await step('192.0.2.31 removed, and the list with it', '/api/security/arp-list/remove', { name: TEST_LIST, ip: '192.0.2.31' }, (d) => !d.arp.lists.some((x) => x.name === TEST_LIST));
  }

  // ---- 5. switch-wide, only when the test VLAN is the only user -------------------
  if (d0.dhcp.enabled && !otherDhcp.length) {
    await step('DHCP snooping off for the switch', '/api/security/dhcp', { enabled: false }, (d) => d.dhcp.enabled === false);
    await step('DHCP snooping on again for the switch', '/api/security/dhcp', { enabled: true }, (d) => d.dhcp.enabled === true);
  } else say('SKIP DHCP snooping for the switch: ' + (d0.dhcp.enabled ? 'VLANs ' + otherDhcp.join(',') + ' use it' : 'it is off'));
  if (d0.arp.enabled && !otherArp.length) {
    await step('ARP inspection off for the switch', '/api/security/arp', { enabled: false }, (d) => d.arp.enabled === false);
    await step('ARP inspection on again for the switch', '/api/security/arp', { enabled: true }, (d) => d.arp.enabled === true);
  } else say('SKIP ARP inspection for the switch: ' + (d0.arp.enabled ? 'VLANs ' + otherArp.join(',') + ' use it' : 'it is off'));

  // ---- the end state ------------------------------------------------------------
  {
    const d = await status();
    check('VLAN ' + VLAN + ', port ' + ifx + ' and the switch are as they were', view(d) === view(d0), view(d) + ' vs ' + view(d0));
  }
  return finish(server);
}

function finish(server) {
  const failed = results.filter((r) => !r.ok).length;
  const verdict = failed ? failed + ' CHECK(S) FAILED' : 'ALL ' + results.length + ' CHECKS PASSED';
  console.log(verdict);
  lines.push(verdict);
  console.log('Nothing was saved to startup. If the switch now says it has unsaved changes, that is from these ' + (cleanup ? 'removals.' : 'put-backs.'));
  if (outDir) {
    fs.mkdirSync(outDir, { recursive: true });
    const file = path.join(outDir, 'switch-test-security-' + host.replace(/[^0-9a-z.]/gi, '_') + '.txt');
    fs.writeFileSync(file, lines.join('\n') + '\n\n' + JSON.stringify(results, null, 2) + '\n');
    console.log('Wrote ' + file);
  }
  server.close();
  setTimeout(() => process.exit(failed ? 1 : 0), 200);
}

main().catch((e) => { console.error(e); process.exit(1); });
