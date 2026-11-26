'use strict';

/**
 * Supervised write test for IPv6 addressing (switch-ipv6.js,
 * routes/ipv6-settings.js) on a test switch. Every change is put back, and
 * nothing is saved to startup.
 *
 *   SBS_COMM=<community> node scripts/switch-test-ipv6.js <IPv4 address> [--vlan=999] [--ifindex=N] [--cleanup] [results folder]
 *
 * It works on the interface of a test VLAN (default 999, ifIndex 100998 on
 * a C1300: 99999 + the VLAN) that already has IPv6 on. The app must reach
 * the switch over IPv4, so nothing here can cut it off.
 *
 *   1. Reads everything.
 *   2. Autoconfig off and back on (or on and back off).
 *   3. A global address 2001:db8:996::2/64 added and removed. A second
 *      address in the sample's /64 (2001:db8:999::2) is tried and noted,
 *      not checked.
 *   4. A static route 2001:db8:997::/48 via 2001:db8:999::fe, metric 5,
 *      added and removed; the default route ::/0 the same way when the
 *      switch has none.
 *   5. A DNS server 2001:db8:999::54 added and removed.
 *   6. IPv6 off and back on for the interface. The addresses set by hand
 *      are taken off first (the switch keeps IPv6 on while it has one) and
 *      put back after.
 *   7. Anything the switch dropped on the way (a route or DNS server) is
 *      put back, and the end state is compared with the start.
 *
 * Each add says which way of making the row the switch took, and the ways
 * it refused first (MODULE-STANDARD rule 6).
 *
 * With --cleanup it instead removes the samples made for the recording on
 * the test VLAN: the 2001:db8:: addresses set by hand, the 2001:db8::
 * static routes through it, the 2001:db8:: DNS servers, and IPv6 on the
 * interface.
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
const outDir = args[1] || null;
const flag = (name) => { const f = flags.find((x) => x.startsWith('--' + name + '=')); return f ? f.slice(name.length + 3) : null; };
const VLAN = flag('vlan') ? Number(flag('vlan')) : 999;
const IFX = flag('ifindex') ? Number(flag('ifindex')) : 99999 + VLAN;
const cleanup = flags.includes('--cleanup');
const community = process.env.SBS_COMM;
if (!host || !community || !(VLAN >= 2 && VLAN <= 4094) || !(IFX > 0)) {
  console.error('Usage: SBS_COMM=<community> node scripts/switch-test-ipv6.js <IPv4 address> [--vlan=999] [--ifindex=N] [--cleanup] [results folder]');
  process.exit(2);
}
if (host.includes(':')) {
  console.error('Give the switch\'s IPv4 address: this test turns IPv6 off on an interface, which must not be the way the app reaches the switch.');
  process.exit(2);
}
// A second prefix: a second address in the same /64 as the sample was
// refused (WrongValue) by every form on .253, so it is tried only as a note.
const TEST_ADDR = '2001:db8:996::2';
const SAME_PREFIX = '2001:db8:999::2';
const TEST_ROUTE = '2001:db8:997::';
const NEXT_HOP = '2001:db8:999::fe';
const TEST_DNS = '2001:db8:999::54';

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
  require('../routes/ipv6-settings')(app);
  const server = http.createServer(app);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return server;
}

const iface = (d) => (d.summary || []).find((x) => x.ifIndex === IFX) || { on: false, global: [] };
const routesVia = (d) => (d.staticRoutes || []).filter((r) => r.ifIndex === IFX);
const staticDns = (d) => (d.dnsServers || []).filter((r) => r.source === 'static');
// The test interface, its routes and the DNS servers, as one comparable line.
function view(d) {
  const i = iface(d);
  return JSON.stringify({
    on: i.on, autoconfig: i.autoconfig,
    global: i.global.filter((g) => g.origin === 'manual').map((g) => g.address + '/' + g.prefixLength).sort(),
    routes: routesVia(d).map((r) => r.dest + '>' + r.nextHop + '/' + r.cost).sort(),
    dns: staticDns(d).map((r) => r.address).sort()
  });
}
const forms = (r) => (r && r.via ? ' (' + r.via + (r.refused && r.refused.length ? '; refused first: ' + r.refused.join('; ') : '') + ')' : '');

async function main() {
  const server = await startApp();
  const base = 'http://127.0.0.1:' + server.address().port;
  const target = { host, port: 161, version: '2c', community, timeout: 8000, retries: 1 };
  const post = async (p, body) => {
    const r = await fetch(base + p, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(Object.assign({ target }, body || {})) });
    const b = await r.json().catch(() => ({ error: 'HTTP ' + r.status }));
    return Object.assign({ httpOk: r.ok }, b);
  };
  const status = () => post('/api/ipv6/status');
  const step = async (label, url, body, test) => {
    const r = await post(url, body);
    const d = await status();
    const ok = r.httpOk && test(d);
    check(label + (r.httpOk ? forms(r) : ''), ok, r.error || (ok ? '' : view(d)));
    return d;
  };

  // ---- 1. read ----------------------------------------------------------------
  const d0 = await status();
  if (!check('read the IPv6 settings', d0.httpOk && Array.isArray(d0.summary), d0.error || '')) return finish(server);
  for (const i of d0.summary) {
    say('  ifIndex ' + i.ifIndex + ': IPv6 ' + i.on + ', link-local ' + i.linkLocal + ', global ' + i.global.map((g) => g.address + '/' + g.prefixLength + ' ' + g.origin).join(', ') +
      ', autoconfig ' + i.autoconfig + ', DHCPv6 ' + i.dhcp);
  }
  say('  static routes: ' + (d0.staticRoutes || []).map((r) => r.dest + ' via ' + r.nextHop + ' if ' + r.ifIndex + ' metric ' + r.cost + (r.active ? ' in use' : '')).join('; '));
  say('  DNS servers: ' + (d0.dnsServers || []).map((r) => r.address + ' ' + r.source).join('; '));
  say('  ipv6InterfaceEnableStatus: ' + (d0.interfaces || []).map((x) => x.ifIndex + '=' + (x.enabled ? 'up' : 'down')).join(', '));
  say('  VLAN ' + VLAN + ' (ifIndex ' + IFX + '): ' + view(d0));
  if (!check('VLAN ' + VLAN + ' (ifIndex ' + IFX + ') has IPv6 on', iface(d0).on, 'interfaces: ' + d0.summary.map((x) => x.ifIndex).join(','))) return finish(server);

  if (cleanup) {
    // Only the documentation-range samples (2001:db8::/32) are removed.
    const sample = (a) => /^2001:db8:/i.test(a);
    for (const g of iface(d0).global.filter((x) => x.origin === 'manual' && sample(x.address))) {
      await step('removed ' + g.address, '/api/ipv6/address/remove', { address: g.address }, (d) => !iface(d).global.some((x) => x.address === g.address));
    }
    for (const r of routesVia(d0).filter((x) => sample(x.dest))) await step('removed the route ' + r.dest, '/api/ipv6/route/remove', { index: r.index }, (d) => !(d.staticRoutes || []).some((x) => x.index === r.index));
    for (const r of staticDns(d0).filter((x) => sample(x.address))) await step('removed the DNS server ' + r.address, '/api/ipv6/dns/remove', { index: r.index }, (d) => !staticDns(d).some((x) => x.address === r.address));
    await step('IPv6 off on VLAN ' + VLAN, '/api/ipv6/enabled', { ifIndex: IFX, on: false }, (d) => !iface(d).on);
    say('  now: ' + view(await status()));
    return finish(server);
  }

  // ---- 2. autoconfig --------------------------------------------------------------
  const ac = !!iface(d0).autoconfig;
  await step('autoconfig ' + (ac ? 'off' : 'on'), '/api/ipv6/autoconfig', { ifIndex: IFX, on: !ac }, (d) => iface(d).autoconfig === !ac);
  await step('autoconfig back ' + (ac ? 'on' : 'off'), '/api/ipv6/autoconfig', { ifIndex: IFX, on: ac }, (d) => iface(d).autoconfig === ac);

  // ---- 3. an address --------------------------------------------------------------
  const hasAddr = (d, a) => iface(d).global.some((g) => g.address === a);
  if (hasAddr(d0, TEST_ADDR)) await step('removed ' + TEST_ADDR + ' left by an earlier run', '/api/ipv6/address/remove', { address: TEST_ADDR }, (d) => !hasAddr(d, TEST_ADDR));
  {
    const r = await post('/api/ipv6/address/add', { ifIndex: IFX, address: SAME_PREFIX, prefixLength: 64 });
    say('NOTE a second address in the same /64, ' + SAME_PREFIX + ': ' + (r.httpOk ? 'taken' + forms(r) : 'refused: ' + r.error));
    if (r.httpOk) await post('/api/ipv6/address/remove', { address: SAME_PREFIX });
  }
  await step('address ' + TEST_ADDR + '/64 added', '/api/ipv6/address/add', { ifIndex: IFX, address: TEST_ADDR, prefixLength: 64 },
    (d) => iface(d).global.some((g) => g.address === TEST_ADDR && g.prefixLength === 64));
  await step('address ' + TEST_ADDR + ' removed', '/api/ipv6/address/remove', { address: TEST_ADDR }, (d) => !hasAddr(d, TEST_ADDR));

  // ---- 4. static routes -----------------------------------------------------------
  const route = (d, dest) => (d.staticRoutes || []).find((r) => r.dest === dest && r.nextHop === NEXT_HOP && r.ifIndex === IFX);
  for (const [dest, len] of [[TEST_ROUTE, 48], ['::', 0]]) {
    const key = dest + '/' + len;
    if (len === 0 && (d0.staticRoutes || []).some((r) => r.dest === '::/0')) { say('SKIP the default route: the switch has one'); continue; }
    const left = route(await status(), key);
    if (left) await step('removed ' + key + ' left by an earlier run', '/api/ipv6/route/remove', { index: left.index }, (d) => !route(d, key));
    const d = await step('route ' + key + ' via ' + NEXT_HOP + ', metric 5, added', '/api/ipv6/route/add',
      { dest, prefixLength: len, nextHop: NEXT_HOP, ifIndex: IFX, cost: 5 }, (x) => route(x, key) && route(x, key).cost === 5);
    const r = route(d, key);
    if (r) await step('route ' + key + ' removed', '/api/ipv6/route/remove', { index: r.index }, (x) => !route(x, key));
  }

  // ---- 5. a DNS server ------------------------------------------------------------
  const dnsOf = (d, a) => staticDns(d).find((r) => r.address === a);
  if (dnsOf(d0, TEST_DNS)) await step('removed ' + TEST_DNS + ' left by an earlier run', '/api/ipv6/dns/remove', { index: dnsOf(d0, TEST_DNS).index }, (d) => !dnsOf(d, TEST_DNS));
  {
    const d = await step('DNS server ' + TEST_DNS + ' added', '/api/ipv6/dns/add', { address: TEST_DNS }, (x) => !!dnsOf(x, TEST_DNS));
    if (dnsOf(d, TEST_DNS)) await step('DNS server ' + TEST_DNS + ' removed', '/api/ipv6/dns/remove', { index: dnsOf(d, TEST_DNS).index }, (x) => !dnsOf(x, TEST_DNS));
  }

  // ---- 6. IPv6 off and on --------------------------------------------------------
  const manual = iface(d0).global.filter((g) => g.origin === 'manual');
  for (const g of manual) await step('took ' + g.address + ' off for the on/off test', '/api/ipv6/address/remove', { address: g.address }, (d) => !hasAddr(d, g.address));
  await step('IPv6 off on VLAN ' + VLAN + ' (the link-local address goes)', '/api/ipv6/enabled', { ifIndex: IFX, on: false }, (d) => !iface(d).on);
  await step('IPv6 on again (the link-local address comes back)', '/api/ipv6/enabled', { ifIndex: IFX, on: true }, (d) => iface(d).on);
  for (const g of manual) {
    await step(g.address + '/' + g.prefixLength + ' put back', '/api/ipv6/address/add', { ifIndex: IFX, address: g.address, prefixLength: g.prefixLength }, (d) => hasAddr(d, g.address));
  }

  // ---- 7. put back anything dropped, and compare ------------------------------------
  {
    let d = await status();
    if (!!iface(d).autoconfig !== ac) d = await step('autoconfig put back', '/api/ipv6/autoconfig', { ifIndex: IFX, on: ac }, (x) => iface(x).autoconfig === ac);
    for (const r of routesVia(d0)) {
      if ((d.staticRoutes || []).some((x) => x.index === r.index)) continue;
      const m = /^(.+)\/(\d+)$/.exec(r.dest);
      d = await step('route ' + r.dest + ' put back (the switch dropped it)', '/api/ipv6/route/add',
        { dest: m[1], prefixLength: Number(m[2]), nextHop: r.nextHop, ifIndex: IFX, cost: r.cost }, (x) => (x.staticRoutes || []).some((y) => y.index === r.index));
    }
    for (const r of staticDns(d0)) {
      if (dnsOf(d, r.address)) continue;
      d = await step('DNS server ' + r.address + ' put back (the switch dropped it)', '/api/ipv6/dns/add', { address: r.address }, (x) => !!dnsOf(x, r.address));
    }
    d = await status();
    check('VLAN ' + VLAN + ', its routes and the DNS servers are as they were', view(d) === view(d0), view(d) + ' vs ' + view(d0));
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
    const file = path.join(outDir, 'switch-test-ipv6-' + host.replace(/[^0-9a-z.]/gi, '_') + '.txt');
    fs.writeFileSync(file, lines.join('\n') + '\n\n' + JSON.stringify(results, null, 2) + '\n');
    console.log('Wrote ' + file);
  }
  server.close();
  setTimeout(() => process.exit(failed ? 1 : 0), 200);
}

main().catch((e) => { console.error(e); process.exit(1); });
