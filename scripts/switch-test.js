'use strict';

/**
 * Supervised write test on one switch port. Run it only with the owner's
 * approval, on the port the owner chose (gi1/0/4 on the test switch).
 *
 *   SBS_COMM=<community> node scripts/switch-test.js <switch address> [ifIndex] [results folder]
 *
 * It starts the app's own SNMP routes on 127.0.0.1 and sends every write
 * through the dashboard's own code (public/src via scripts/lib/browser-writes),
 * so the SETs are exactly the ones the panels send:
 *
 *   1. A switchport change the "switch" refuses part-way (the refusal is
 *      forced here, before it leaves), and the app's undo.
 *   2. Routed mode ("no switchport"), a static address, a static route, the
 *      DHCP client (skipped when the port has a link), then a refused return
 *      to switchport whose undo must put the address back.
 *   3. Back to a switchport through the editor's own path.
 *   4. A nameserver, a search domain and a host mapping, added and deleted.
 *
 * It records everything it touches first, compares at the end, puts back
 * anything that still differs, and ends with RESTORED OK or NOT RESTORED.
 * It never saves the configuration (no rlCopy write is ever sent), so a
 * reboot of the switch would also bring back the saved state.
 */

process.env.SNMP_MAX_RPS = process.env.SNMP_MAX_RPS || '20';
const fs = require('fs');
const path = require('path');
const http = require('http');
const { loadBrowserWrites } = require('./lib/browser-writes');

const host = process.argv[2];
const ifIndex = parseInt(process.argv[3] || '4', 10);
const outDir = process.argv[4] || null;
const community = process.env.SBS_COMM;
if (!host || !community || !Number.isFinite(ifIndex)) {
  console.error('Usage: SBS_COMM=<community> node scripts/switch-test.js <address> [ifIndex] [results folder]');
  process.exit(2);
}

// Test values that cannot clash with a real network: a /30 and a /24 from
// 10.253.244-245, a documentation-range nameserver and a .invalid domain.
const T = {
  ip: process.env.SBS_TEST_IP || '10.253.244.1',
  mask: '255.255.255.252',
  nextHop: process.env.SBS_TEST_NEXTHOP || '10.253.244.2',
  routeDest: process.env.SBS_TEST_ROUTE || '10.253.245.0',
  routeMask: '255.255.255.0',
  nameserver: '192.0.2.53',
  domain: 'sbs-test.invalid',
  hostName: 'sbs-test-host',
  hostAddr: '192.0.2.10'
};

const lines = [];
function say(msg) { const l = '[' + new Date().toISOString().slice(11, 19) + '] ' + msg; lines.push(l); console.log(l); }
const results = [];
function check(name, ok, detail) {
  results.push({ name, ok: !!ok, detail: detail || '' });
  say((ok ? 'PASS ' : 'FAIL ') + name + (detail ? ': ' + detail : ''));
  return !!ok;
}
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

// ---- the app's SNMP routes, in this process --------------------------------
async function startApp() {
  // The app's own request log still goes to logs/app.log; on screen, only
  // its warnings and errors, so the test's lines stay readable.
  const out = console.log;
  console.log = (...a) => { if (typeof a[0] === 'string' && /^\[[0-9T:.\-Z]+\] \[INFO\]/.test(a[0])) return; out(...a); };
  const app = require('../web');
  require('../routes/snmp')(app);
  const server = http.createServer(app);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return server;
}

async function main() {
  // The dashboard service polls the switch with the previous version, which
  // does not hold its reads during a write. Two writers is also two sets of
  // readings. Ask for it to be stopped first.
  if (!process.env.SBS_SERVICE_RUNNING_OK) {
    const up = await new Promise((r) => {
      const req = http.get({ host: '127.0.0.1', port: 3000, path: '/', timeout: 1500 }, (res) => { res.resume(); r(true); });
      req.on('error', () => r(false));
      req.on('timeout', () => { req.destroy(); r(false); });
    });
    if (up) {
      console.error('The SBS Management Tool is running on this PC (port 3000). Stop it first, then run this again.');
      process.exit(3);
    }
  }

  const server = await startApp();
  const base = 'http://127.0.0.1:' + server.address().port;
  let forced = null;   // { match(vbs) -> bool, error } refuses one SET once
  const w = loadBrowserWrites({
    fetch: (p, init) => fetch(base + p, init),
    onSet: (vbs) => {
      if (forced && forced.match(vbs)) { const e = forced.error; forced = null; say('  (refused here, not sent: ' + vbs[0].oid + ')'); return e; }
      return null;
    }
  });
  const s = { target: { host, port: 161, version: '2c', community, timeout: 5000, retries: 1 }, host };

  // Reads go straight to the switch as raw varbinds (exact bytes, so the
  // before/after compare and the put-back are exact). Writes go through the app.
  const snmp = require('net-snmp');
  const core = require('../snmp-core');
  const enc = (v) => (Buffer.isBuffer(v) ? 'hex:' + v.toString('hex') : String(v));
  const get = (oids) => new Promise((resolve, reject) => {
    const sess = core.buildSnmpSession(s.target);
    sess.on('error', () => {});
    sess.get(core.resolveOids(oids), (err, vbs) => {
      sess.close();
      if (err) return reject(new Error('GET failed: ' + err.message));
      resolve(vbs.map((vb) => (snmp.isVarbindError(vb) ? { oid: vb.oid, value: null, error: snmp.varbindError(vb) } : { oid: vb.oid, value: enc(vb.value) })));
    });
  });
  const walk = (oid) => new Promise((resolve, reject) => {
    const sess = core.buildSnmpSession(s.target);
    sess.on('error', () => {});
    core.boundedWalk(sess, core.resolveOids([oid])[0], { raw: true, maxRows: 4000 }, (err, rows) => {
      sess.close();
      if (err) return reject(new Error('walk ' + oid + ' failed: ' + err.message));
      resolve(rows.map((vb) => ({ oid: vb.oid, value: enc(vb.value) })));
    });
  });
  const val = (r) => (r == null ? null : r.value);
  const idxOf = (base, oid) => (oid.startsWith(base + '.') ? oid.slice(base.length + 1) : null);

  const PORT_OIDS = ['vlanSwitchPortModeCategory', 'vlanPortModeState', 'vlanAccessPortModeVlanId',
    'vlanTrunkPortModeNativeVlanId', 'vlanTrunkModeList1to1024', 'vlanTrunkModeList1025to2048',
    'vlanTrunkModeList2049to3072', 'vlanTrunkModeList3073to4094'];
  const TABLES = {
    addresses: w.SVI_IP.ifIndex, addressMasks: w.SVI_IP.netmask,
    dhcpClients: w.DHCP_CL.status,
    staticRoutes: w.DNS_ROUTE.srRowStatus,
    nameservers: w.DNS_ROUTE.v2ServerStatus, nameserverRows: w.DNS_ROUTE.nsInetStatus,
    domains: w.DNS_ROUTE.domRowStatus, hosts: w.DNS_ROUTE.hostRowStatus,
    vlanEgress: '1.3.6.1.2.1.17.7.1.4.3.1.2', vlanUntagged: '1.3.6.1.2.1.17.7.1.4.3.1.4'
  };

  async function snapshot() {
    const port = {};
    const rows = await get(PORT_OIDS.map((n) => n + '.' + ifIndex).concat(['rlDnsClEnable.0']));
    PORT_OIDS.forEach((n, i) => { port[n] = { value: rows[i].value, error: rows[i].error }; });
    const dnsEnable = val(rows[PORT_OIDS.length]);
    const tables = {};
    for (const [k, oid] of Object.entries(TABLES)) {
      tables[k] = {};
      for (const r of await walk(oid)) tables[k][idxOf(oid, r.oid) || r.oid] = r.value;
    }
    return { port, dnsEnable, tables };
  }
  const short = (v) => String(v).replace(/(00)+$/, '..');
  function differences(a, b) {
    const out = [];
    for (const n of PORT_OIDS) if (JSON.stringify(a.port[n]) !== JSON.stringify(b.port[n])) out.push('port ' + n + ': ' + short(a.port[n].value) + ' -> ' + short(b.port[n].value));
    if (String(a.dnsEnable) !== String(b.dnsEnable)) out.push('rlDnsClEnable: ' + a.dnsEnable + ' -> ' + b.dnsEnable);
    for (const k of Object.keys(TABLES)) {
      const keys = new Set(Object.keys(a.tables[k]).concat(Object.keys(b.tables[k])));
      for (const i of keys) if (a.tables[k][i] !== b.tables[k][i]) out.push(k + ' ' + i + ': ' + (a.tables[k][i] || '(none)') + ' -> ' + (b.tables[k][i] || '(none)'));
    }
    return out;
  }

  // ---- before anything is written ------------------------------------------
  say('Switch ' + host + ', ifIndex ' + ifIndex + '. Reading the current state.');
  const name = await get(['ifName.' + ifIndex, 'ifOperStatus.' + ifIndex]);
  const portName = Buffer.from(String(name[0].value || '').replace(/^hex:/, ''), 'hex').toString('latin1');
  const linkUp = parseInt(val(name[1]), 10) === 1;
  say('Port ' + portName + ', link ' + (linkUp ? 'up' : 'down') + '.');
  const before = await snapshot();
  const cat = parseInt(before.port.vlanSwitchPortModeCategory.value, 10);
  const mode = parseInt(before.port.vlanPortModeState.value, 10);
  const accessVlan = parseInt(before.port.vlanAccessPortModeVlanId.value, 10);
  const nativeVlan = parseInt(before.port.vlanTrunkPortModeNativeVlanId.value, 10);
  const vlansOnSwitch = Object.keys(before.tables.vlanEgress).map((i) => parseInt(i.split('.').pop(), 10)).filter(Number.isFinite).sort((a, b) => a - b);

  // Stop before writing anything unless every safety condition holds.
  const stop = (why) => { say('STOPPED before any write: ' + why); finish(server, 'NOT STARTED'); };
  if (!/(^|[^0-9])1\/0\/4$|gi1\/0\/4/i.test(portName) && !process.env.SBS_TEST_ANY_PORT) return stop('ifIndex ' + ifIndex + ' is "' + portName + '", not gi1/0/4.');
  if (cat !== 1) return stop('the port is not a switchport now (category ' + cat + ').');
  if (mode !== 11 && mode !== 12) return stop('the port is in mode ' + mode + ', not access or trunk.');
  const mgmt = Object.entries(before.tables.addresses).find(([ip]) => ip === host);
  if (mgmt && parseInt(mgmt[1], 10) === ifIndex) return stop('the switch’s management address is on this port.');
  if (before.tables.addresses[T.ip] || Object.keys(before.tables.staticRoutes).some((k) => k.startsWith(T.routeDest + '.'))) return stop('the test addresses ' + T.ip + ' / ' + T.routeDest + ' are already in use.');
  const otherVlan = vlansOnSwitch.find((v) => v !== accessVlan);
  if (mode === 11 && !Number.isFinite(otherVlan)) return stop('there is no second VLAN to move the port to.');
  // The port as the editor sees it (what switchportBefore records).
  const editorBefore = mode === 11
    ? { mode: 'access', access: accessVlan, tagged: [], addrs: [] }
    : { mode: 'trunk', native: nativeVlan, tagged: vlansOnSwitch.filter((v) => (portBits(before.tables.vlanEgress, v))), addrs: [] };
  function portBits(table, vlan) {
    const hex = Object.entries(table).find(([i]) => parseInt(i.split('.').pop(), 10) === vlan);
    if (!hex) return false;
    const bytes = String(hex[1]).replace(/^hex:/, '');
    const byte = parseInt(bytes.substr(Math.floor((ifIndex - 1) / 8) * 2, 2) || '0', 16);
    return !!(byte & (0x80 >> ((ifIndex - 1) % 8)));
  }
  say('Before: ' + (mode === 11 ? 'access VLAN ' + accessVlan : 'trunk, native ' + nativeVlan + ', VLANs ' + editorBefore.tagged.join(',')) + '. VLANs on the switch: ' + vlansOnSwitch.join(',') + '.');

  const portNow = async () => {
    const r = await get(['vlanSwitchPortModeCategory.' + ifIndex, 'vlanPortModeState.' + ifIndex, 'vlanAccessPortModeVlanId.' + ifIndex, 'vlanTrunkPortModeNativeVlanId.' + ifIndex]);
    return { cat: parseInt(val(r[0]), 10), mode: parseInt(val(r[1]), 10), access: parseInt(val(r[2]), 10), native: parseInt(val(r[3]), 10) };
  };
  const addrRow = async (ip) => {
    const rows = await walk(w.SVI_IP.ifIndex);
    const r = rows.find((x) => idxOf(w.SVI_IP.ifIndex, x.oid) === ip);
    return r ? parseInt(val(r), 10) : null;
  };

  try {
    // ---- 1. a switchport change refused part-way, and the undo -------------
    say('1. Switchport change refused on its last step.');
    const change = mode === 11
      ? { ifIndex, mode: 'access', access: otherVlan, wasRouted: false, before: editorBefore }
      : { ifIndex, mode: 'trunk', native: nativeVlan, tagged: editorBefore.tagged.filter((v) => v !== nativeVlan).slice(0, -1), wasRouted: false, before: editorBefore };
    forced = { match: (vbs) => vbs[0].oid.startsWith('vlanPortModeState.'), error: 'WrongValue' };
    const r1 = await w.applySwitchportConfig(s, change);
    forced = null;
    r1.log.forEach((l) => say('   ' + l));
    check('refused change reports failure and restored', !r1.ok && r1.restored === true, 'ok=' + r1.ok + ' restored=' + r1.restored);
    const p1 = await portNow();
    check('port is back as it was', p1.cat === 1 && p1.mode === mode && (mode === 11 ? p1.access === accessVlan : p1.native === nativeVlan),
      JSON.stringify(p1));

    // ---- 2. routed mode, address, route, DHCP ------------------------------
    say('2. Routed mode ("no switchport").');
    const r2 = await w.applySwitchportConfig(s, { ifIndex, mode: 'routed', wasRouted: false, before: editorBefore });
    r2.log.forEach((l) => say('   ' + l));
    check('no switchport accepted', r2.ok);
    check('port reads back as routed', (await portNow()).cat === 2);
    await wait(2500);   // the address write is refused for about 2 s after the category change

    say('   Static address ' + T.ip + '/30.');
    try { await w.snmpSet(s, w.ifAddressVarbinds(T.ip, T.mask, ifIndex)); check('address accepted', true); }
    catch (e) { check('address accepted', false, e.message); }
    check('address reads back on this port', (await addrRow(T.ip)) === ifIndex);

    say('   Static route ' + T.routeDest + '/24 via ' + T.nextHop + '.');
    const rr = await w.snmpSetResult(s, w.staticRouteVarbinds(T.routeDest, T.routeMask, T.nextHop, 1));
    const routeErr = (rr.body && rr.body.error) || ((rr.body && rr.body.results) || []).map((x) => x.error).filter(Boolean)[0];
    const routeIdx = [T.routeDest, T.routeMask, '0', T.nextHop].join('.');
    if (check('static route accepted', rr.ok && !routeErr, routeErr || '')) {
      const rows = await walk(w.DNS_ROUTE.srRowStatus);
      check('route reads back', rows.some((x) => idxOf(w.DNS_ROUTE.srRowStatus, x.oid) === routeIdx));
      const del = await w.rowStatusDelete(s, w.DNS_ROUTE.srRowStatus + '.' + routeIdx);
      check('route deleted', del.ok && !(del.body && del.body.error), del.body && del.body.error);
      const after = await walk(w.DNS_ROUTE.srRowStatus);
      check('route is gone', !after.some((x) => idxOf(w.DNS_ROUTE.srRowStatus, x.oid) === routeIdx));
    }

    say('   Returning to switchport, refused at the category step: the undo must bring the address back.');
    forced = { match: (vbs) => vbs[0].oid === 'vlanSwitchPortModeCategory.' + ifIndex && vbs[0].value === 1, error: 'InconsistentValue' };
    const back1 = Object.assign({}, editorBefore, { ifIndex, wasRouted: true, before: { mode: 'routed', addrs: [{ ip: T.ip, mask: T.mask, owner: 1 }] } });
    const r3 = await w.applySwitchportConfig(s, back1);
    forced = null;
    r3.log.forEach((l) => say('   ' + l));
    check('refused return reports failure and restored', !r3.ok && r3.restored === true, 'ok=' + r3.ok + ' restored=' + r3.restored);
    check('port is still routed', (await portNow()).cat === 2);
    check('address is back on this port', (await addrRow(T.ip)) === ifIndex);

    say('   Removing the address.');
    const rm = await w.removeIfAddress(s, ifIndex, { ip: T.ip }, false);
    check('address removed', rm.ok, rm.error);
    check('address is gone', (await addrRow(T.ip)) === null);

    if (linkUp) say('   DHCP client skipped: the port has a link, and a lease could add a route.');
    else {
      say('   DHCP client on.');
      try { await w.snmpSet(s, { oid: w.DHCP_CL.status + '.' + ifIndex, type: 'Integer', value: 4 }); check('DHCP client accepted', true); }
      catch (e) { check('DHCP client accepted', false, e.message); }
      const on = await walk(w.DHCP_CL.status);
      check('DHCP client reads back', on.some((x) => idxOf(w.DHCP_CL.status, x.oid) === String(ifIndex)));
      const off = await w.removeIfAddress(s, ifIndex, null, true);
      check('DHCP client removed', off.ok, off.error);
      const gone = await walk(w.DHCP_CL.status);
      check('DHCP client is gone', !gone.some((x) => idxOf(w.DHCP_CL.status, x.oid) === String(ifIndex)));
    }

    // ---- 3. back to a switchport, the editor's own path ---------------------
    say('3. Back to switchport as it was.');
    const r4 = await w.applySwitchportConfig(s, Object.assign({}, editorBefore, { ifIndex, wasRouted: true, before: { mode: 'routed', addrs: [] } }));
    r4.log.forEach((l) => say('   ' + l));
    check('switchport accepted', r4.ok);
    const p4 = await portNow();
    check('port reads back as before', p4.cat === 1 && p4.mode === mode && (mode === 11 ? p4.access === accessVlan : p4.native === nativeVlan), JSON.stringify(p4));

    // ---- 4. DNS -------------------------------------------------------------
    say('4. Nameserver ' + T.nameserver + '.');
    const ns = await w.snmpSetResult(s, w.nameserverVarbinds(T.nameserver));
    if (check('nameserver accepted', ns.ok && !(ns.body && ns.body.error), ns.body && ns.body.error)) {
      const rows = await walk(w.DNS_ROUTE.v2ServerStatus);
      const row = rows.find((x) => { const d = w.dnsV2ServerIndex(idxOf(w.DNS_ROUTE.v2ServerStatus, x.oid)); return d && d.addr === T.nameserver; });
      if (check('nameserver reads back', !!row)) {
        const del = await w.rowStatusDelete(s, row.oid);
        check('nameserver deleted', del.ok && !(del.body && del.body.error), del.body && del.body.error);
      }
    }
    say('   Search domain ' + T.domain + '.');
    const dm = await w.snmpSetResult(s, w.dnsDomainVarbinds(T.domain));
    if (check('domain accepted', dm.ok && !(dm.body && dm.body.error), dm.body && dm.body.error)) {
      const idx = w.dnsNameIndex(T.domain);
      const rows = await walk(w.DNS_ROUTE.domRowStatus);
      check('domain reads back', rows.some((x) => idxOf(w.DNS_ROUTE.domRowStatus, x.oid) === idx));
      const del = await w.rowStatusDelete(s, w.DNS_ROUTE.domRowStatus + '.' + idx);
      check('domain deleted', del.ok && !(del.body && del.body.error), del.body && del.body.error);
    }
    say('   Host mapping ' + T.hostName + ' = ' + T.hostAddr + '.');
    const hm = await w.snmpSetResult(s, w.dnsHostVarbinds(T.hostName, T.hostAddr));
    if (check('host mapping accepted', hm.ok && !(hm.body && hm.body.error), hm.body && hm.body.error)) {
      const idx = w.dnsHostIndex(T.hostName);
      const rows = await walk(w.DNS_ROUTE.hostRowStatus);
      check('host mapping reads back', rows.some((x) => idxOf(w.DNS_ROUTE.hostRowStatus, x.oid) === idx));
      const del = await w.rowStatusDelete(s, w.DNS_ROUTE.hostRowStatus + '.' + idx);
      check('host mapping deleted', del.ok && !(del.body && del.body.error), del.body && del.body.error);
    }
  } catch (e) {
    check('test ran to the end', false, e.message);
  } finally {
    forced = null;
  }

  // ---- compare, and put back anything that still differs --------------------
  await wait(1500);
  let after = await snapshot();
  let diff = differences(before, after);
  if (diff.length) {
    say('Differences after the test (the app’s own steps left these):');
    diff.forEach((d) => say('   ' + d));
    check('app steps left the switch as it was', false, diff.length + ' difference(s)');
    await putBack(w, s, before, after);
    await wait(1500);
    after = await snapshot();
    diff = differences(before, after);
  } else {
    check('app steps left the switch as it was', true);
  }
  if (diff.length) { say('Still different after putting back:'); diff.forEach((d) => say('   ' + d)); }
  const failed = results.filter((r) => !r.ok).length;
  say(results.length + ' checks, ' + failed + ' failed. The configuration was not saved.');
  finish(server, diff.length ? 'NOT RESTORED' : 'RESTORED OK');

  // Raw put-back: the port's recorded columns, then any row the test added.
  async function putBack(wr, sess, b, a) {
    say('Putting the recorded state back directly.');
    const extra = (k) => Object.keys(a.tables[k]).filter((i) => !(i in b.tables[k]));
    for (const i of extra('staticRoutes')) await wr.rowStatusDelete(sess, TABLES.staticRoutes + '.' + i);
    for (const i of extra('nameservers')) await wr.rowStatusDelete(sess, TABLES.nameservers + '.' + i);
    for (const i of extra('nameserverRows')) await wr.rowStatusDelete(sess, TABLES.nameserverRows + '.' + i);
    for (const i of extra('domains')) await wr.rowStatusDelete(sess, TABLES.domains + '.' + i);
    for (const i of extra('hosts')) await wr.rowStatusDelete(sess, TABLES.hosts + '.' + i);
    for (const i of extra('dhcpClients')) await wr.snmpSetResult(sess, { oid: TABLES.dhcpClients + '.' + i, type: 'Integer', value: 6 });
    for (const i of extra('addresses')) await wr.snmpSetResult(sess, { oid: wr.SVI_IP.status + '.' + i, type: 'Integer', value: 2 });
    const P = b.port;
    if (parseInt(a.port.vlanSwitchPortModeCategory.value, 10) !== parseInt(P.vlanSwitchPortModeCategory.value, 10)) {
      await wr.snmpSetResult(sess, { oid: 'vlanSwitchPortModeCategory.' + ifIndex, type: 'Integer', value: parseInt(P.vlanSwitchPortModeCategory.value, 10) });
      await wait(2500);
    }
    const hexOf = (c) => String(c.value || '').replace(/^hex:/, '');
    const steps = [
      { oid: 'vlanTrunkPortModeNativeVlanId.' + ifIndex, type: 'Gauge', value: parseInt(P.vlanTrunkPortModeNativeVlanId.value, 10) },
      ...['vlanTrunkModeList1to1024', 'vlanTrunkModeList1025to2048', 'vlanTrunkModeList2049to3072', 'vlanTrunkModeList3073to4094']
        .map((n) => ({ oid: n + '.' + ifIndex, type: 'OctetString', valueHex: hexOf(P[n]) })),
      { oid: 'vlanAccessPortModeVlanId.' + ifIndex, type: 'Gauge', value: parseInt(P.vlanAccessPortModeVlanId.value, 10) },
      { oid: 'vlanPortModeState.' + ifIndex, type: 'Integer', value: parseInt(P.vlanPortModeState.value, 10) }
    ];
    for (const vb of steps) {
      if (JSON.stringify(a.port[vb.oid.split('.')[0]]) === JSON.stringify(P[vb.oid.split('.')[0]])) continue;
      const r = await wr.snmpSetResult(sess, vb);
      say('   ' + vb.oid + ': ' + ((r.body && r.body.error) || ((r.body && r.body.results) || []).map((x) => x.error).filter(Boolean)[0] || 'ok'));
    }
  }
}

function finish(server, verdict) {
  console.log(verdict);
  lines.push(verdict);
  if (outDir) {
    fs.mkdirSync(outDir, { recursive: true });
    const file = path.join(outDir, 'switch-test-' + host.replace(/[^0-9a-z.]/gi, '_') + '.txt');
    fs.writeFileSync(file, lines.join('\n') + '\n\n' + JSON.stringify(results, null, 2) + '\n');
    console.log('Wrote ' + file);
  }
  server.close();
  setTimeout(() => process.exit(verdict === 'RESTORED OK' ? 0 : 1), 200);
}

main().catch((e) => { console.error(e); process.exit(1); });
