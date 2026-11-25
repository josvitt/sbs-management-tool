'use strict';

/**
 * Supervised write test for the Spanning tree settings (switch-stp.js,
 * routes/stp-settings.js) on a test switch. Every change is put back, and
 * nothing is saved to startup.
 *
 *   SBS_COMM=<community> node scripts/switch-test-stp.js <address> [port ifIndex] [--mode] [results folder]
 *
 * The port (default 4) should have nothing plugged in: its spanning tree is
 * turned off and on again.
 *
 *   1. Reads everything.
 *   2. The port: priority, cost, PortFast, automatic PortFast, BPDU guard and
 *      spanning tree off and on, each changed and put back.
 *   3. The bridge priority for the switch, raised to 61440 (so the switch is
 *      less likely to become root, never more) and put back.
 *   4. Under PVST: the first VLAN's bridge priority, and the port's cost and
 *      priority in that VLAN. Under MSTP: the same for instance 1 if there
 *      is one.
 *   5. With --mode only: the mode changed to RSTP (or MSTP when it is RSTP)
 *      and put back. Every switch on the network rebuilds its tree twice,
 *      which stops traffic for a few seconds each time.
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
const tryMode = flags.includes('--mode');
const community = process.env.SBS_COMM;
if (!host || !community) {
  console.error('Usage: SBS_COMM=<community> node scripts/switch-test-stp.js <address> [port ifIndex] [--mode] [results folder]');
  process.exit(2);
}

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
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

async function startApp() {
  const out = console.log;
  console.log = (...a) => { if (typeof a[0] === 'string' && /^\[[0-9T:.\-Z]+\] \[INFO\]/.test(a[0])) return; out(...a); };
  const app = require('../web');
  require('../routes/stp-settings')(app);
  const server = http.createServer(app);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return server;
}

const portView = (x) => x && JSON.stringify({ on: x.enabled, pri: x.priority, cost: x.adminCost, edge: x.edge, auto: x.autoEdge, guard: x.bpduGuard });

async function main() {
  const server = await startApp();
  const base = 'http://127.0.0.1:' + server.address().port;
  const target = { host, port: 161, version: '2c', community, timeout: 8000, retries: 1 };
  const post = async (p, body) => {
    const r = await fetch(base + p, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(Object.assign({ target }, body || {})) });
    const b = await r.json().catch(() => ({ error: 'HTTP ' + r.status }));
    return Object.assign({ httpOk: r.ok }, b);
  };
  const status = () => post('/api/stp/status');

  // ---- 1. read ----------------------------------------------------------------
  const d0 = await status();
  if (!check('read the spanning tree settings', d0.httpOk && Array.isArray(d0.ports), d0.error || '')) return finish(server);
  const p0 = d0.ports.find((x) => x.ifIndex === ifx);
  if (!check('port ' + ifx + ' has spanning tree settings', !!p0, 'bridge ports: ' + d0.ports.map((x) => x.port + '=' + x.ifIndex).join(','))) return finish(server);
  const bp = p0.port;
  say('  on ' + d0.enabled + ', mode ' + d0.mode + ', priority ' + d0.priority + ', type ' + d0.type + ', supported ' + d0.supportedType);
  say('  port ' + ifx + ' (bridge port ' + bp + '): ' + portView(p0) + ', role ' + p0.role + ', cost in use ' + p0.cost);
  say('  VLAN rows: ' + d0.vlans.map((v) => v.vlan + '@' + v.priority + '/' + v.rowStatus + ' (' + v.ports.length + ' port rows)').join(', '));
  say('  instances: ' + d0.instances.map((i) => i.instance + '@' + i.priority + ' (' + i.ports.length + ' port rows)').join(', '));
  if (p0.role && p0.role !== 'disabled') say('  NOTE: port ' + ifx + ' is ' + p0.role + '; a port with nothing plugged in is better.');

  const portStep = async (label, body, test) => {
    const r = await post('/api/stp/port', Object.assign({ port: bp }, body));
    const x = (await status()).ports.find((y) => y.port === bp);
    return check(label, r.httpOk && x && test(x), r.error || portView(x));
  };

  // ---- 2. the port ----------------------------------------------------------------
  {
    const pri = p0.priority === 64 ? 96 : 64;
    await portStep('port priority ' + pri, { priority: pri }, (x) => x.priority === pri);
    await portStep('port priority back to ' + p0.priority, { priority: p0.priority }, (x) => x.priority === p0.priority);
    const cost0 = p0.adminCost == null ? 0 : p0.adminCost;
    await portStep('port cost 100000', { cost: 100000 }, (x) => x.adminCost === 100000 || x.cost === 100000);
    await portStep('port cost back to ' + (cost0 || 'automatic'), { cost: cost0 }, (x) => (x.adminCost == null ? 0 : x.adminCost) === cost0);
    await portStep('PortFast ' + (p0.edge ? 'off' : 'on'), { edge: !p0.edge }, (x) => x.edge === !p0.edge);
    await portStep('PortFast back ' + (p0.edge ? 'on' : 'off'), { edge: !!p0.edge }, (x) => x.edge === !!p0.edge);
    if (p0.autoEdge != null) {
      await portStep('automatic PortFast ' + (p0.autoEdge ? 'off' : 'on'), { autoEdge: !p0.autoEdge }, (x) => x.autoEdge === !p0.autoEdge);
      await portStep('automatic PortFast back ' + (p0.autoEdge ? 'on' : 'off'), { autoEdge: !!p0.autoEdge }, (x) => x.autoEdge === !!p0.autoEdge);
    } else say('SKIP automatic PortFast: not reported');
    await portStep('BPDU guard ' + (p0.bpduGuard ? 'off' : 'on'), { bpduGuard: !p0.bpduGuard }, (x) => x.bpduGuard === !p0.bpduGuard);
    await portStep('BPDU guard back ' + (p0.bpduGuard ? 'on' : 'off'), { bpduGuard: !!p0.bpduGuard }, (x) => x.bpduGuard === !!p0.bpduGuard);
    if (p0.enabled !== false) {
      await portStep('spanning tree off on the port', { enabled: false }, (x) => x.enabled === false);
      await portStep('spanning tree on again on the port', { enabled: true }, (x) => x.enabled === true);
    }
  }

  // ---- 3. the switch's bridge priority --------------------------------------------
  {
    let r = await post('/api/stp/priority', { priority: 61440 });
    let d = await status();
    check('bridge priority 61440', r.httpOk && d.priority === 61440, r.error || 'reads ' + d.priority);
    r = await post('/api/stp/priority', { priority: d0.priority });
    d = await status();
    check('bridge priority back to ' + d0.priority, r.httpOk && d.priority === d0.priority, r.error || 'reads ' + d.priority);
  }

  // ---- 4. per VLAN or instance ------------------------------------------------------
  const perVlan = d0.mode === 'pvst' || d0.mode === 'rapid-pvst';
  const where = perVlan ? (d0.vlans[0] ? { key: 'vlan', id: d0.vlans[0].vlan, row: d0.vlans[0] } : { key: 'vlan', id: 1, row: null })
    : (d0.mode === 'mstp' && d0.instances.find((i) => i.instance >= 1) ? { key: 'instance', id: d0.instances.find((i) => i.instance >= 1).instance } : null);
  if (where) {
    if (perVlan && !where.row) say('  NOTE: the switch lists no VLAN rows; trying VLAN 1 to see what it answers.');
    const list = (d) => (where.key === 'vlan' ? d.vlans.map((v) => ({ id: v.vlan, priority: v.priority, ports: v.ports })) : d.instances.map((i) => ({ id: i.instance, priority: i.priority, ports: i.ports })));
    const before = list(d0).find((x) => x.id === where.id) || { priority: 32768, ports: [] };
    const W = {}; W[where.key] = where.id;
    let r = await post('/api/stp/priority', Object.assign({ priority: 61440 }, W));
    let x = list(await status()).find((y) => y.id === where.id);
    check(where.key + ' ' + where.id + ' bridge priority 61440', r.httpOk && x && x.priority === 61440, r.error || JSON.stringify(x && { priority: x.priority }));
    r = await post('/api/stp/priority', Object.assign({ priority: before.priority == null ? 32768 : before.priority }, W));
    x = list(await status()).find((y) => y.id === where.id);
    check(where.key + ' ' + where.id + ' bridge priority back to ' + before.priority, r.httpOk && x && x.priority === before.priority, r.error || JSON.stringify(x && { priority: x.priority }));

    const row0 = (before.ports || []).find((y) => y.port === bp);
    say('  port ' + ifx + ' in ' + where.key + ' ' + where.id + ': ' + JSON.stringify(row0 || null));
    const cost0 = row0 ? (row0.cost != null ? row0.cost : (row0.adminCost || 0)) : 0;
    const pri0 = row0 && row0.priority != null ? row0.priority : 128;
    const pri = pri0 === 64 ? 96 : 64;
    r = await post('/api/stp/port-in', Object.assign({ port: bp, priority: pri, cost: 200000 }, W));
    let row = ((list(await status()).find((y) => y.id === where.id) || {}).ports || []).find((y) => y.port === bp);
    check('port ' + ifx + ' in ' + where.key + ' ' + where.id + ': priority ' + pri + ', cost 200000',
      r.httpOk && row && row.priority === pri && (row.cost === 200000 || row.adminCost === 200000), r.error || JSON.stringify(row || null));
    r = await post('/api/stp/port-in', Object.assign({ port: bp, priority: pri0, cost: cost0 }, W));
    row = ((list(await status()).find((y) => y.id === where.id) || {}).ports || []).find((y) => y.port === bp);
    check('port ' + ifx + ' in ' + where.key + ' ' + where.id + ' back', r.httpOk && (!row0 ? true : (row && row.priority === pri0)), r.error || JSON.stringify(row || null));
  } else say('SKIP per VLAN or instance: mode ' + d0.mode + ' has none to try');

  // ---- 5. the mode (only with --mode) ------------------------------------------------
  if (tryMode) {
    const other = d0.mode === 'rstp' ? 'mstp' : 'rstp';
    let r = await post('/api/stp/mode', { mode: other });
    await wait(5000);
    let d = await status();
    check('mode ' + other, r.httpOk && d.mode === other, r.error || 'reads ' + d.mode);
    r = await post('/api/stp/mode', { mode: d0.mode });
    await wait(5000);
    d = await status();
    check('mode back to ' + d0.mode, r.httpOk && d.mode === d0.mode, r.error || 'reads ' + d.mode);
  } else say('SKIP the mode: run with --mode to try it');

  // ---- the end state ------------------------------------------------------------
  {
    const d = await status();
    const p = d.ports.find((x) => x.port === bp);
    check('port ' + ifx + ' is as it was', portView(p) === portView(p0), portView(p) + ' vs ' + portView(p0));
    check('the switch is as it was', d.priority === d0.priority && d.mode === d0.mode && d.enabled === d0.enabled,
      'priority ' + d.priority + ', mode ' + d.mode + ', on ' + d.enabled);
  }
  return finish(server);
}

function finish(server) {
  const failed = results.filter((r) => !r.ok).length;
  const verdict = failed ? failed + ' CHECK(S) FAILED' : 'ALL ' + results.length + ' CHECKS PASSED';
  console.log(verdict);
  lines.push(verdict);
  console.log('Nothing was saved to startup. If the switch now says it has unsaved changes, that is from these put-backs.');
  if (outDir) {
    fs.mkdirSync(outDir, { recursive: true });
    const file = path.join(outDir, 'switch-test-stp-' + host.replace(/[^0-9a-z.]/gi, '_') + '.txt');
    fs.writeFileSync(file, lines.join('\n') + '\n\n' + JSON.stringify(results, null, 2) + '\n');
    console.log('Wrote ' + file);
  }
  server.close();
  setTimeout(() => process.exit(failed ? 1 : 0), 200);
}

main().catch((e) => { console.error(e); process.exit(1); });
