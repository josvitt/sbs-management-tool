'use strict';

/**
 * Supervised write test for Port features (switch-ports.js,
 * routes/port-features.js) on a test switch. Every change is put back, and
 * nothing is saved to startup.
 *
 *   SBS_COMM=<community> node scripts/switch-test-ports.js <address> [port ifIndex] [--look] [results folder]
 *
 * The port (default 4) should have nothing plugged in: its PoE is turned off
 * and on, it is locked for a moment, and a full cable test takes its link
 * down. The next port up is copied to it by a mirroring session.
 *
 *   1. Reads everything.
 *   2. PoE: priority, power limit, off and on again.
 *   3. Port security: lock with a 5-address limit, then put it back.
 *   4. Storm control: broadcast rate 10000, then back. With --look it waits
 *      for you to check the unit on the switch's web page.
 *   5. LLDP, CDP and EEE on the port, each changed and put back.
 *   6. Errdisable: BPDU guard recovery and the interval, changed and put back.
 *   7. CDP for the whole switch, changed and put back.
 *   8. Mirroring: copies the next port to this one in a free session, then
 *      removes it. Sessions already on the switch are left alone.
 *   9. A full cable test on the port.
 *
 * The app's own routes run on 127.0.0.1, so this tests what the panel sends.
 * No community is written to the results file.
 */

process.env.SNMP_MAX_RPS = process.env.SNMP_MAX_RPS || '20';
const fs = require('fs');
const path = require('path');
const http = require('http');
const readline = require('readline');

const flags = process.argv.slice(2).filter((a) => a.startsWith('--'));
const args = process.argv.slice(2).filter((a) => !a.startsWith('--'));
const host = args[0];
const ifx = /^\d+$/.test(args[1] || '') ? Number(args[1]) : 4;
const outDir = /^\d+$/.test(args[1] || '') ? (args[2] || null) : (args[1] || null);
const look = flags.includes('--look');
const community = process.env.SBS_COMM;
if (!host || !community) {
  console.error('Usage: SBS_COMM=<community> node scripts/switch-test-ports.js <address> [port ifIndex] [--look] [results folder]');
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
function pause(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((r) => rl.question(question, (a) => { rl.close(); r(a); }));
}

async function startApp() {
  const out = console.log;
  console.log = (...a) => { if (typeof a[0] === 'string' && /^\[[0-9T:.\-Z]+\] \[INFO\]/.test(a[0])) return; out(...a); };
  const app = require('../web');
  require('../routes/port-features')(app);
  const server = http.createServer(app);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return server;
}

const find = (list, key, v) => (list || []).find((x) => x[key] === v);

async function main() {
  const server = await startApp();
  const base = 'http://127.0.0.1:' + server.address().port;
  const target = { host, port: 161, version: '2c', community, timeout: 8000, retries: 1 };
  const post = async (p, body) => {
    const r = await fetch(base + p, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(Object.assign({ target }, body || {})) });
    const b = await r.json().catch(() => ({ error: 'HTTP ' + r.status }));
    return Object.assign({ httpOk: r.ok }, b);
  };
  const status = () => post('/api/ports/status');

  // ---- 1. read ----------------------------------------------------------------
  const d0 = await status();
  if (!check('read the port features', d0.httpOk && Array.isArray(d0.ports), d0.error || '')) return finish(server);
  if (!check('port ' + ifx + ' is a front-panel port', d0.ports.includes(ifx), 'ports: ' + d0.ports.join(','))) return finish(server);
  const src = d0.ports.find((i) => i > ifx);
  const poe0 = find(d0.poe, 'port', ifx);
  const sec0 = find(d0.security, 'ifIndex', ifx);
  const storm0 = find(d0.storm, 'ifIndex', ifx);
  const lldp0 = find(d0.lldp.ports, 'port', ifx);
  const cdp0 = find(d0.cdp.ports, 'ifIndex', ifx);
  const eee0 = find(d0.eee.ports, 'ifIndex', ifx);
  say('  PoE ' + (poe0 ? (poe0.admin ? 'on' : 'off') + ', ' + poe0.priority + ', limit ' + poe0.limitMw + ' mW, ' + poe0.detection : 'none'));
  say('  security ' + (sec0 ? (sec0.locked ? 'locked' : 'unlocked') + ', ' + sec0.mode + ', max ' + sec0.maxMacs : 'none'));
  say('  storm ' + (storm0 ? JSON.stringify(storm0.traffic) : 'none'));
  say('  LLDP ' + (lldp0 && lldp0.admin) + ', CDP ' + (cdp0 && cdp0.on) + ', EEE ' + (eee0 && eee0.admin));
  say('  errdisable interval ' + d0.errdisable.intervalSec + ' s; switch CDP ' + d0.cdp.enabled);
  say('  mirroring sessions: ' + d0.mirror.destinations.map((x) => x.session + '->' + x.ifIndex).join(', '));
  if (poe0 && poe0.detection === 'deliveringPower') {
    say('Port ' + ifx + ' is powering a device. Choose a port with nothing plugged in.');
    return finish(server);
  }

  // ---- 2. PoE -------------------------------------------------------------------
  if (poe0) {
    const P = { group: poe0.group, port: poe0.port };
    const pri = poe0.priority === 'high' ? 'critical' : 'high';
    let r = await post('/api/ports/poe', Object.assign({ priority: pri, limitMw: 15400 }, P));
    let d = await status();
    let x = find(d.poe, 'port', ifx);
    check('PoE priority ' + pri + ' and limit 15.4 W', r.httpOk && x.priority === pri && x.limitMw === 15400, r.error || ('reads ' + x.priority + ', ' + x.limitMw + ' mW'));
    r = await post('/api/ports/poe', Object.assign({ admin: false }, P));
    d = await status(); x = find(d.poe, 'port', ifx);
    check('PoE off', r.httpOk && x.admin === false, r.error || ('reads ' + x.admin + ', ' + x.detection));
    r = await post('/api/ports/poe', Object.assign({ admin: poe0.admin, priority: poe0.priority, limitMw: poe0.limitMw }, P));
    d = await status(); x = find(d.poe, 'port', ifx);
    check('PoE put back', r.httpOk && x.admin === poe0.admin && x.priority === poe0.priority && x.limitMw === poe0.limitMw, r.error || ('reads ' + x.admin + ', ' + x.priority + ', ' + x.limitMw));
  } else say('SKIP PoE: the port has none');

  // ---- 3. port security ---------------------------------------------------------
  if (sec0) {
    let r = await post('/api/ports/security', { ifIndex: ifx, mode: 'dynamic', maxMacs: 5, locked: true });
    let d = await status();
    let x = find(d.security, 'ifIndex', ifx);
    check('lock the port, learning up to 5', r.httpOk && x.locked && x.mode === 'dynamic' && x.maxMacs === 5, r.error || JSON.stringify(x));
    r = await post('/api/ports/security', { ifIndex: ifx, mode: sec0.mode, maxMacs: sec0.maxMacs, locked: sec0.locked });
    d = await status(); x = find(d.security, 'ifIndex', ifx);
    check('port security put back', r.httpOk && x.locked === sec0.locked && x.mode === sec0.mode && x.maxMacs === sec0.maxMacs, r.error || JSON.stringify(x));
  }

  // ---- 4. storm control ---------------------------------------------------------
  if (storm0 && storm0.traffic.broadcast) {
    const was = storm0.traffic.broadcast.rate;
    let r = await post('/api/ports/storm', { ifIndex: ifx, traffic: 'broadcast', rate: 10000 });
    let d = await status();
    let x = find(d.storm, 'ifIndex', ifx).traffic.broadcast;
    check('broadcast storm control at 10000', r.httpOk && x.rate === 10000, r.error || JSON.stringify(x));
    if (look && r.httpOk) {
      const a = await pause('  On the switch\'s web page, open Security > Storm Control and look at port ' + ifx + '.\n  What does it show for broadcast (the number and its unit)? Type it, then Enter: ');
      say('  the web page shows: ' + a.trim() + ' (unit ' + x.unit + ', action ' + x.action + ')');
    }
    r = await post('/api/ports/storm', { ifIndex: ifx, traffic: 'broadcast', rate: was });
    d = await status(); x = find(d.storm, 'ifIndex', ifx).traffic.broadcast;
    check('broadcast storm control put back', r.httpOk && x.rate === was, r.error || JSON.stringify(x));
  }

  // ---- 5. LLDP, CDP and EEE on the port -----------------------------------------
  for (const [key, before, other, read] of [
    ['lldp', lldp0 && lldp0.admin, lldp0 && (lldp0.admin === 'disabled' ? 'txAndRx' : 'disabled'), (d) => find(d.lldp.ports, 'port', ifx).admin],
    ['cdp', cdp0 && cdp0.on, cdp0 && !cdp0.on, (d) => find(d.cdp.ports, 'ifIndex', ifx).on],
    ['eee', eee0 && eee0.admin, eee0 && !eee0.admin, (d) => find(d.eee.ports, 'ifIndex', ifx).admin]
  ]) {
    if (before == null) { say('SKIP ' + key + ': not reported'); continue; }
    let r = await post('/api/ports/discovery', { ifIndex: ifx, [key]: other });
    let v = read(await status());
    check(key.toUpperCase() + ' on the port: ' + other, r.httpOk && v === other, r.error || ('reads ' + v));
    r = await post('/api/ports/discovery', { ifIndex: ifx, [key]: before });
    v = read(await status());
    check(key.toUpperCase() + ' on the port put back', r.httpOk && v === before, r.error || ('reads ' + v));
  }

  // ---- 6. errdisable ---------------------------------------------------------------
  {
    const c0 = find(d0.errdisable.causes, 'cause', 'stp-bpdu-guard');
    if (c0) {
      let r = await post('/api/ports/errdisable/cause', { cause: 'stp-bpdu-guard', on: !c0.recover });
      let c = find((await status()).errdisable.causes, 'cause', 'stp-bpdu-guard');
      check('BPDU guard recovery ' + (!c0.recover ? 'on' : 'off'), r.httpOk && c.recover === !c0.recover, r.error || ('reads ' + c.recover));
      r = await post('/api/ports/errdisable/cause', { cause: 'stp-bpdu-guard', on: c0.recover });
      c = find((await status()).errdisable.causes, 'cause', 'stp-bpdu-guard');
      check('BPDU guard recovery put back', r.httpOk && c.recover === c0.recover, r.error || ('reads ' + c.recover));
    }
    const i0 = d0.errdisable.intervalSec;
    if (i0 != null) {
      let r = await post('/api/ports/errdisable/interval', { seconds: i0 === 600 ? 900 : 600 });
      let v = (await status()).errdisable.intervalSec;
      check('errdisable interval changed', r.httpOk && v === (i0 === 600 ? 900 : 600), r.error || ('reads ' + v));
      r = await post('/api/ports/errdisable/interval', { seconds: i0 });
      v = (await status()).errdisable.intervalSec;
      check('errdisable interval put back', r.httpOk && v === i0, r.error || ('reads ' + v));
    }
  }

  // ---- 7. CDP for the switch ------------------------------------------------------
  if (d0.cdp.enabled != null) {
    let r = await post('/api/ports/global', { feature: 'cdp', on: !d0.cdp.enabled });
    let v = (await status()).cdp.enabled;
    check('switch CDP ' + (!d0.cdp.enabled ? 'on' : 'off'), r.httpOk && v === !d0.cdp.enabled, r.error || ('reads ' + v));
    r = await post('/api/ports/global', { feature: 'cdp', on: d0.cdp.enabled });
    v = (await status()).cdp.enabled;
    check('switch CDP put back', r.httpOk && v === d0.cdp.enabled, r.error || ('reads ' + v));
  }

  // ---- 8. mirroring -----------------------------------------------------------------
  {
    const used = d0.mirror.destinations.map((x) => x.session).concat(d0.mirror.sources.map((x) => x.session));
    const id = [1, 2, 3, 4].find((n) => !used.includes(n));
    const busy = d0.mirror.destinations.some((x) => x.ifIndex === ifx) || d0.mirror.sources.some((x) => x.index === src || x.index === ifx);
    if (!id || !src || busy) say('SKIP mirroring: no free session, or the ports are already mirrored');
    else {
      let r = await post('/api/ports/mirror/add', { session: id, dest: ifx, sources: [{ ifIndex: src, direction: 'both' }] });
      let m = (await status()).mirror;
      const dst = find(m.destinations, 'session', id);
      const s1 = m.sources.find((x) => x.session === id && x.index === src);
      check('mirror port ' + src + ' to port ' + ifx + ' in session ' + id, r.httpOk && dst && dst.ifIndex === ifx && s1 && s1.direction === 'both',
        r.error || JSON.stringify({ dst, s1 }));
      if (dst) say('  the destination row reads ' + JSON.stringify(dst));
      r = await post('/api/ports/mirror/remove', { session: id });
      m = (await status()).mirror;
      check('remove session ' + id, r.httpOk && !find(m.destinations, 'session', id) && !m.sources.some((x) => x.session === id), r.error || JSON.stringify(m));
    }
  }

  // ---- 9. cable test --------------------------------------------------------------
  {
    const r = await post('/api/ports/cable-test', { ifIndex: ifx, kind: 'full' });
    check('full cable test on port ' + ifx, r.httpOk && Array.isArray(r.results) && r.results.length > 0,
      r.error || r.results.map((x) => x.test + ' ' + x.status + ' ' + x.result + (x.units ? ' u' + x.units : '')).join('; '));
  }

  // ---- the end state ------------------------------------------------------------
  {
    const d = await status();
    const same = JSON.stringify(find(d.poe, 'port', ifx) && { a: find(d.poe, 'port', ifx).admin, p: find(d.poe, 'port', ifx).priority, l: find(d.poe, 'port', ifx).limitMw }) ===
        JSON.stringify(poe0 && { a: poe0.admin, p: poe0.priority, l: poe0.limitMw }) &&
      JSON.stringify(find(d.security, 'ifIndex', ifx)) === JSON.stringify(Object.assign({}, sec0, { macCount: (find(d.security, 'ifIndex', ifx) || {}).macCount })) &&
      JSON.stringify(find(d.storm, 'ifIndex', ifx)) === JSON.stringify(storm0) &&
      JSON.stringify(d.lldp) === JSON.stringify(d0.lldp) && d.cdp.enabled === d0.cdp.enabled &&
      JSON.stringify(d.cdp.ports) === JSON.stringify(d0.cdp.ports) &&
      JSON.stringify(d.eee.ports.map((x) => x.admin)) === JSON.stringify(d0.eee.ports.map((x) => x.admin)) &&
      JSON.stringify(d.errdisable.causes) === JSON.stringify(d0.errdisable.causes) && d.errdisable.intervalSec === d0.errdisable.intervalSec &&
      JSON.stringify(d.mirror) === JSON.stringify(d0.mirror);
    check('everything is as it was at the start', same);
  }
  finish(server);
}

function finish(server) {
  const failed = results.filter((r) => !r.ok).length;
  const verdict = failed ? failed + ' CHECK(S) FAILED' : 'ALL ' + results.length + ' CHECKS PASSED';
  console.log(verdict);
  lines.push(verdict);
  console.log('Nothing was saved to startup. If the switch now says it has unsaved changes, that is from these put-backs.');
  if (outDir) {
    fs.mkdirSync(outDir, { recursive: true });
    const file = path.join(outDir, 'switch-test-ports-' + host.replace(/[^0-9a-z.]/gi, '_') + '.txt');
    fs.writeFileSync(file, lines.join('\n') + '\n\n' + JSON.stringify(results, null, 2) + '\n');
    console.log('Wrote ' + file);
  }
  server.close();
  setTimeout(() => process.exit(failed ? 1 : 0), 200);
}

main().catch((e) => { console.error(e); process.exit(1); });
