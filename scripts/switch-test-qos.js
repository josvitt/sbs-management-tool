'use strict';

/**
 * Supervised write test for QoS (switch-qos.js, routes/qos-settings.js) on
 * a test switch. Every change is put back, and nothing is saved to startup.
 *
 *   SBS_COMM=<community> node scripts/switch-test-qos.js <address> [--port=4] [--port2=5] [--cleanup] [results folder]
 *
 * --port is the port with the CLI samples (gi1/0/4, ifIndex 4, on .253);
 * --port2 is a port with no queue shaper, for making a shape profile. The
 * rates used are 500,000 kb/s, so traffic on the ports is not held back.
 *
 *   1. Reads everything.
 *   2. The trust mode changed and put back; the QoS mode set to advanced
 *      and back to what it was.
 *   3. Trust off and back on (or on and back off) for the port.
 *   4. The port's rate limit, shaper, and the shaper of queue 3 changed and
 *      put back.
 *   5. Queue 5 shaped on the second port (a new shape profile) and turned
 *      off again (the profile is removed).
 *   6. CoS 5 and DSCP 10 sent to another queue and put back; the CoS map
 *      put back to the defaults with "Put back the defaults" when it started
 *      at the defaults.
 *   7. Anything that changed on the way is put back, and the end state is
 *      compared with the start.
 *
 * Each change says which way of writing it the switch took, and the ways it
 * refused first (MODULE-STANDARD rule 6).
 *
 * With --cleanup it instead removes the CLI samples on --port: the rate
 * limit, the port shaper and the queue shapers, and puts the CoS and DSCP
 * maps back to the defaults.
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
const P = flag('port') ? Number(flag('port')) : 4;
const P2 = flag('port2') ? Number(flag('port2')) : 5;
const cleanup = flags.includes('--cleanup');
const community = process.env.SBS_COMM;
if (!host || !community || !(P > 0 && P < 1000) || !(P2 > 0 && P2 < 1000) || P === P2) {
  console.error('Usage: SBS_COMM=<community> node scripts/switch-test-qos.js <address> [--port=4] [--port2=5] [--cleanup] [results folder]');
  process.exit(2);
}
const RATE = 500000;

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
  require('../routes/qos-settings')(app);
  const server = http.createServer(app);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return server;
}

const port = (d, ifx) => (d.ports || []).find((x) => x.ifIndex === ifx);
const qShaped = (d, ifx, q) => { const x = port(d, ifx); return ((x && x.queueShaper && x.queueShaper.queues) || []).find((y) => y.queue === q); };
const cosQ = (d, c) => ((d.cosMap || []).find((m) => m.cos === c) || {}).queue;
const dscpQ = (d, v) => ((d.dscpMap || []).find((m) => m.dscp === v) || {}).queue;
const portView = (x) => (x ? {
  trust: x.trust, rateLimit: x.rateLimit, shaper: x.shaper.on ? x.shaper.cir + '/' + x.shaper.cbs : 'off',
  queues: ((x.queueShaper && x.queueShaper.queues) || []).map((q) => q.queue + ':' + q.cir + '/' + q.cbs).join(',')
} : null);
// The mode, the two test ports and the maps, as one comparable line.
function view(d) {
  return JSON.stringify({
    mode: d.mode, basicTrust: d.basicTrust, advancedTrust: d.advancedTrust,
    p: portView(port(d, P)), p2: portView(port(d, P2)),
    cos: (d.cosMap || []).map((m) => m.queue).join(''), dscp: (d.dscpMap || []).map((m) => m.queue).join('')
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
  const status = () => post('/api/qos/status');
  const step = async (label, url, body, test) => {
    const r = await post(url, body);
    const d = await status();
    const ok = r.httpOk && test(d, r);
    check(label + (r.httpOk ? forms(r) : ''), ok, r.error || (ok ? '' : view(d)));
    return d;
  };

  // ---- 1. read ----------------------------------------------------------------
  const d0 = await status();
  if (!check('read the QoS settings', d0.httpOk && Array.isArray(d0.ports), d0.error || '')) return finish(server);
  say('  mode ' + d0.mode + ', trust basic ' + d0.basicTrust + ', advanced ' + d0.advancedTrust + ', ' + d0.ports.length + ' ports');
  say('  scheduling: ' + (d0.scheduling || []).map((s) => s.name + ' ' + s.queues.map((q) => q.queue + q.type).join(' ')).join('; '));
  say('  shape profiles: ' + (d0.shapeProfiles || []).map((s) => s.index + ' [' + s.queues.filter((q) => q.cir).map((q) => q.queue + ':' + q.cir).join(',') + ']').join('; '));
  say('  start: ' + view(d0));
  if (!check('ports ' + P + ' and ' + P2 + ' are reported', port(d0, P) && port(d0, P2), 'ports: ' + d0.ports.map((x) => x.ifIndex).join(','))) return finish(server);

  if (cleanup) {
    const x = port(d0, P);
    if (x.rateLimit) await step('rate limit off on port ' + P, '/api/qos/rate-limit', { ifIndex: P, rate: 0 }, (d) => !port(d, P).rateLimit);
    if (x.shaper.on) await step('shaper off on port ' + P, '/api/qos/port-shaper', { ifIndex: P, cir: 0 }, (d) => !port(d, P).shaper.on);
    for (const q of ((x.queueShaper && x.queueShaper.queues) || [])) {
      await step('queue ' + q.queue + ' shaper off on port ' + P, '/api/qos/queue-shaper', { ifIndex: P, queue: q.queue, cir: 0 }, (d) => !qShaped(d, P, q.queue));
    }
    await step('CoS map back to the defaults', '/api/qos/restore-map', { map: 'cos' }, (d) => d.cosMap.every((m) => m.queue === m.default));
    await step('DSCP map back to the defaults', '/api/qos/restore-map', { map: 'dscp' }, (d) => d.dscpMap.every((m) => m.queue === m.default));
    return finish(server);
  }

  // ---- 2. trust mode and QoS mode ------------------------------------------------
  if (d0.mode === 'basic' || d0.mode === 'advanced') {
    const key = d0.mode === 'advanced' ? 'advancedTrust' : 'basicTrust';
    const other = d0[key] === 'cos' ? 'dscp' : 'cos';
    await step('trust set to ' + other, '/api/qos/trust', { trust: other }, (d) => d[key] === other);
    await step('trust put back to ' + d0[key], '/api/qos/trust', { trust: d0[key] }, (d) => d[key] === d0[key]);
    const otherMode = d0.mode === 'basic' ? 'advanced' : 'basic';
    await step('QoS mode set to ' + otherMode, '/api/qos/mode', { mode: otherMode }, (d) => d.mode === otherMode);
    let d = await step('QoS mode put back to ' + d0.mode, '/api/qos/mode', { mode: d0.mode }, (x) => x.mode === d0.mode);
    if (view(d) !== view(d0)) say('  NOTE after the mode change and back: ' + view(d));
  } else {
    say('  QoS is off on this switch; the trust and mode changes are skipped.');
  }

  // ---- 3. trust on the port --------------------------------------------------------
  const t0 = port(d0, P).trust;
  await step('trust ' + (t0 ? 'off' : 'on') + ' on port ' + P, '/api/qos/port-trust', { ifIndex: P, on: !t0 }, (d) => port(d, P).trust === !t0);
  await step('trust put back on port ' + P, '/api/qos/port-trust', { ifIndex: P, on: t0 }, (d) => port(d, P).trust === t0);

  // ---- 4. rate limit, shaper, queue shaper on the port --------------------------------
  {
    const x = port(d0, P);
    await step('rate limit ' + RATE + ' kb/s on port ' + P, '/api/qos/rate-limit', { ifIndex: P, rate: RATE }, (d) => port(d, P).rateLimit === RATE);
    await step('rate limit put back (' + (x.rateLimit || 0) + ')', '/api/qos/rate-limit', { ifIndex: P, rate: x.rateLimit || 0 }, (d) => port(d, P).rateLimit === (x.rateLimit || 0));
    await step('shaper ' + RATE + ' kb/s on port ' + P, '/api/qos/port-shaper', { ifIndex: P, cir: RATE, cbs: 128000 }, (d) => port(d, P).shaper.on && port(d, P).shaper.cir === RATE);
    if (x.shaper.on) await step('shaper put back (' + x.shaper.cir + ')', '/api/qos/port-shaper', { ifIndex: P, cir: x.shaper.cir, cbs: x.shaper.cbs }, (d) => port(d, P).shaper.cir === x.shaper.cir);
    else await step('shaper off again', '/api/qos/port-shaper', { ifIndex: P, cir: 0 }, (d) => !port(d, P).shaper.on);
    const q3 = qShaped(d0, P, 3);
    await step('queue 3 shaped at ' + RATE + ' kb/s on port ' + P, '/api/qos/queue-shaper', { ifIndex: P, queue: 3, cir: RATE, cbs: 128000 }, (d) => (qShaped(d, P, 3) || {}).cir === RATE);
    if (q3) await step('queue 3 shaper put back (' + q3.cir + ')', '/api/qos/queue-shaper', { ifIndex: P, queue: 3, cir: q3.cir, cbs: q3.cbs }, (d) => (qShaped(d, P, 3) || {}).cir === q3.cir);
    else await step('queue 3 shaper off again', '/api/qos/queue-shaper', { ifIndex: P, queue: 3, cir: 0 }, (d) => !qShaped(d, P, 3));
  }

  // ---- 5. a new shape profile on the second port -----------------------------------------
  if (port(d0, P2).queueShaper) {
    say('  port ' + P2 + ' already has a queue shaper, so making a new shape profile is skipped. Give --port2= a port with none.');
  } else {
    let made = null;
    await step('queue 5 shaped at ' + RATE + ' kb/s on port ' + P2 + ' (a new shape profile)', '/api/qos/queue-shaper',
      { ifIndex: P2, queue: 5, cir: RATE, cbs: 128000 }, (d, r) => { made = r.profile; return (qShaped(d, P2, 5) || {}).cir === RATE; });
    await step('queue 5 shaper off on port ' + P2 + ' (profile ' + made + ' removed)', '/api/qos/queue-shaper',
      { ifIndex: P2, queue: 5, cir: 0 }, (d, r) => !port(d, P2).queueShaper && r.profileRemoved && !(d.shapeProfiles || []).some((s) => s.index === made));
  }

  // ---- 6. the maps ---------------------------------------------------------------------
  {
    const c5 = cosQ(d0, 5), d10 = dscpQ(d0, 10);
    const cTo = c5 === 3 ? 4 : 3, dTo = d10 === 4 ? 5 : 4;
    await step('CoS 5 to queue ' + cTo, '/api/qos/cos-map', { cos: 5, queue: cTo }, (d) => cosQ(d, 5) === cTo);
    if ((d0.cosMap || []).every((m) => m.queue === m.default)) {
      await step('CoS map put back with "Put back the defaults"', '/api/qos/restore-map', { map: 'cos' }, (d, r) => cosQ(d, 5) === c5 && r.changed === 1);
    } else {
      await step('CoS 5 put back to queue ' + c5, '/api/qos/cos-map', { cos: 5, queue: c5 }, (d) => cosQ(d, 5) === c5);
    }
    await step('DSCP 10 to queue ' + dTo, '/api/qos/dscp-map', { dscp: 10, queue: dTo }, (d) => dscpQ(d, 10) === dTo);
    await step('DSCP 10 put back to queue ' + d10, '/api/qos/dscp-map', { dscp: 10, queue: d10 }, (d) => dscpQ(d, 10) === d10);
  }

  // ---- 7. put back anything that changed, and compare --------------------------------------
  {
    let d = await status();
    if (view(d) !== view(d0)) {
      say('  differs from the start: ' + view(d));
      for (const m of d0.cosMap || []) if (cosQ(d, m.cos) !== m.queue) await post('/api/qos/cos-map', { cos: m.cos, queue: m.queue });
      for (const m of d0.dscpMap || []) if (dscpQ(d, m.dscp) !== m.queue) await post('/api/qos/dscp-map', { dscp: m.dscp, queue: m.queue });
      const x = port(d0, P), y = port(d, P);
      if (y.trust !== x.trust) await post('/api/qos/port-trust', { ifIndex: P, on: x.trust });
      if (y.rateLimit !== x.rateLimit) await post('/api/qos/rate-limit', { ifIndex: P, rate: x.rateLimit || 0 });
      if (portView(y).shaper !== portView(x).shaper) await post('/api/qos/port-shaper', { ifIndex: P, cir: x.shaper.on ? x.shaper.cir : 0, cbs: x.shaper.cbs });
      for (const q of ((x.queueShaper && x.queueShaper.queues) || [])) {
        const now = qShaped(d, P, q.queue);
        if (!now || now.cir !== q.cir) await post('/api/qos/queue-shaper', { ifIndex: P, queue: q.queue, cir: q.cir, cbs: q.cbs });
      }
      d = await status();
    }
    check('the mode, ports ' + P + ' and ' + P2 + ' and the maps are as they were', view(d) === view(d0), view(d) + ' vs ' + view(d0));
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
    const file = path.join(outDir, 'switch-test-qos-' + host.replace(/[^0-9a-z.]/gi, '_') + '.txt');
    fs.writeFileSync(file, lines.join('\n') + '\n\n' + JSON.stringify(results, null, 2) + '\n');
    console.log('Wrote ' + file);
  }
  server.close();
  setTimeout(() => process.exit(failed ? 1 : 0), 200);
}

main().catch((e) => { console.error(e); process.exit(1); });
