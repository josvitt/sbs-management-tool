'use strict';

/**
 * Supervised write test for the System panel (switch-system.js, routes/system.js)
 * on a test switch. Every change is put back, and nothing is saved to startup.
 *
 *   SBS_COMM=<community> node scripts/switch-test-system.js <address> [results folder]
 *
 *   1. Reads the clock, SNTP, users and management access.
 *   2. Sets the time zone to +01:30 "TST", checks, and puts it back.
 *   3. Turns SNTP off and on again (or on and off, if it was off).
 *   4. Sets the clock to this computer's time in the switch's time zone and
 *      checks it reads back within a minute.
 *   5. Checks that the only admin can be neither deleted nor demoted.
 *   6. Turns Telnet on and off again (or off and on, if it was on).
 *
 * The app's own routes run on 127.0.0.1, so this tests what the panel sends.
 * No community is written to the results file.
 */

process.env.SNMP_MAX_RPS = process.env.SNMP_MAX_RPS || '20';
const fs = require('fs');
const path = require('path');
const http = require('http');

const args = process.argv.slice(2);
const host = args[0];
const outDir = args[1] || null;
const community = process.env.SBS_COMM;
if (!host || !community) {
  console.error('Usage: SBS_COMM=<community> node scripts/switch-test-system.js <address> [results folder]');
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

async function startApp() {
  const out = console.log;
  console.log = (...a) => { if (typeof a[0] === 'string' && /^\[[0-9T:.\-Z]+\] \[INFO\]/.test(a[0])) return; out(...a); };
  const app = require('../web');
  require('../routes/system')(app);
  const server = http.createServer(app);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return server;
}

const sameOffset = (a, b) => String(a || '').replace(/^\+/, '') === String(b || '').replace(/^\+/, '');

// The switch's local time from this computer's clock, as the panel sends it.
function switchLocalNow(offsetSec) {
  const d = new Date(Date.now() + (Number(offsetSec) || 0) * 1000);
  const p2 = (n) => String(n).padStart(2, '0');
  return d.getUTCFullYear() + '-' + p2(d.getUTCMonth() + 1) + '-' + p2(d.getUTCDate()) + ' ' +
    p2(d.getUTCHours()) + ':' + p2(d.getUTCMinutes()) + ':' + p2(d.getUTCSeconds());
}

async function main() {
  const server = await startApp();
  const base = 'http://127.0.0.1:' + server.address().port;
  const target = { host, port: 161, version: '2c', community, timeout: 5000, retries: 1 };
  const post = async (p, body) => {
    const r = await fetch(base + p, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(Object.assign({ target }, body || {})) });
    const b = await r.json().catch(() => ({ error: 'HTTP ' + r.status }));
    return Object.assign({ httpOk: r.ok }, b);
  };
  const status = () => post('/api/system/status');

  // ---- 1. read ----------------------------------------------------------------
  const st0 = await status();
  if (!check('read the system settings', st0.httpOk && st0.time, st0.error || '')) return finish(server);
  const t0 = st0.time, a0 = st0.access;
  say('  clock ' + t0.now + ' (' + t0.clock + '), zone ' + t0.zoneOffset + ' ' + (t0.zoneCode || '') +
    ', SNTP ' + (t0.sntp.unicast ? 'on' : 'off') + ' with ' + t0.servers.length + ' servers');
  say('  ' + st0.users.list.length + ' local users, ' + st0.users.list.filter((u) => u.privilege === 15).length + ' admin(s)');
  say('  SSH ' + a0.ssh + ', Telnet ' + a0.telnet + ', HTTPS ' + a0.https + ', HTTP ' + a0.http);

  // ---- 2. time zone -----------------------------------------------------------
  {
    const r = await post('/api/system/timezone', { offset: '+01:30', code: 'TST' });
    const s = await status();
    check('set the time zone to +01:30 TST', r.httpOk && /^\+?01:30$/.test(s.time.zoneOffset) && s.time.zoneCode === 'TST',
      r.error || ('reads ' + s.time.zoneOffset + ' ' + s.time.zoneCode + ', total offset ' + s.time.totalOffsetSec + ' s'));
    const back = await post('/api/system/timezone', { offset: /^[+-]/.test(t0.zoneOffset) ? t0.zoneOffset : '+' + t0.zoneOffset, code: t0.zoneCode || '' });
    const s2 = await status();
    check('put the time zone back', back.httpOk && sameOffset(s2.time.zoneOffset, t0.zoneOffset) && (s2.time.zoneCode || '') === (t0.zoneCode || ''),
      back.error || ('reads ' + s2.time.zoneOffset + ' ' + s2.time.zoneCode));
  }

  // ---- 3. SNTP on/off ---------------------------------------------------------
  {
    const was = t0.sntp.unicast;
    const r = await post('/api/system/sntp', { on: !was });
    const s = await status();
    check('turn SNTP ' + (was ? 'off' : 'on'), r.httpOk && s.time.sntp.unicast === !was, r.error || ('reads ' + s.time.sntp.unicast));
    const back = await post('/api/system/sntp', { on: was });
    const s2 = await status();
    check('turn SNTP ' + (was ? 'on' : 'off') + ' again', back.httpOk && s2.time.sntp.unicast === was, back.error || ('reads ' + s2.time.sntp.unicast));
  }

  // ---- 4. clock ---------------------------------------------------------------
  {
    const local = switchLocalNow(t0.totalOffsetSec);
    const r = await post('/api/system/clock', { local });
    const s = await status();
    const diff = Math.abs(Date.parse(s.time.now.replace(' ', 'T') + 'Z') - Date.parse(local.replace(' ', 'T') + 'Z')) / 1000;
    check('set the clock to this computer\'s time', r.httpOk && diff < 60, r.error || ('sent ' + local + ', reads ' + s.time.now + ' (' + s.time.clock + ')'));
  }

  // ---- 5. users: the only-admin guard ----------------------------------------
  {
    const admins = st0.users.list.filter((x) => x.privilege === 15);
    if (admins.length === 1) {
      const name = admins[0].name;
      const g = await post('/api/system/user/delete', { name });
      const g2 = await post('/api/system/user/privilege', { name, privilege: 1 });
      const s = await status();
      const u = s.users.list.find((x) => x.name === name);
      check('the only admin can be neither deleted nor demoted', !g.httpOk && !g2.httpOk && u && u.privilege === 15, g.error || 'it was accepted');
    } else {
      say('SKIP the only-admin guard: the switch has ' + admins.length + ' admins');
    }
  }

  // ---- 6. a management service ----------------------------------------------
  {
    const was = !!a0.telnet;
    const r = await post('/api/system/service', { service: 'telnet', on: !was });
    const s = await status();
    check('turn Telnet ' + (was ? 'off' : 'on'), r.httpOk && s.access.telnet === !was, r.error || ('reads ' + s.access.telnet));
    const back = await post('/api/system/service', { service: 'telnet', on: was });
    const s2 = await status();
    check('turn Telnet ' + (was ? 'on' : 'off') + ' again', back.httpOk && s2.access.telnet === was, back.error || ('reads ' + s2.access.telnet));
  }

  // ---- the end state ---------------------------------------------------------
  {
    const s = await status();
    const same = sameOffset(s.time.zoneOffset, t0.zoneOffset) && s.time.sntp.unicast === t0.sntp.unicast &&
      s.users.list.length === st0.users.list.length &&
      ['ssh', 'telnet', 'https', 'http'].every((k) => s.access[k] === a0[k]);
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
    const file = path.join(outDir, 'switch-test-system-' + host.replace(/[^0-9a-z.]/gi, '_') + '.txt');
    fs.writeFileSync(file, lines.join('\n') + '\n\n' + JSON.stringify(results, null, 2) + '\n');
    console.log('Wrote ' + file);
  }
  server.close();
  setTimeout(() => process.exit(failed ? 1 : 0), 200);
}

main().catch((e) => { console.error(e); process.exit(1); });
