'use strict';

/**
 * Supervised write test for the System panel (switch-system.js, routes/system.js)
 * on a test switch. Every change is put back, and nothing is saved to startup.
 *
 *   SBS_COMM=<community> node scripts/switch-test-system.js <address> [--login-check] [results folder]
 *
 *   1. Reads the clock, SNTP, users and management access.
 *   2. Sets the time zone to +01:30 "TST", checks, and puts it back.
 *   3. Adds SNTP servers 192.0.2.123 and sbs-test.example.com, checks, and
 *      removes them.
 *   4. Turns SNTP off and on again (or on and off, if it was off).
 *   5. Sets the clock to this computer's time in the switch's time zone and
 *      checks it reads back within a minute.
 *   6. Adds a user "sbstest" with privilege 1 and a random password, changes
 *      its privilege to 7 and its password, checks the only-admin guard, and
 *      deletes the user.
 *      --login-check pauses after the user is added and prints its password,
 *      so you can sign in over SSH as sbstest and confirm the password works.
 *      Press Enter to go on; the user is deleted either way.
 *   7. Turns Telnet on and off again (or off and on, if it was on).
 *
 * The app's own routes run on 127.0.0.1, so this tests what the panel sends.
 * No password or community is written to the results file.
 */

process.env.SNMP_MAX_RPS = process.env.SNMP_MAX_RPS || '20';
const fs = require('fs');
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const readline = require('readline');

const args = process.argv.slice(2);
const host = args[0];
const loginCheck = args.includes('--login-check');
const outDir = args.filter((a, i) => i > 0 && !a.startsWith('--'))[0] || null;
const community = process.env.SBS_COMM;
if (!host || !community) {
  console.error('Usage: SBS_COMM=<community> node scripts/switch-test-system.js <address> [--login-check] [results folder]');
  process.exit(2);
}

const lines = [];
function say(msg, secret) {
  const l = '[' + new Date().toISOString().slice(11, 19) + '] ' + msg;
  if (!secret) lines.push(l);
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

function pressEnter(prompt) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(prompt, () => { rl.close(); resolve(); });
  });
}

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

  // ---- 3. SNTP servers --------------------------------------------------------
  for (const address of ['192.0.2.123', 'sbs-test.example.com']) {
    const had = t0.servers.some((x) => x.address === address);
    if (had) { say('SKIP SNTP server ' + address + ': already configured'); continue; }
    const r = await post('/api/system/sntp/add', { address });
    const s = await status();
    const row = s.time.servers.find((x) => x.address === address);
    check('add SNTP server ' + address, r.httpOk && !!row, r.error || (row ? 'form "' + r.shape + '", polled ' + row.polled + ', status ' + row.status : 'not listed'));
    const rm = await post('/api/system/sntp/remove', { address });
    const s2 = await status();
    check('remove SNTP server ' + address, rm.httpOk && !s2.time.servers.some((x) => x.address === address), rm.error || '');
  }
  {
    const s = await status();
    check('the original SNTP servers are all still there', t0.servers.every((x) => s.time.servers.some((y) => y.address === x.address)));
  }

  // ---- 4. SNTP on/off ---------------------------------------------------------
  {
    const was = t0.sntp.unicast;
    const r = await post('/api/system/sntp', { on: !was });
    const s = await status();
    check('turn SNTP ' + (was ? 'off' : 'on'), r.httpOk && s.time.sntp.unicast === !was, r.error || ('reads ' + s.time.sntp.unicast));
    const back = await post('/api/system/sntp', { on: was });
    const s2 = await status();
    check('turn SNTP ' + (was ? 'on' : 'off') + ' again', back.httpOk && s2.time.sntp.unicast === was, back.error || ('reads ' + s2.time.sntp.unicast));
  }

  // ---- 5. clock ---------------------------------------------------------------
  {
    const local = switchLocalNow(t0.totalOffsetSec);
    const r = await post('/api/system/clock', { local });
    const s = await status();
    const diff = Math.abs(Date.parse(s.time.now.replace(' ', 'T') + 'Z') - Date.parse(local.replace(' ', 'T') + 'Z')) / 1000;
    check('set the clock to this computer\'s time', r.httpOk && diff < 60, r.error || ('sent ' + local + ', reads ' + s.time.now + ' (' + s.time.clock + ')'));
  }

  // ---- 6. users ---------------------------------------------------------------
  {
    const name = 'sbstest';
    if (st0.users.list.some((u) => u.name === name)) {
      say('SKIP users: a user called sbstest already exists');
    } else {
      const pw = 'Sb' + crypto.randomBytes(6).toString('hex') + '-7';
      const r = await post('/api/system/user/add', { name, password: pw, privilege: 1 });
      let s = await status();
      let u = s.users.list.find((x) => x.name === name);
      check('add user sbstest with privilege 1', r.httpOk && u && u.privilege === 1, r.error || (u ? 'password form "' + r.passwordForm + '", privilege ' + u.privilege : 'not listed'));
      if (!r.httpOk && !u) say('  (the add removed its own row again, as it should)');
      if (r.httpOk && u && loginCheck) {
        say('  Sign in over SSH now: ssh ' + name + '@' + host + '  password ' + pw, true);
        await pressEnter('  Did the sign-in work? Note it, then press Enter to go on. ');
      }
      if (!u) {
        say('SKIP the other user steps: sbstest was not added');
      } else {
      const pr = await post('/api/system/user/privilege', { name, privilege: 7 });
      s = await status(); u = s.users.list.find((x) => x.name === name);
      check('change its privilege to 7', pr.httpOk && u && u.privilege === 7, pr.error || (u ? 'privilege ' + u.privilege : 'not listed'));
      const pw2 = await post('/api/system/user/password', { name, password: 'Sb' + crypto.randomBytes(6).toString('hex') + '-8' });
      check('change its password', pw2.httpOk, pw2.error || ('form "' + pw2.passwordForm + '"'));
      const admins = s.users.list.filter((x) => x.privilege === 15);
      if (admins.length === 1) {
        const g = await post('/api/system/user/delete', { name: admins[0].name });
        const s3 = await status();
        check('the only admin cannot be deleted', !g.httpOk && s3.users.list.some((x) => x.name === admins[0].name), g.error || 'it was accepted');
      }
      const del = await post('/api/system/user/delete', { name });
      s = await status();
      check('delete user sbstest', del.httpOk && !s.users.list.some((x) => x.name === name), del.error || '');
      }
    }
  }

  // ---- 7. a management service ----------------------------------------------
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
      s.time.servers.length === t0.servers.length && s.users.list.length === st0.users.list.length &&
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
