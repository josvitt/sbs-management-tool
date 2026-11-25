'use strict';

/**
 * Supervised test of reboot, firmware and configuration restore on one
 * switch. Run it only with the owner's approval, on the test switch.
 *
 *   SBS_COMM=<community> node scripts/switch-test-maint.js <address> [--image <file>] [--reboot] [results folder]
 *
 * It starts the app's own routes on 127.0.0.1 and goes through them, so
 * the requests are the ones the dashboard sends. Without options it never
 * reboots the switch and leaves it as it found it:
 *
 *   1. Reads the firmware images, the next boot image, the reboot schedule
 *      and whether the running configuration is saved.
 *   2. Schedules a reboot an hour out, checks it, cancels it, checks that.
 *   3. Makes the other image the next boot image, checks, and puts it back.
 *   4. Reads the startup configuration and copies the same text back into
 *      startup over TFTP, then reads startup again and compares. If it
 *      differs, the text read at the start (held in memory) is copied back
 *      again. The running configuration is never touched.
 *
 *   --image <file>  also installs that firmware file into the inactive
 *                   image slot. Use the version the switch already runs
 *                   unless you mean to upgrade: the old inactive image is
 *                   overwritten.
 *   --save-first    saves running to startup before the round trip (the
 *                   owner's choice, on the test switch only), so startup
 *                   starts as a known copy and a rewritten one can be put
 *                   back by saving again.
 *   --diff-only     writes nothing: reads running and startup and prints
 *                   where they differ, as line numbers and each line's
 *                   first word only (never whole lines, which can hold
 *                   keys).
 *   --reboot        then reboots the switch, waits for it to come back,
 *                   and checks the image it runs and that its running
 *                   configuration is the restored startup one. Refused
 *                   while the running configuration has unsaved changes.
 *
 * No configuration text is ever written to disk: the results file holds
 * only the lines printed here.
 */

process.env.SNMP_MAX_RPS = process.env.SNMP_MAX_RPS || '20';
const fs = require('fs');
const path = require('path');
const http = require('http');

const args = process.argv.slice(2);
const host = args[0];
const imageAt = args.indexOf('--image');
const imagePath = imageAt > 0 ? args[imageAt + 1] : null;
const doReboot = args.includes('--reboot');
const diffOnly = args.includes('--diff-only');
const saveFirst = args.includes('--save-first');
const outDir = args.filter((a, i) => i > 0 && !a.startsWith('--') && i !== imageAt + 1)[0] || null;
const community = process.env.SBS_COMM;
if (!host || !community || (imageAt > 0 && !imagePath)) {
  console.error('Usage: SBS_COMM=<community> node scripts/switch-test-maint.js <address> [--image <file>] [--reboot] [results folder]');
  process.exit(2);
}

const lines = [];
function say(msg) { const l = '[' + new Date().toISOString().slice(11, 19) + '] ' + msg; lines.push(l); console.log(l); }
const results = [];
function check(name, ok, detail) {
  results.push({ name, ok: !!ok, detail: detail || '' });
  say((ok ? 'PASS ' : 'FAIL ') + name + (detail ? ': ' + detail : ''));
  return !!ok;
}
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

// Where two configurations differ, without printing their contents: line
// numbers, + or -, and each line's first word. The file header lines the
// switch writes itself are shown whole, since they hold no settings.
function diffSummary(aText, bText) {
  const norm = (t) => String(t).replace(/\r\n?/g, '\n').replace(/\n+$/, '').split('\n').map((l) => l.replace(/\s+$/, ''));
  const a = norm(aText), b = norm(bText);
  const n = a.length, m = b.length;
  const L = Array.from({ length: n + 1 }, () => new Int32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) L[i][j] = a[i] === b[j] ? L[i + 1][j + 1] + 1 : Math.max(L[i + 1][j], L[i][j + 1]);
  const HEADER = /^(config-file-header|v\d[\w./ -]*|CLI v[\d.]+|file SSD indicator \w+|@|!|exit|unit-type-control-(start|end))$/;
  const show = (l) => (HEADER.test(l.trim()) ? '"' + l.trim() + '"' : (l.trim().split(/\s+/)[0] || '(blank)').slice(0, 24) + ' ...');
  const out = [];
  let i = 0, j = 0;
  while (i < n || j < m) {
    if (i < n && j < m && a[i] === b[j]) { i++; j++; }
    else if (j < m && (i >= n || L[i][j + 1] >= L[i + 1][j])) { out.push('    + line ' + (j + 1) + ': ' + show(b[j])); j++; }
    else { out.push('    - line ' + (i + 1) + ': ' + show(a[i])); i++; }
  }
  return out;
}

async function startApp() {
  const out = console.log;
  console.log = (...a) => { if (typeof a[0] === 'string' && /^\[[0-9T:.\-Z]+\] \[INFO\]/.test(a[0])) return; out(...a); };
  const app = require('../web');
  require('../routes/config')(app);
  require('../routes/maint')(app);
  const server = http.createServer(app);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return server;
}

async function main() {
  if (!process.env.SBS_SERVICE_RUNNING_OK) {
    const up = await new Promise((r) => {
      const req = http.get({ host: '127.0.0.1', port: 3000, path: '/', timeout: 1500 }, (res) => { res.resume(); r(true); });
      req.on('error', () => r(false));
      req.on('timeout', () => { req.destroy(); r(false); });
    });
    if (up) {
      console.error('The SBS Management Tool is running on this PC (port 3000). Stop it first (it also holds the TFTP port), then run this again.');
      process.exit(3);
    }
  }
  let image = null;
  if (imagePath) {
    image = fs.readFileSync(imagePath);
    if (image.length < 1024 * 1024) { console.error(imagePath + ' is too small to be a firmware image.'); process.exit(2); }
  }

  const server = await startApp();
  const base = 'http://127.0.0.1:' + server.address().port;
  const target = { host, port: 161, version: '2c', community, timeout: 5000, retries: 1 };
  const post = async (p, body) => {
    const r = await fetch(base + p, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const b = await r.json().catch(() => ({ error: 'HTTP ' + r.status }));
    return Object.assign({ httpOk: r.ok }, b);
  };
  const snmp = require('net-snmp');
  const core = require('../snmp-core');
  const maint = require('../switch-maint');
  const configFetch = require('../config-fetch');
  const tftpPort = Number(process.env.TFTP_PORT) || undefined;
  const session = () => core.buildSnmpSession(target);
  const get = (oids) => new Promise((resolve) => {
    const sess = session();
    sess.on('error', () => {});
    sess.get(oids, (err, vbs) => {
      sess.close();
      if (err) return resolve(oids.map(() => null));
      resolve(vbs.map((vb) => (snmp.isVarbindError(vb) ? null : vb.value)));
    });
  });
  const SYS_DESCR = '1.3.6.1.2.1.1.1.0', SYS_UPTIME = '1.3.6.1.2.1.1.3.0', SAVED = '1.3.6.1.4.1.9.6.1.101.1.13.0';
  const isSaved = async () => { const [v] = await get([SAVED]); return v == null ? null : Number(v) === 1; };
  const describe = (st) => (st.units || []).map((u) => 'unit ' + u.unit + ': running ' + u.active + ', boots ' + u.nextBoot + ' next; ' +
    u.images.map((i) => i.slot + ' ' + (i.version || '?') + ' (' + (i.name || 'no name') + (i.date ? ', ' + i.date : '') + ')').join('; ')).join(' | ');

  // ---- 1. read -------------------------------------------------------------
  const [descr] = await get([SYS_DESCR]);
  say('Switch ' + host + ': ' + String(descr || '(no answer)').split('\n')[0]);
  if (!descr) { say('STOPPED: the switch does not answer.'); return finish(server, 'NOT STARTED'); }
  const st0 = await post('/api/maint/status', { target });
  if (!check('read the images and the reboot schedule', st0.httpOk && Array.isArray(st0.units), st0.error)) return finish(server, 'NOT STARTED');
  say('  ' + describe(st0));
  say('  reboot: ' + (st0.reboot.readable ? (st0.reboot.scheduled ? 'scheduled in ' + st0.reboot.inSeconds + ' s' : 'none scheduled') : 'not readable'));
  if (st0.reboot.scheduled) { say('STOPPED: a reboot is already scheduled on this switch; cancel or wait for it first.'); return finish(server, 'NOT STARTED'); }
  const saved0 = await isSaved();
  say('  running configuration saved: ' + saved0);
  const unit0 = st0.units[0] || {};

  if (diffOnly) {
    try {
      const run = await configFetch.fetchConfig(session, { host, kind: 'running', tftpPort });
      const start = await configFetch.fetchConfig(session, { host, kind: 'startup', tftpPort });
      say('  running ' + run.lines + ' lines, startup ' + start.lines + ' lines. Where startup differs from running:');
      const d = diffSummary(run.text, start.text);
      for (const l of d) say(l);
      check('read and compare running and startup', true, d.length + ' line(s) differ');
    } catch (e) { check('read and compare running and startup', false, e.message); }
    return finish(server, 'NOTHING WRITTEN');
  }

  // ---- 2. schedule and cancel ---------------------------------------------
  const sch = await post('/api/maint/reboot', { target, seconds: 3600 });
  if (check('schedule a reboot in an hour', sch.httpOk && sch.ok, sch.error || ('via ' + sch.via))) {
    const st1 = await post('/api/maint/status', { target });
    check('the switch reports it scheduled', st1.reboot && st1.reboot.scheduled && st1.reboot.inSeconds > 3400 && st1.reboot.inSeconds <= 3600,
      st1.reboot ? 'in ' + st1.reboot.inSeconds + ' s' : st1.error);
    const can = await post('/api/maint/reboot/cancel', { target });
    const st2 = await post('/api/maint/status', { target });
    const cancelled = check('cancel it', can.httpOk && can.ok && st2.reboot && !st2.reboot.scheduled, can.error || '');
    if (!cancelled) {
      const at = new Date(Date.now() + ((st2.reboot && st2.reboot.inSeconds) || 3600) * 1000);
      say('!!! THE SWITCH WILL REBOOT AT ABOUT ' + at.toLocaleTimeString() + ' unless the reboot is cancelled from its own CLI.');
    }
  }

  // ---- 3. next boot image round trip ---------------------------------------
  const other = (unit0.images || []).find((i) => i.slot !== unit0.nextBoot);
  if (other && unit0.nextBoot) {
    const set = await post('/api/maint/next-boot', { target, unit: unit0.unit, image: other.slot });
    const st3 = await post('/api/maint/status', { target });
    const u3 = (st3.units || [])[0] || {};
    check('make ' + other.slot + ' the next boot image', set.httpOk && u3.nextBoot === other.slot, set.error || ('reads ' + u3.nextBoot));
    const back = await post('/api/maint/next-boot', { target, unit: unit0.unit, image: unit0.nextBoot });
    const st4 = await post('/api/maint/status', { target });
    const u4 = (st4.units || [])[0] || {};
    check('put the next boot image back to ' + unit0.nextBoot, back.httpOk && u4.nextBoot === unit0.nextBoot, back.error || ('reads ' + u4.nextBoot));
  } else {
    say('SKIP next boot image: the switch lists only one image.');
  }

  // ---- 4. startup configuration round trip ----------------------------------
  let startupText = null;
  let savedNow = saved0 === true;
  if (saveFirst && !savedNow) {
    const sv = await post('/api/config/sync', { target, from: 'running', to: 'startup' });
    savedNow = check('save running to startup first (--save-first)', sv.httpOk && !sv.error && (await isSaved()) === true, sv.error || '');
  }
  try {
    const a = await configFetch.fetchConfig(session, { host, kind: 'startup', tftpPort });
    startupText = a.text;
    say('  startup configuration read: ' + a.lines + ' lines');
    const pushed = await maint.pushFile(session, { host, dest: 'startup', buffer: Buffer.from(startupText, 'utf8'), tftpPort });
    check('copy it back into startup over TFTP', pushed.finished, 'row shape "' + pushed.shape + '", completion via ' + pushed.via);
    const b = await configFetch.fetchConfig(session, { host, kind: 'startup', tftpPort });
    const same = maint.sameConfig(a.text, b.text);
    check('startup reads back the same', same, same ? '' : a.lines + ' lines before, ' + b.lines + ' after');
    if (savedNow) check('the switch still says running and startup are equal', (await isSaved()) === true);
    if (!same) {
      say('  Where startup changed (before -> after):');
      for (const l of diffSummary(a.text, b.text)) say(l);
      if (savedNow) {
        // Running still holds what startup was, so saving it is the exact put-back.
        say('  Putting startup back: saving running to startup.');
        await configFetch.copyConfig(session, { host, from: 'running', to: 'startup' });
      } else {
        say('  Putting startup back: copying the text read at the start into startup again.');
        await maint.pushFile(session, { host, dest: 'startup', buffer: Buffer.from(startupText, 'utf8'), tftpPort });
      }
      const c = await configFetch.fetchConfig(session, { host, kind: 'startup', tftpPort });
      check('startup put back', maint.sameConfig(a.text, c.text));
    }
  } catch (e) {
    check('startup round trip', false, e.message);
  }

  // ---- 5. firmware install (opt-in) ----------------------------------------
  let expectBoot = null;
  if (image) {
    const r = await fetch(base + '/api/firmware/stage?name=' + encodeURIComponent(path.basename(imagePath)), {
      method: 'POST', headers: { 'Content-Type': 'application/octet-stream' }, body: image
    });
    const staged = await r.json();
    if (check('upload ' + path.basename(imagePath) + ' to the app', staged.ok, staged.error || (staged.bytes + ' bytes, sha256 ' + String(staged.sha256).slice(0, 16)))) {
      say('  Installing. The switch writes flash for several minutes; do not power it off.');
      const t0 = Date.now();
      const ins = await post('/api/firmware/install', { target, id: staged.id });
      check('the switch pulls and installs it', ins.httpOk && ins.ok, ins.error || ('row shape "' + ins.shape + '", ' + Math.round((Date.now() - t0) / 1000) + ' s'));
      const st5 = await post('/api/maint/status', { target });
      say('  after install: ' + describe(st5));
      const u5 = (st5.units || [])[0] || {};
      check('the switch still runs ' + unit0.active, u5.active === unit0.active);
      expectBoot = u5.nextBoot;
      say('  next boot image is now ' + u5.nextBoot);
    }
  }

  // ---- 6. reboot (opt-in) ---------------------------------------------------
  if (doReboot) {
    if ((await isSaved()) !== true) {
      say('SKIP reboot: the running configuration has unsaved changes, and a reboot would lose them.');
    } else {
      const [up0] = await get([SYS_UPTIME]);
      const rb = await post('/api/maint/reboot', { target, seconds: 0 });
      if (check('reboot now', rb.httpOk && rb.ok, rb.error || ('via ' + rb.via))) {
        say('  Waiting for the switch to go down and come back (up to 12 minutes).');
        const t0 = Date.now();
        let down = false, back = false;
        while (Date.now() - t0 < 12 * 60000) {
          await wait(10000);
          const [up] = await get([SYS_UPTIME]);
          if (up == null) { if (!down) say('  down'); down = true; continue; }
          if (Number(up) < Number(up0) || down) { back = true; break; }
        }
        check('the switch came back', back, Math.round((Date.now() - t0) / 1000) + ' s');
        if (back) {
          await wait(30000);   // let its services settle before more reads
          const st6 = await post('/api/maint/status', { target });
          say('  after reboot: ' + describe(st6));
          const u6 = (st6.units || [])[0] || {};
          const want = expectBoot || unit0.nextBoot;
          check('it runs the image chosen to boot next (' + want + ')', u6.active === want, 'runs ' + u6.active);
          check('running and startup are equal after the reboot', (await isSaved()) === true);
          if (startupText != null) {
            try {
              const run = await configFetch.fetchConfig(session, { host, kind: 'running', tftpPort });
              check('the running configuration is the restored startup one', maint.sameConfig(run.text, startupText),
                run.lines + ' lines');
            } catch (e) { check('read the running configuration', false, e.message); }
          }
        }
      }
    }
  }

  const failed = results.filter((r) => !r.ok).length;
  finish(server, failed ? failed + ' CHECK(S) FAILED' : 'ALL ' + results.length + ' CHECKS PASSED');
}

function finish(server, verdict) {
  console.log(verdict);
  lines.push(verdict);
  if (outDir) {
    fs.mkdirSync(outDir, { recursive: true });
    const file = path.join(outDir, 'switch-test-maint-' + host.replace(/[^0-9a-z.]/gi, '_') + '.txt');
    fs.writeFileSync(file, lines.join('\n') + '\n\n' + JSON.stringify(results, null, 2) + '\n');
    console.log('Wrote ' + file);
  }
  server.close();
  setTimeout(() => process.exit(/PASSED/.test(verdict) ? 0 : 1), 200);
}

main().catch((e) => { console.error(e); process.exit(1); });
